// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type volumeFileOwner struct {
	Publication *volumes.FilePublication `json:",omitempty"`
	Schema      uint8
	ID          string
	Scope       volumes.Scope
	Native      [32]byte
	Consumer    volumes.Consumer
	Phase       string
	Pin         *volumes.NativeLease
	Reply       userauth.VolumeFileReply
}
type volumeFileWorkRequest struct {
	Session access.Session
	ID      string
	At      int64
}

func (r *Runtime) volumeFileWork(ctx context.Context, session access.Session, id string) (control.VolumeFileJob, error) {
	return r.volumeFileWorkAt(ctx, session, id, 0)
}

func (r *Runtime) volumeFileWorkAt(ctx context.Context, session access.Session, id string, epoch uint64) (control.VolumeFileJob, error) {
	body, _ := json.Marshal(volumeFileWorkRequest{session, id, time.Now().Unix()})
	reply, err := r.appCall(ctx, "volume-file-work", body)
	if err != nil || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex == 0 {
		return control.VolumeFileJob{}, sfcp.ErrAdmission
	}
	job, err := schema.Decode[control.VolumeFileJob](reply.Data)
	if err != nil || job.ID != id {
		return control.VolumeFileJob{}, sfcp.ErrAdmission
	}
	// A quorum permit may precede the native owner's local publication. Wait
	// for its durable command ordinal, then recheck the original job and the
	// current grant on that view. ReadAtLeast deliberately returns Local=true.
	view, err := r.Engine().ReadAtLeast(ctx, reply.CommandIndex)
	if err != nil {
		return control.VolumeFileJob{}, err
	}
	if epoch != 0 && view.State.ModuleEpoch() != epoch {
		return control.VolumeFileJob{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.VolumeFileWork(view.State, r.commandIdentity().Public, session, id, time.Now().Unix())
	if err != nil || volumes.NativeBindingDigest(current.Native) != volumes.NativeBindingDigest(job.Native) || current.Consumer != job.Consumer || current.Request != job.Request || current.Method != job.Method {
		return control.VolumeFileJob{}, sfcp.ErrAdmission
	}
	return current, nil
}
func (r *Runtime) saveVolumeFile(row volumeFileOwner) error {
	raw, err := json.Marshal(row)
	if err != nil {
		return err
	}
	return r.reports.Write(map[string][]byte{"volume/file/" + row.ID: raw})
}

// runVolumeFile holds the same shared Volume consumer and local native lease
// through all stream I/O, file/parent sync, journal sync and positive close.
// Transport loss never releases an unknown write or resubmits another job.
func (r *Runtime) runVolumeFile(ctx context.Context, session access.Session, job control.VolumeFileJob, channel userauth.VolumeFileIO) (userauth.VolumeFileReply, error) {
	if job.Native.Owner.Key != r.Identity.Public {
		owner, ok := r.nativeOwner(job.Native.Owner.Key)
		if !ok || !r.acceptsResourceOwner(ctx, job.Native.Owner.Node, job.Native.Owner.Key) {
			return userauth.VolumeFileReply{}, sfcp.ErrAdmission
		}
		return owner.runVolumeFile(ctx, session, job, channel)
	}
	if !r.volumeSourceMu.TryLock() {
		return userauth.VolumeFileReply{}, sfcp.ErrBudget
	}
	defer r.volumeSourceMu.Unlock()
	r.inputLife.RLock()
	defer r.inputLife.RUnlock()
	if r.ctx.Err() != nil || r.nativeVolumes == nil || job.Native.Owner.Key != r.Identity.Public {
		return userauth.VolumeFileReply{}, sfcp.ErrAdmission
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current, err := r.volumeFileWorkAt(ctx, session, job.ID, channel.Epoch)
	if err != nil || current.ID != job.ID || volumes.NativeBindingDigest(current.Native) != volumes.NativeBindingDigest(job.Native) || current.Consumer != job.Consumer {
		return userauth.VolumeFileReply{}, sfcp.ErrAdmission
	}
	row := volumeFileOwner{Schema: 1, ID: job.ID, Scope: job.Request.Scope, Native: volumes.NativeBindingDigest(job.Native), Consumer: job.Consumer, Phase: "intent"}
	raw, err := r.reports.GetBounded("volume/file/"+job.ID, 128<<10)
	if err == nil {
		old, e := schema.Decode[volumeFileOwner](raw)
		if e != nil || old.Schema != 1 || old.ID != row.ID || old.Scope != row.Scope || old.Native != row.Native || old.Consumer != row.Consumer {
			return userauth.VolumeFileReply{}, sfcp.ErrAdmission
		}
		row = old
	} else if !errors.Is(err, storage.ErrMissing) {
		return userauth.VolumeFileReply{}, err
	} else if channel.Recover {
		return row.Reply, sfcp.ErrAdmission
	} else if err = r.saveVolumeFile(row); err != nil {
		return userauth.VolumeFileReply{}, err
	}
	if row.Phase == "returned" {
		if err = r.reportVolumeFile(ctx, job, row.Reply); err != nil {
			return row.Reply, err
		}
		return row.Reply, nil
	}
	key, consumer := volumes.NativeKey(job.Native.Spec), volumes.DataConsumerID(job.Consumer)
	if row.Pin == nil {
		local, e := r.nativeVolumes.View(key)
		if e != nil {
			return row.Reply, e
		}
		pin, exists := local.Consumers[consumer]
		if !exists {
			lease, e := r.nativeVolumes.Pin(ctx, key, consumer, job.Native.Generation)
			if lease.Pin.Token != 0 {
				row.Pin = &lease
			}
			if e != nil {
				_ = r.saveVolumeFile(row)
				return row.Reply, e
			}
			pin = lease.Pin
		}
		if row.Pin == nil {
			row.Pin = &volumes.NativeLease{Key: key, Consumer: consumer, Owner: job.Native.Owner, Scope: job.Request.Scope, Pin: pin}
		}
		row.Phase = "pinned"
		if err = r.saveVolumeFile(row); err != nil {
			return row.Reply, err
		}
	}
	if channel.Recover && row.Phase != "applying" && row.Phase != "completed" {
		return row.Reply, sfcp.ErrAdmission
	}
	if row.Phase != "completed" {
		root, e := r.nativeVolumes.OpenConsumerData(ctx, job.Native, job.Consumer, *row.Pin)
		if e != nil {
			return row.Reply, e
		}
		reply := userauth.VolumeFileReply{Schema: 1, ID: job.ID, Code: "ok"}
		if row.Phase == "applying" {
			// Only the original staged inode/rename intent can prove this effect.
			if job.Method != "volume-file-put" || row.Publication == nil || row.Publication.Operation != job.ID || row.Publication.Path != job.Request.Path || row.Publication.Size != job.Request.Size || row.Publication.Digest != job.Request.Digest {
				root.Close()
				return row.Reply, sfcp.ErrAdmission
			}
			result, err := volumes.RecoverPutFile(ctx, root, *row.Publication)
			if err != nil {
				root.Close()
				return row.Reply, err
			}
			reply.Result = &result
		} else {
			row.Phase = "applying"
			if err = r.saveVolumeFile(row); err != nil {
				root.Close()
				return row.Reply, err
			}
			switch job.Method {
			case "volume-file-put":
				var result volumes.FileResult
				result, e = volumes.PutFileWithPublication(ctx, root, job.Request.Path, job.ID, channel.Source, job.Request.Size, job.Request.Digest, job.Request.Overwrite, func(p volumes.FilePublication) error {
					if _, err := r.volumeFileWorkAt(ctx, session, job.ID, channel.Epoch); err != nil {
						return err
					}
					row.Publication = &p
					return r.saveVolumeFile(row)
				})
				if e == nil {
					reply.Result = &result
				}
			case "volume-file-delete":
				e = volumes.DeleteFile(root, job.Request.Path)
			case "volume-file-list":
				reply.Entries, reply.Next, e = volumes.ListFiles(ctx, root, job.Request.Path, job.Request.After)
			case "volume-file-get":
				var file io.ReadCloser
				var info volumes.FileEntry
				file, info, e = volumes.OpenFileData(root, job.Request.Path, job.Request.MaxBytes)
				if e == nil {
					h := sha256.New()
					var size int64
					buffer := make([]byte, 24<<10)
					for {
						n, readErr := file.Read(buffer)
						if n > 0 {
							if channel.Write == nil {
								e = sfcp.ErrAdmission
								break
							}
							if e = channel.Write(buffer[:n]); e != nil {
								break
							}
							_, _ = h.Write(buffer[:n])
							size += int64(n)
						}
						if errors.Is(readErr, io.EOF) {
							break
						}
						if readErr != nil {
							e = readErr
							break
						}
					}
					clear(buffer)
					e = errors.Join(e, file.Close())
					var digest [32]byte
					copy(digest[:], h.Sum(nil))
					if e == nil && size == info.Size {
						reply.Result = &volumes.FileResult{Path: info.Path, Size: size, Digest: digest}
					} else if e == nil {
						e = sfcp.ErrAdmission
					}
				}
			default:
				e = sfcp.ErrAdmission
			}
		}
		if e != nil {
			var writeErr *volumes.FileWriteError
			known := job.Method != "volume-file-put" || errors.As(e, &writeErr) && !writeErr.MayHavePublished
			if known {
				reply.Code = "unavailable"
				if errors.Is(e, volumes.ErrFileConflict) {
					reply.Code = "conflict"
				} else if errors.Is(e, volumes.ErrFileLimit) {
					reply.Code = "limit"
				} else if errors.Is(e, volumes.ErrFilePath) {
					reply.Code = "invalid"
				}
				e = nil
			}
		}
		closeErr := root.Close()
		if e != nil || closeErr != nil {
			return row.Reply, errors.Join(e, closeErr)
		}
		row.Reply, row.Phase = reply, "completed"
		if err = r.saveVolumeFile(row); err != nil {
			return row.Reply, err
		}
	}
	return r.finishVolumeFile(ctx, job, row)
}

func (r *Runtime) finishVolumeFile(ctx context.Context, job control.VolumeFileJob, row volumeFileOwner) (userauth.VolumeFileReply, error) {
	// No open descriptor or live stream callback remains before native Return.
	if row.Pin == nil {
		return row.Reply, sfcp.ErrAdmission
	}
	local, err := r.nativeVolumes.View(row.Pin.Key)
	if err != nil {
		return row.Reply, err
	}
	if pin, exists := local.Consumers[row.Pin.Consumer]; exists {
		if pin != row.Pin.Pin {
			return row.Reply, sfcp.ErrAdmission
		}
		if err = r.nativeVolumes.Return(*row.Pin); err != nil {
			return row.Reply, err
		}
	}
	row.Phase = "returned"
	if err = r.saveVolumeFile(row); err != nil {
		return row.Reply, err
	}
	if err = r.reportVolumeFile(ctx, job, row.Reply); err != nil {
		return row.Reply, err
	}
	return row.Reply, nil
}

func (r *Runtime) reportVolumeFile(ctx context.Context, job control.VolumeFileJob, reply userauth.VolumeFileReply) error {
	// This is a signed positive close of the original consumer, not a new
	// user I/O admission. The leader rechecks its exact owner and CAS below;
	// a follower's local view supplies the report envelope and may be retried.
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return sfcp.ErrAdmission
	}
	if book, e := r.controlPolicy.Volumes(view.State); e == nil {
		if original, ok := book.VolumeFile(job.ID); ok && original.Phase == "Completed" {
			return nil
		}
	}
	gone := volumes.Gone{Scope: job.Request.Scope, Consumer: job.Consumer, Stopped: true, MountsGone: true}
	gone.Signature = ed25519.Sign(r.Identity.Private, volumes.GoneBytes(gone))
	report := control.VolumeFileReport{Schema: 1, Operation: "file", ID: job.ID, Code: reply.Code, Epoch: view.State.ModuleEpoch(), RootRevision: view.State.Object(control.VolumesKey).Revision, At: time.Now().Unix(), Result: reply.Result, Gone: gone}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.VolumeFileReportBytes(report))
	raw, _ := json.Marshal(report)
	out, err := r.appCall(ctx, "volume-file-report", raw)
	if err != nil {
		return err
	}
	if out.Committed == nil || out.Committed.Result.Code != state.Applied {
		return sfcp.ErrAdmission
	}
	return nil
}

// Only positively completed original I/O is auto-settled after a disconnect or
// credential revocation. Applying/unknown writes retain their exact references.
func (r *Runtime) advanceVolumeFiles(ctx context.Context, v cluster.View) error {
	if r.reports == nil || r.nativeVolumes == nil || !r.volumeSourceMu.TryLock() {
		return nil
	}
	defer r.volumeSourceMu.Unlock()
	rows, err := r.reports.ScanBounded("volume/file/", 256, 32<<20)
	if err != nil {
		return err
	}
	book, err := r.controlPolicy.Volumes(v.State)
	if err != nil {
		return err
	}
	for _, raw := range rows {
		row, err := schema.Decode[volumeFileOwner](raw)
		if err != nil || row.Schema != 1 {
			return sfcp.ErrAdmission
		}
		if row.Phase != "completed" && row.Phase != "returned" {
			continue
		}
		job, ok := book.VolumeFile(row.ID)
		if !ok || job.Native.Owner.Key != r.Identity.Public || volumes.NativeBindingDigest(job.Native) != row.Native || job.Consumer != row.Consumer {
			return sfcp.ErrAdmission
		}
		if job.Phase == "Completed" {
			continue
		}
		if row.Phase == "returned" {
			err = r.reportVolumeFile(ctx, job, row.Reply)
		} else {
			_, err = r.finishVolumeFile(ctx, job, row)
		}
		if err != nil {
			return err
		}
		return nil
	}
	return nil
}
