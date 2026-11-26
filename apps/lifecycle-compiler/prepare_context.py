#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Assemble an explicit local compiler image context; never build/download/run."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile
import tarfile


def static_elf(path):
    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
            raise ValueError("a static Linux ELF64 executable is required")
        machine = struct.unpack_from("<H", header, 18)[0]
        offset = struct.unpack_from("<Q", header, 32)[0]
        entry_size, count = struct.unpack_from("<HH", header, 54)
        if machine not in (62, 183) or entry_size < 56 or count > 1024:
            raise ValueError("unsupported compiler architecture or ELF header")
        for index in range(count):
            stream.seek(offset + index * entry_size)
            program = stream.read(entry_size)
            if len(program) != entry_size or struct.unpack_from("<I", program)[0] == 3:
                raise ValueError("dynamic/interpreter-dependent compiler input")
        return machine


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            result.update(block)
    return result.hexdigest()


def export_registry(context, output):
    """Export local rootfs bytes to the existing bounded Registry V2 fixture."""
    context = Path(context).resolve(strict=True)
    output = Path(output).absolute()
    metadata = json.loads((context / "context.json").read_text())
    if output.exists() or output.is_symlink() or metadata["schema"] != 1:
        raise ValueError("new registry cache output and schema 1 context required")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".compiler-registry-", dir=output.parent))
    try:
        blobs = staging / "blobs/sha256"
        blobs.mkdir(parents=True)
        layer = staging / "layer.gz"
        uncompressed = hashlib.sha256()

        class LayerWriter:
            def __init__(self, stream):
                self.stream = stream

            def write(self, data):
                uncompressed.update(data)
                return self.stream.write(data)

        def ordinary(info):
            if not (info.isfile() or info.isdir()):
                raise ValueError("ordinary local compiler context files required")
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            return info

        with layer.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=1, mtime=0) as compressed:
                with tarfile.open(mode="w|", fileobj=LayerWriter(compressed), format=tarfile.GNU_FORMAT) as archive:
                    for path in sorted((context / "rootfs").iterdir()):
                        archive.add(path, arcname=path.name, filter=ordinary)
        if layer.stat().st_size > 512 << 20:
            raise ValueError("compiler layer exceeds bounded fixture descriptor")
        layer_digest = "sha256:" + digest(layer)
        layer_size = layer.stat().st_size
        layer.rename(blobs / layer_digest[7:])

        def encode(value):
            return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

        config = encode({"architecture": metadata["architecture"], "os": "linux",
                         "config": {"User": "10001:10001", "WorkingDir": "/work",
                                    "Entrypoint": ["/usr/local/bin/lifecycle-compiler"]},
                         "rootfs": {"type": "layers", "diff_ids": ["sha256:" + uncompressed.hexdigest()]}})
        config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
        (blobs / config_digest[7:]).write_bytes(config)
        media = "application/vnd.docker.distribution.manifest.v2+json"
        manifest = encode({"schemaVersion": 2, "mediaType": media,
                           "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                                      "digest": config_digest, "size": len(config)},
                           "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                                       "digest": layer_digest, "size": layer_size}]})
        image_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        (staging / "lifecycle-compiler-manifest.json").write_bytes(manifest)
        (staging / "images.json").write_bytes(encode({"schema": 1, "images": [
            {"Repository": "lifecycle-compiler", "Digest": image_digest, "Config": config_digest}]}))
        staging.rename(output)
        return {"image": image_digest, "config": config_digest, "layer_bytes": layer_size}
    except BaseException:
        shutil.rmtree(staging)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--toolchain-version", required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--registry-cache", type=Path, help="optional immutable local Registry V2 fixture export")
    args = parser.parse_args()
    toolchain = args.toolchain.resolve(strict=True)
    compiler = args.compiler.resolve(strict=True)
    output = args.out.absolute()
    if output.exists() or output.is_symlink() or not compiler.is_file():
        parser.error("output must be new and compiler must be an existing local file")
    if (toolchain / "VERSION").read_text().splitlines()[0] != args.toolchain_version:
        parser.error("toolchain VERSION differs from the fixed requested version")
    machine = static_elf(compiler)
    if static_elf(toolchain / "bin/go") != machine:
        parser.error("compiler and Go toolchain architectures differ")
    # Reject symlink escapes and special files before copying any toolchain
    # source. The original checkout/toolchain/caches remain unchanged.
    for directory, folders, files in os.walk(toolchain, followlinks=False):
        for name in folders + files:
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                parser.error("toolchain context requires ordinary files/directories without symlinks")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".lifecycle-compiler-", dir=output.parent))
    try:
        rootfs = staging / "rootfs"
        for directory in ("input", "work", "output", "cache", "usr/local/bin", "opt"):
            (rootfs / directory).mkdir(parents=True, exist_ok=True)
        shutil.copytree(toolchain, rootfs / "opt/go")
        target = rootfs / "usr/local/bin/lifecycle-compiler"
        shutil.copyfile(compiler, target)
        target.chmod(0o555)
        source = Path(__file__).resolve().parent
        for name in ("Dockerfile", ".dockerignore"):
            shutil.copyfile(source / name, staging / name)
        metadata = {"schema": 1, "toolchain": args.toolchain_version,
                    "architecture": "amd64" if machine == 62 else "arm64",
                    "compiler_sha256": digest(compiler),
                    "go_sha256": digest(toolchain / "bin/go"),
                    "network_or_container_actions": False}
        (staging / "context.json").write_text(json.dumps(metadata, indent=2) + "\n")
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging)
        raise
    if args.registry_cache:
        export_registry(output, args.registry_cache)
    print(json.dumps({"schema": 1, "context": str(output), "assembled": True,
                      "image_built": False, "container_started": False}))


if __name__ == "__main__":
    main()
