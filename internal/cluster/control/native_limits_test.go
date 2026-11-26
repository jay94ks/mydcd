// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/tenancy"
)

// A refused native permit names the limit that refused it, and stays ErrCatalog.
func TestNativePacketLimitsNameTheirReason(t *testing.T) {
	global := tenancy.NodeLimit{Node: "node-a", MaxConsumers: 16, PacketQueuePackets: 64, PacketQueueBytes: 1 << 20}
	scoped := tenancy.NodeLimit{Tenant: "shop", Node: "node-a", MaxConsumers: 8}
	if _, err := checkPacketLimits("shop", "node-a", global, scoped, 1280); !errors.Is(err, ErrCatalog) || !strings.Contains(err.Error(), "tenant shop packet queue on server node-a") {
		t.Fatal(err)
	}
	scoped.PacketQueuePackets, scoped.PacketQueueBytes = 8, 64<<10
	limits, err := checkPacketLimits("shop", "node-a", global, scoped, 1280)
	if err != nil || limits.QueuePackets != 8 || limits.QueueBytes != 64<<10 {
		t.Fatal(limits, err)
	}
	global.PacketQueueBytes = 1000
	if _, err = checkPacketLimits("shop", "node-a", global, scoped, 1280); !errors.Is(err, ErrCatalog) || !strings.Contains(err.Error(), "server node-a packet queue") {
		t.Fatal(err)
	}
	if err = checkNativeLimits("shop", "node-a", [32]byte{1}, tenancy.Quotas{}, global, true, scoped, false); !errors.Is(err, ErrCatalog) || !strings.Contains(err.Error(), "tenant shop has no limit on server node-a") {
		t.Fatal(err)
	}
}
