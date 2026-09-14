package procfs

import (
	"testing"
	"time"

	"github.com/mthamil107/whotyped/internal/rules"
)

// TestNewDefaultsAndNetSwitch: zero Options give the documented defaults with
// the connection scan on; NoNet is the switch behind readers.netconn.enabled.
func TestNewDefaultsAndNetSwitch(t *testing.T) {
	r := New(&rules.Pack{}, Options{})
	if !r.NetEnabled || r.Interval != 5*time.Second || r.NetInterval != 10*time.Second || r.Name() != "procfs" {
		t.Fatalf("defaults: %+v", r)
	}
	r = New(&rules.Pack{}, Options{NoNet: true, NetInterval: time.Second})
	if r.NetEnabled {
		t.Fatal("NoNet must clear NetEnabled")
	}
}
