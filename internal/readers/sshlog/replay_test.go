package sshlog

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/event"
)

const fixtureDir = "../../../testdata/sshlog"

// golden is the expected event count per Kind for each fixture. Counts were
// derived by hand from the fixture text; a change here is a parser change.
var golden = map[string]map[event.Kind]int{
	"openssh-8.9-ubuntu2204.log": {
		event.SSHAuthOK: 1, event.SSHPAMOpen: 2, event.SSHSessionStart: 1, event.SSHAuthFail: 5, event.SSHDisconnect: 6,
	},
	"openssh-9.6-ubuntu2404-verbose.log": {
		event.SSHAuthOK: 1, event.SSHPAMOpen: 2, event.SSHSessionStart: 14, event.SSHDisconnect: 17,
	},
	"openssh-9.8-sshd-session.log": {
		event.SSHAuthOK: 1, event.SSHPAMOpen: 2, event.SSHSessionStart: 2, event.SSHDisconnect: 7, event.SSHAuthFail: 1,
	},
	"openssh-10.0-sshd-auth.log": {
		event.SSHAuthOK: 1, event.SSHPAMOpen: 2, event.SSHSessionStart: 1, event.SSHDisconnect: 4, event.SSHAuthFail: 9,
	},
	"debug1-banner.log": {
		event.SSHBanner: 2, event.SSHEnv: 3, event.SSHAuthOK: 2, event.SSHPAMOpen: 4, event.SSHSessionStart: 2, event.SSHDisconnect: 4,
	},
	"rhel9-secure.log": {
		event.SSHAuthOK: 2, event.SSHPAMOpen: 4, event.SSHSessionStart: 2, event.SSHDisconnect: 7, event.SSHAuthFail: 5,
	},
	"journal.jsonl": {
		event.SSHAuthOK: 1, event.SSHPAMOpen: 2, event.SSHSessionStart: 1, event.SSHDisconnect: 3, event.SSHAuthFail: 1,
	},
}

func TestReplayGolden(t *testing.T) {
	for name, want := range golden {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join(fixtureDir, name))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			events := ReplayReader(f, now)
			got := map[event.Kind]int{}
			for _, ev := range events {
				got[ev.Kind]++
				if ev.Source != Source {
					t.Errorf("Source=%q", ev.Source)
				}
				if ev.TS.IsZero() {
					t.Errorf("zero TS on %+v", ev)
				}
				if ev.Field("ident") == "" || ev.Field("host") == "" {
					t.Errorf("missing ident/host on %+v", ev)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("counts=%v want %v", got, want)
			}
		})
	}
}

// The ControlMaster fixture is what the rhythm clue is built on: 14 exec
// channels on one connection, all under one PID, sub-second gaps.
func TestReplayControlMasterShape(t *testing.T) {
	f, err := os.Open(filepath.Join(fixtureDir, "openssh-9.6-ubuntu2404-verbose.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var starts []event.Event
	for _, ev := range ReplayReader(f, now) {
		if ev.Kind == event.SSHSessionStart {
			starts = append(starts, ev)
		}
	}
	if len(starts) != 14 {
		t.Fatalf("got %d session starts", len(starts))
	}
	for i, ev := range starts {
		if ev.PID != 2216 || ev.User != "alice" || ev.SrcPort != 60122 || ev.Field("stype") != "command" || ev.Field("tty") != "" {
			t.Errorf("start %d: %+v", i, ev)
		}
		if i > 0 {
			gap := ev.TS.Sub(starts[i-1].TS)
			if gap < 300*time.Millisecond || gap > 1500*time.Millisecond {
				t.Errorf("gap %d = %s outside expected range", i, gap)
			}
		}
	}
}

func TestReplayJournalCursorAndTS(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(fixtureDir, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	events := ReplayReader(bytesReader(b), now)
	if len(events) == 0 {
		t.Fatal("no events")
	}
	first := events[0]
	if first.Kind != event.SSHAuthOK || first.PID != 1234 || first.Field("host") != "web-03" {
		t.Errorf("first=%+v", first)
	}
	if !first.TS.Equal(time.UnixMicro(1757599402114532)) {
		t.Errorf("TS=%s", first.TS)
	}
	// The _PID-only entry (no SYSLOG_PID) must still carry its pid.
	for _, ev := range events {
		if ev.Kind == event.SSHSessionStart && ev.PID != 1240 {
			t.Errorf("session_start PID=%d want 1240", ev.PID)
		}
	}
}
