package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mthamil107/whotyped/internal/alert"
	"github.com/mthamil107/whotyped/internal/config"
)

func replayDryRun(t *testing.T, scenario string, cfg config.Config) []alert.Alert {
	t.Helper()
	var out bytes.Buffer
	err := Run(context.Background(), cfg, Options{
		Replay: filepath.Join("..", "..", "testdata", "dataset", scenario, "events.jsonl"),
		DryRun: true,
		Stdout: &out,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var alerts []alert.Alert
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var a alert.Alert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatalf("bad alert line %q: %v", line, err)
		}
		alerts = append(alerts, a)
	}
	return alerts
}

// TestReplayMCPParamiko is the Windows-runnable end-to-end check: the
// dispatcher must emit agent_detected at 88 for the paramiko MCP scenario.
func TestReplayMCPParamiko(t *testing.T) {
	cfg := config.Default()
	cfg.Host = "test-host"
	alerts := replayDryRun(t, "mcp-paramiko", cfg)
	if len(alerts) == 0 {
		t.Fatal("no alerts printed")
	}
	var detected *alert.Alert
	for i := range alerts {
		if alerts[i].Event == alert.EvDetected {
			detected = &alerts[i]
		}
	}
	if detected == nil {
		t.Fatalf("no agent_detected among %d alerts", len(alerts))
	}
	// agent_detected goes out at the first crossing of 70 (score 83 for this
	// dataset); the track's final verdict, 88, is what simulate --offline shows.
	if detected.Score < 70 || detected.Level != "alert" || detected.Class != "suspected_agent" || detected.Host != "test-host" {
		t.Fatalf("unexpected alert: score=%d level=%s class=%s host=%s", detected.Score, detected.Level, detected.Class, detected.Host)
	}
	if detected.Schema != alert.Schema || detected.SessionID == "" || len(detected.Reasons) == 0 {
		t.Fatalf("incomplete alert %+v", detected)
	}
}

func TestReplayHumanStaysQuiet(t *testing.T) {
	if alerts := replayDryRun(t, "human-admin", config.Default()); len(alerts) != 0 {
		t.Fatalf("human admin produced %d alerts: %+v", len(alerts), alerts[0])
	}
}

func TestReplayDeclaredAgent(t *testing.T) {
	alerts := replayDryRun(t, "declared-agent", config.Default())
	found := false
	for _, a := range alerts {
		if a.Event == alert.EvDeclared && a.Class == "declared_agent" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no agent_declared among %+v", alerts)
	}
}

func TestProfilesFilteredByConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Allowlist.ProfilesEnabled = []string{"ansible"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pack, err := loadPack(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Profiles) != 1 || pack.Profiles[0].ID != "ansible" {
		t.Fatalf("profiles %+v", pack.Profiles)
	}
	cfg.Allowlist.ProfilesEnabled = nil
	pack, _ = loadPack(cfg, log)
	if len(pack.Profiles) != 0 {
		t.Fatalf("expected no profiles, got %d", len(pack.Profiles))
	}
}

func TestRunRejectsBadRulesDir(t *testing.T) {
	cfg := config.Default()
	cfg.Rules.Dirs = []string{filepath.Join("..", "..", "internal", "app")} // .go files only: no yaml, so fine
	cfg.Allowlist.ExtraFile = "app.go"                                      // not YAML: must fail as ErrConfig
	err := Run(context.Background(), cfg, Options{Replay: "x", DryRun: true, Stdout: io.Discard,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err == nil || !strings.Contains(err.Error(), ErrConfig.Error()) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

// TestRunLiveShutsDownCleanly starts the live loop with a file source (the
// only reader that runs on every OS) and cancels it: Run must return within
// two seconds with no error, having stopped the reader and flushed state.
func TestRunLiveShutsDownCleanly(t *testing.T) {
	cfg := config.Default()
	cfg.Host = "test-host"
	cfg.StateDir = t.TempDir()
	cfg.Readers.SSHLog = config.SSHLog{Source: "file", File: filepath.Join("..", "..", "testdata", "sshlog", "openssh-9.6-ubuntu2404-verbose.log")}
	cfg.Readers.Auditd.Enabled = false
	cfg.Readers.Procfs.Enabled = false
	cfg.Readers.Netconn.Enabled = false
	cfg.Sinks.JSONFile.Path = filepath.Join(cfg.StateDir, "alerts.jsonl")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	}()
	// Give the reader a moment to open the file, then stop everything.
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runLive did not return within 2s of cancel")
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "state.json")); err != nil {
		t.Fatalf("state not persisted on shutdown: %v", err)
	}
}
