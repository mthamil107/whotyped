package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whotyped/whotyped/internal/alert"
	"github.com/whotyped/whotyped/internal/clues"
	"github.com/whotyped/whotyped/internal/score"
)

func sample() alert.Alert {
	return alert.Alert{
		Schema: alert.Schema, TS: time.Date(2026, 9, 11, 14, 3, 22, 0, time.UTC), Host: "web-03",
		Event: alert.EvDetected, Class: score.ClassSuspected, Mode: "remote_agent",
		User: "alice", SrcIP: "10.0.0.5", KeyFingerprint: "SHA256:Qm3k", Score: 82, Level: score.LevelAlert,
		Reasons: []clues.Clue{
			{ID: "rhythm.burst", Category: clues.CatRhythm, Weight: 20, Evidence: "14 exec channels in 92s"},
			{ID: "style.tool_wrapper", Category: clues.CatStyle, Weight: 8, Evidence: "bash -lc <cmd> && cat"},
		},
		Suppressed: []score.Suppression{}, SessionID: "tr_9f31c2a7b8e4", Connections: 1,
		ActionsHint: "Ask alice whether an AI tool is driving this key.",
	}
}

type capture struct {
	mu      sync.Mutex
	body    []byte
	headers http.Header
	status  int
}

func (c *capture) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.body, c.headers = b, r.Header.Clone()
		status := c.status
		c.mu.Unlock()
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		io.WriteString(w, "ok")
	}))
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("payload is not JSON: %v\n%s", err, b)
	}
	return m
}

func TestSlackFormat(t *testing.T) {
	c := &capture{}
	srv := c.server()
	defer srv.Close()
	s := New(srv.URL, "slack", time.Second, map[string]string{"X-Token": "abc"})
	if s.Name() != "webhook:slack" {
		t.Fatalf("name %q", s.Name())
	}
	if err := s.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	if c.headers.Get("X-Token") != "abc" || c.headers.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", c.headers)
	}
	m := decode(t, c.body)
	blocks := m["blocks"].([]any)
	header := blocks[0].(map[string]any)
	if header["type"] != "header" || header["text"].(map[string]any)["text"] != "whotyped: agent_detected on web-03" {
		t.Fatalf("header block %v", header)
	}
	fields := blocks[1].(map[string]any)["fields"].([]any)
	joined := ""
	for _, f := range fields {
		joined += f.(map[string]any)["text"].(string) + "|"
	}
	for _, want := range []string{"*User*\nalice", "*Source IP*\n10.0.0.5", "*Score*\n82", "*Level*\nalert", "*Agent*\n-"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("fields missing %q in %q", want, joined)
		}
	}
	reasons := blocks[2].(map[string]any)["text"].(map[string]any)["text"].(string)
	if !strings.Contains(reasons, "• rhythm.burst (20): 14 exec channels in 92s") {
		t.Fatalf("reasons %q", reasons)
	}
	if !strings.Contains(reasons, "bash -lc &lt;cmd&gt; &amp;&amp; cat") {
		t.Fatalf("mrkdwn not escaped: %q", reasons)
	}
	hint := blocks[3].(map[string]any)["elements"].([]any)[0].(map[string]any)["text"]
	if hint != sample().ActionsHint {
		t.Fatalf("hint %v", hint)
	}
}

func TestSlackFreezeBlock(t *testing.T) {
	a := sample()
	a.Event = alert.EvFreeze
	a.FreezeWindow = &alert.Freeze{Name: "release", Until: a.TS.Add(time.Hour)}
	b, err := Payload("slack", a)
	if err != nil {
		t.Fatal(err)
	}
	blocks := decode(t, b)["blocks"].([]any)
	if len(blocks) != 5 || !strings.Contains(blocks[3].(map[string]any)["text"].(map[string]any)["text"].(string), "release") {
		t.Fatalf("freeze block missing: %d blocks", len(blocks))
	}
}

func TestTeamsFormat(t *testing.T) {
	c := &capture{}
	srv := c.server()
	defer srv.Close()
	if err := New(srv.URL, "teams", time.Second, nil).Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	m := decode(t, c.body)
	if m["type"] != "message" {
		t.Fatalf("envelope %v", m)
	}
	att := m["attachments"].([]any)[0].(map[string]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("attachment %v", att)
	}
	card := att["content"].(map[string]any)
	if card["type"] != "AdaptiveCard" || card["version"] != "1.4" {
		t.Fatalf("card %v", card)
	}
	body := card["body"].([]any)
	if body[0].(map[string]any)["text"] != "whotyped: agent_detected on web-03" {
		t.Fatalf("title %v", body[0])
	}
	facts := body[1].(map[string]any)["facts"].([]any)
	if facts[0].(map[string]any)["value"] != "alice" || len(facts) != 7 {
		t.Fatalf("facts %v", facts)
	}
	if txt := body[2].(map[string]any)["text"].(string); !strings.Contains(txt, "- rhythm.burst (20): 14 exec channels in 92s") {
		t.Fatalf("reasons %q", txt)
	}
}

func TestGenericFormat(t *testing.T) {
	c := &capture{}
	srv := c.server()
	defer srv.Close()
	if err := New(srv.URL, "", time.Second, nil).Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	var back alert.Alert
	if err := json.Unmarshal(c.body, &back); err != nil {
		t.Fatal(err)
	}
	if back.Schema != alert.Schema || back.Event != alert.EvDetected || back.Score != 82 || len(back.Reasons) != 2 {
		t.Fatalf("round trip %+v", back)
	}
}

func TestStatusClassification(t *testing.T) {
	c := &capture{}
	srv := c.server()
	defer srv.Close()
	s := New(srv.URL, "generic", time.Second, nil)
	cases := []struct {
		status    int
		wantErr   bool
		transient bool
	}{
		{200, false, false}, {204, false, false},
		{400, true, false}, {404, true, false},
		{429, true, true}, {500, true, true}, {503, true, true},
	}
	for _, tc := range cases {
		c.mu.Lock()
		c.status = tc.status
		c.mu.Unlock()
		err := s.Send(context.Background(), sample())
		if (err != nil) != tc.wantErr {
			t.Fatalf("status %d: err=%v", tc.status, err)
		}
		if errors.Is(err, ErrTransient) != tc.transient || alert.IsTransient(err) != tc.transient {
			t.Fatalf("status %d: transient=%v err=%v", tc.status, tc.transient, err)
		}
	}
	// Connection refused is transient too.
	srv.Close()
	if err := s.Send(context.Background(), sample()); !errors.Is(err, ErrTransient) {
		t.Fatalf("network error not transient: %v", err)
	}
}

func TestUnknownFormat(t *testing.T) {
	s := New("http://127.0.0.1:1", "carrier-pigeon", time.Second, nil)
	err := s.Send(context.Background(), sample())
	if err == nil || errors.Is(err, ErrTransient) {
		t.Fatalf("unknown format should be a permanent error, got %v", err)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	err := New(srv.URL, "generic", 50*time.Millisecond, nil).Send(context.Background(), sample())
	if !errors.Is(err, ErrTransient) {
		t.Fatalf("timeout should be transient: %v", err)
	}
}

func TestDiscordFormat(t *testing.T) {
	c := &capture{}
	srv := c.server()
	defer srv.Close()
	s := New(srv.URL, "discord", time.Second, nil)
	if s.Name() != "webhook:discord" {
		t.Fatalf("name %q", s.Name())
	}
	a := sample()
	a.Reasons[1].Evidence = "bash -lc `cat *.env` | head" // markdown-significant characters
	a.FreezeWindow = &alert.Freeze{Name: "release", Until: a.TS.Add(time.Hour)}
	if err := s.Send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	m := decode(t, c.body)
	if !strings.Contains(m["content"].(string), "alice@10.0.0.5 score 82") {
		t.Errorf("content %q", m["content"])
	}
	embeds := m["embeds"].([]any)
	if len(embeds) != 1 {
		t.Fatalf("embeds %v", embeds)
	}
	e := embeds[0].(map[string]any)
	if e["title"] != "whotyped: agent_detected on web-03" || e["color"] != float64(0xE67E22) {
		t.Errorf("title/color %v %v", e["title"], e["color"])
	}
	desc := e["description"].(string)
	if !strings.Contains(desc, "rhythm.burst (20)") || strings.Contains(desc, "`cat *.env`") || !strings.Contains(desc, "\\`cat \\*.env\\`") {
		t.Errorf("description not escaped: %q", desc)
	}
	fields := e["fields"].([]any)
	if len(fields) != 8 {
		t.Fatalf("fields %d", len(fields))
	}
	first := fields[0].(map[string]any)
	if first["name"] != "User" || first["value"] != "alice" || first["inline"] != true {
		t.Errorf("first field %v", first)
	}
	last := fields[7].(map[string]any)
	if last["name"] != "Freeze window" || !strings.Contains(last["value"].(string), "release until 2026-09-11T15:03:22Z") {
		t.Errorf("freeze field %v", last)
	}
	if e["footer"].(map[string]any)["text"] != a.ActionsHint || e["timestamp"] != "2026-09-11T14:03:22Z" {
		t.Errorf("footer/timestamp %v %v", e["footer"], e["timestamp"])
	}

	// High is red; an empty field value becomes "-" rather than an invalid embed.
	a.Level = score.LevelHigh
	a.SrcIP = ""
	b, err := Payload(FormatDiscord, a)
	if err != nil {
		t.Fatal(err)
	}
	e = decode(t, b)["embeds"].([]any)[0].(map[string]any)
	if e["color"] != float64(0xE74C3C) || e["fields"].([]any)[1].(map[string]any)["value"] != "-" {
		t.Errorf("high/empty handling: %v", e)
	}
}

// TestAllFormatsRender: every config-accepted format produces JSON, and
// "json" is the generic format under its config name.
func TestAllFormatsRender(t *testing.T) {
	for _, f := range []string{FormatGeneric, FormatJSON, FormatSlack, FormatTeams, FormatDiscord} {
		b, err := Payload(f, sample())
		if err != nil || len(b) == 0 {
			t.Errorf("%s: %v", f, err)
		}
		decode(t, b)
	}
	g, _ := Payload(FormatGeneric, sample())
	j, _ := Payload(FormatJSON, sample())
	if string(g) != string(j) {
		t.Error("json must be an alias of generic")
	}
	if New("http://x", "JSON", 0, nil).Name() != "webhook:generic" || New("http://x", "", 0, nil).Name() != "webhook:generic" {
		t.Error("New must normalise json/empty to generic")
	}
}

// TestErrorsNeverLeakWebhookPath: transport failures are wrapped by
// net/http in a *url.Error whose Error() prints the whole URL; the path of
// a Slack/Teams/Discord webhook is the credential.
func TestErrorsNeverLeakWebhookPath(t *testing.T) {
	// A listener that is closed immediately gives a deterministic refused
	// connection on a port nobody else holds.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	secret := "T000/B000/xoxb-SECRET-TOKEN"
	for _, format := range []string{FormatSlack, FormatTeams, FormatDiscord, FormatGeneric} {
		s := New("http://"+addr+"/services/"+secret+"?token=q", format, time.Second, nil)
		err := s.Send(context.Background(), sample())
		if err == nil {
			t.Fatalf("%s: expected an error", format)
		}
		msg := err.Error()
		if strings.Contains(msg, secret) || strings.Contains(msg, "/services") || strings.Contains(msg, "token=q") {
			t.Fatalf("%s: error leaks the URL: %s", format, msg)
		}
		if !strings.Contains(msg, "http://"+addr) || !errors.Is(err, alert.ErrTransient) {
			t.Fatalf("%s: error should name the host and be transient: %s", format, msg)
		}
	}
	// A context deadline mid-request goes the same way.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = New(srv.URL+"/hooks/"+secret, FormatSlack, 200*time.Millisecond, nil).Send(ctx, sample())
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "/hooks") {
		t.Fatalf("timeout error leaks: %v", err)
	}
	// An unparsable URL is reported without echoing it.
	err = New("http://[::1]:namedport/"+secret, FormatSlack, time.Second, nil).Send(context.Background(), sample())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("bad url error leaks: %v", err)
	}
}

// TestChatMarkdownEscaped: attacker-controlled names (comm, AI_AGENT) reach
// the cards; markdown in them must render as text.
func TestChatMarkdownEscaped(t *testing.T) {
	a := sample()
	a.Agent = "*urgent*_[click](https://evil.example)`code`#1~"
	a.User = "<@channel>&*"
	a.Reasons[0].Evidence = "comm [x](y) *bold*"
	teams, err := Payload(FormatTeams, a)
	if err != nil {
		t.Fatal(err)
	}
	ts := string(teams)
	for _, raw := range []string{`[click](https://evil.example)`, "*urgent*", "`code`#1", "[x](y)"} {
		if strings.Contains(ts, raw) {
			t.Errorf("teams card carries unescaped %q", raw)
		}
	}
	// JSON doubles every backslash: an escaped `*` is `\\*` on the wire.
	for _, esc := range []string{"\\\\*urgent\\\\*", "\\\\[click\\\\]\\\\(https://evil.example\\\\)", "\\\\#1", "\\\\`code\\\\`"} {
		if !strings.Contains(ts, esc) {
			t.Errorf("teams escaping missing %q in: %s", esc, ts)
		}
	}
	slack, err := Payload(FormatSlack, a)
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(slack, &top); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(top.Text, "<@channel>") || !strings.Contains(top.Text, "&lt;@channel&gt;&amp;*") {
		t.Errorf("slack fallback text not escaped: %q", top.Text)
	}
}
