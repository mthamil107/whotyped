// Package webhook posts alerts to an HTTP endpoint as Slack Block Kit, a
// Microsoft Teams Adaptive Card, a Discord embed, or the raw alert JSON.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/whotyped/whotyped/internal/alert"
	"github.com/whotyped/whotyped/internal/score"
)

// ErrTransient is alert.ErrTransient; 5xx, 429 and network failures wrap it
// so the dispatcher retries them, while other 4xx are permanent.
var ErrTransient = alert.ErrTransient

// Formats accepted by New. FormatJSON is the config-file spelling of
// FormatGeneric (sinks.webhook.format: json) and is normalised to it.
const (
	FormatSlack   = "slack"
	FormatTeams   = "teams"
	FormatDiscord = "discord"
	FormatGeneric = "generic"
	FormatJSON    = "json"
)

// Sink is an HTTP webhook sink.
type Sink struct {
	url     string
	format  string
	headers map[string]string
	client  *http.Client
}

// New builds a sink. format "" means generic; an unknown format is reported
// by every Send rather than silently downgraded. timeout <= 0 means 10s.
func New(url, format string, timeout time.Duration, headers map[string]string) alert.Sink {
	format = strings.ToLower(format)
	if format == "" || format == FormatJSON {
		format = FormatGeneric
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	return &Sink{url: url, format: strings.ToLower(format), headers: h, client: &http.Client{Timeout: timeout}}
}

// Name implements alert.Sink.
func (s *Sink) Name() string { return "webhook:" + s.format }

// Send posts the formatted payload.
func (s *Sink) Send(ctx context.Context, a alert.Alert) error {
	body, err := Payload(s.format, a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "whotyped")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: webhook: %v", ErrTransient, err)
	}
	defer resp.Body.Close()
	// Drain a little so the connection can be reused; the body is not useful.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("%w: webhook: %s", ErrTransient, resp.Status)
	default:
		return fmt.Errorf("webhook: %s", resp.Status)
	}
}

// Payload renders a for the given format. Exported so config validation and
// `simulate --dry-run` can show what would be sent.
func Payload(format string, a alert.Alert) ([]byte, error) {
	switch format {
	case FormatSlack:
		return json.Marshal(slackPayload(a))
	case FormatTeams:
		return json.Marshal(teamsPayload(a))
	case FormatDiscord:
		return json.Marshal(discordPayload(a))
	case FormatGeneric, FormatJSON:
		return json.Marshal(a)
	}
	return nil, fmt.Errorf("webhook: unknown format %q", format)
}

func title(a alert.Alert) string { return fmt.Sprintf("whotyped: %s on %s", a.Event, a.Host) }

func agentOrDash(a alert.Alert) string {
	if a.Agent == "" {
		return "-"
	}
	return a.Agent
}

func reasonLines(a alert.Alert, bullet string, esc func(string) string) string {
	if len(a.Reasons) == 0 {
		return bullet + "(no reasons recorded)"
	}
	var b strings.Builder
	for i, r := range a.Reasons {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s%s (%d): %s", bullet, esc(r.ID), r.Weight, esc(r.Evidence))
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Slack

// slackEscape escapes the three characters Slack treats as control sequences
// inside mrkdwn text; evidence strings can contain shell fragments.
func slackEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func slackPayload(a alert.Alert) map[string]any {
	field := func(name, val string) map[string]any {
		return map[string]any{"type": "mrkdwn", "text": "*" + name + "*\n" + slackEscape(val)}
	}
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": title(a), "emoji": false}},
		{"type": "section", "fields": []map[string]any{
			field("User", a.User),
			field("Source IP", a.SrcIP),
			field("Score", fmt.Sprint(a.Score)),
			field("Level", string(a.Level)),
			field("Agent", agentOrDash(a)),
			field("Class", string(a.Class)),
		}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": reasonLines(a, "• ", slackEscape)}},
	}
	if a.FreezeWindow != nil {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": fmt.Sprintf(":no_entry: *Freeze window* %s until %s",
				slackEscape(a.FreezeWindow.Name), a.FreezeWindow.Until.UTC().Format(time.RFC3339))},
		})
	}
	blocks = append(blocks, map[string]any{"type": "context", "elements": []map[string]any{
		{"type": "mrkdwn", "text": slackEscape(a.ActionsHint)},
	}})
	return map[string]any{
		"text":   title(a) + " — " + a.User + "@" + a.SrcIP + " score " + fmt.Sprint(a.Score),
		"blocks": blocks,
	}
}

// ---------------------------------------------------------------------------
// Teams

func teamsPayload(a alert.Alert) map[string]any {
	facts := []map[string]string{
		{"title": "User", "value": a.User},
		{"title": "Source IP", "value": a.SrcIP},
		{"title": "Score", "value": fmt.Sprint(a.Score)},
		{"title": "Level", "value": string(a.Level)},
		{"title": "Agent", "value": agentOrDash(a)},
		{"title": "Class", "value": string(a.Class)},
		{"title": "Session", "value": a.SessionID},
	}
	if a.FreezeWindow != nil {
		facts = append(facts, map[string]string{"title": "Freeze window",
			"value": a.FreezeWindow.Name + " until " + a.FreezeWindow.Until.UTC().Format(time.RFC3339)})
	}
	ident := func(s string) string { return s }
	body := []map[string]any{
		{"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": title(a), "wrap": true},
		{"type": "FactSet", "facts": facts},
		{"type": "TextBlock", "text": reasonLines(a, "- ", ident), "wrap": true},
		{"type": "TextBlock", "text": a.ActionsHint, "wrap": true, "isSubtle": true},
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"msteams": map[string]any{"width": "Full"},
				"body":    body,
			},
		}},
	}
}

// ---------------------------------------------------------------------------
// Discord

// Discord webhook limits (execute-webhook endpoint): content 2000, embed
// title 256, description 4096, field value 1024, footer 2048; a field value
// must not be empty.
const (
	discordContentMax = 2000
	discordTitleMax   = 256
	discordDescMax    = 4096
	discordFieldMax   = 1024
	discordFooterMax  = 2048
)

// discordEscape neutralises the markdown Discord renders inside embeds;
// evidence fragments carry shell text (`*`, `_`, `|`, backticks).
func discordEscape(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "*", "\\*", "_", "\\_", "~", "\\~", "`", "\\`", "|", "\\|")
	return r.Replace(s)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func discordPayload(a alert.Alert) map[string]any {
	color := 0x3498DB // info: blue
	switch a.Level {
	case score.LevelHigh:
		color = 0xE74C3C // red
	case score.LevelAlert:
		color = 0xE67E22 // orange
	}
	field := func(name, val string, inline bool) map[string]any {
		if val == "" {
			val = "-" // Discord rejects empty field values
		}
		return map[string]any{"name": name, "value": truncate(discordEscape(val), discordFieldMax), "inline": inline}
	}
	fields := []map[string]any{
		field("User", a.User, true),
		field("Source IP", a.SrcIP, true),
		field("Score", fmt.Sprint(a.Score), true),
		field("Level", string(a.Level), true),
		field("Agent", agentOrDash(a), true),
		field("Class", string(a.Class), true),
		field("Session", a.SessionID, false),
	}
	if a.FreezeWindow != nil {
		fields = append(fields, field("Freeze window",
			a.FreezeWindow.Name+" until "+a.FreezeWindow.Until.UTC().Format(time.RFC3339), false))
	}
	embed := map[string]any{
		"title":       truncate(title(a), discordTitleMax),
		"description": truncate(reasonLines(a, "• ", discordEscape), discordDescMax),
		"color":       color,
		"fields":      fields,
		"footer":      map[string]any{"text": truncate(a.ActionsHint, discordFooterMax)},
	}
	if !a.TS.IsZero() {
		embed["timestamp"] = a.TS.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"content": truncate(title(a)+" — "+a.User+"@"+a.SrcIP+" score "+fmt.Sprint(a.Score), discordContentMax),
		"embeds":  []map[string]any{embed},
	}
}
