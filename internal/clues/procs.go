package clues

import (
	"fmt"
	"strings"
	"time"

	"github.com/mthamil107/whotyped/internal/rules"
	"github.com/mthamil107/whotyped/internal/session"
)

const (
	WeightProcAgentName = 45
	WeightProcAgentEnv  = 40
	WeightProcSkipFlags = 25

	maxProcEvidence = 3
)

// Procs matches live processes attributed to the track against the agent
// rules: the binary name, the environment markers agents leave in children,
// and permission-skipping flags.
type Procs struct{}

// ID implements Detector.
func (Procs) ID() string { return "procs" }

// Evaluate implements Detector.
func (Procs) Evaluate(t *session.Track, p *rules.Pack, now time.Time) []Clue {
	if t == nil || len(t.Procs) == 0 {
		return nil
	}
	var names, envs, flags []string
	for _, ps := range t.Procs {
		label := fmt.Sprintf("%s (pid %d)", procName(ps), ps.PID)
		if a := matchProcAgent(ps, p); a != nil {
			names = append(names, label+" "+a.ID)
		} else if ps.Agent != "" { // the procfs reader already matched a rule
			names = append(names, label+" "+ps.Agent)
		}
		if _, kv := matchProcEnv(ps, p); kv != "" {
			envs = append(envs, label+" "+kv)
		}
		if f := matchSkipFlag(ps, p); f != "" {
			flags = append(flags, label+" "+f)
		}
	}
	var out []Clue
	if len(names) > 0 {
		out = append(out, Clue{ID: "proc.agent_name", Category: CatProcess, Weight: WeightProcAgentName, Evidence: joinEvidence(names), TS: now})
	}
	if len(envs) > 0 {
		out = append(out, Clue{ID: "proc.agent_env", Category: CatProcess, Weight: WeightProcAgentEnv, Evidence: joinEvidence(envs), TS: now})
	}
	if len(flags) > 0 {
		out = append(out, Clue{ID: "proc.skip_flags", Category: CatFlags, Weight: WeightProcSkipFlags, Evidence: joinEvidence(flags), TS: now})
	}
	return out
}

func procName(ps session.ProcSample) string {
	switch {
	case ps.Comm != "":
		return ps.Comm
	case ps.Exe != "":
		return basename(ps.Exe)
	}
	return Fragment("", ps.Cmd)
}

// matchProcAgent finds the agent whose process name or argv substring matches.
func matchProcAgent(ps session.ProcSample, p *rules.Pack) *rules.Agent {
	if p == nil {
		return nil
	}
	comm, exe := strings.ToLower(ps.Comm), strings.ToLower(basename(ps.Exe))
	cmd := strings.ToLower(ps.Cmd)
	for i := range p.Agents {
		a := &p.Agents[i]
		if a.Disabled {
			continue
		}
		for _, n := range a.ProcessNames {
			n = strings.ToLower(n)
			if n != "" && (n == comm || n == exe) {
				return a
			}
		}
		for _, s := range a.ArgvContains {
			if s != "" && strings.Contains(cmd, strings.ToLower(s)) {
				return a
			}
		}
	}
	return nil
}

// matchProcEnv finds an agent whose env marker is present; returns the agent
// and the "NAME=value" that matched. Rules may be "NAME" or "NAME=value".
func matchProcEnv(ps session.ProcSample, p *rules.Pack) (*rules.Agent, string) {
	if p == nil || len(ps.Env) == 0 {
		return nil, ""
	}
	for i := range p.Agents {
		a := &p.Agents[i]
		if a.Disabled {
			continue
		}
		for _, rule := range a.EnvVars {
			name, want, hasVal := strings.Cut(rule, "=")
			got, ok := ps.Env[name]
			if !ok || (hasVal && got != want) {
				continue
			}
			return a, name + "=" + Fragment("", got)
		}
	}
	return nil, ""
}

// matchSkipFlag returns the permission-skipping flag seen on the process:
// either pre-extracted by the reader (ps.Flags) or found in the command line.
func matchSkipFlag(ps session.ProcSample, p *rules.Pack) string {
	if len(ps.Flags) > 0 {
		return ps.Flags[0]
	}
	if p == nil || ps.Cmd == "" {
		return ""
	}
	for _, a := range p.Agents {
		if a.Disabled {
			continue
		}
		for _, f := range a.SkipFlags {
			if f != "" && strings.Contains(ps.Cmd, f) {
				return f
			}
		}
	}
	return ""
}

func joinEvidence(parts []string) string {
	if len(parts) <= maxProcEvidence {
		return strings.Join(parts, "; ")
	}
	return strings.Join(parts[:maxProcEvidence], "; ") + fmt.Sprintf(" +%d more", len(parts)-maxProcEvidence)
}
