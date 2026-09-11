package check

import (
	"bufio"
	"io"
	"sort"
	"strings"
)

// ParseAuditRules scans auditctl-style rules and reports whether an
// always,exit rule on execve exists for the 64-bit and 32-bit ABIs, plus
// the distinct keys (-k / -F key=) attached to those rules. A rule without
// `-F arch=` uses the native ABI, which whotyped counts as b64.
func ParseAuditRules(r io.Reader) (hasExecve64, hasExecve32 bool, keys []string) {
	keySet := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		toks := strings.Fields(line)
		var (
			action   string
			arch     string
			syscalls []string
			ruleKeys []string
		)
		for i := 0; i < len(toks); i++ {
			t := toks[i]
			next := func() string {
				if i+1 < len(toks) {
					i++
					return toks[i]
				}
				return ""
			}
			switch t {
			case "-a", "-A":
				action = strings.ToLower(next())
			case "-S":
				syscalls = append(syscalls, strings.Split(next(), ",")...)
			case "-F":
				v := next()
				switch {
				case strings.HasPrefix(v, "arch="):
					arch = strings.TrimPrefix(v, "arch=")
				case strings.HasPrefix(v, "key="):
					ruleKeys = append(ruleKeys, strings.TrimPrefix(v, "key="))
				}
			case "-k":
				ruleKeys = append(ruleKeys, next())
			}
		}
		if !(strings.Contains(action, "always") && strings.Contains(action, "exit")) {
			continue
		}
		execve := false
		for _, s := range syscalls {
			switch s {
			case "execve", "all", "59", "11", "221", "322", "execveat":
				execve = true
			}
		}
		if !execve {
			continue
		}
		switch arch {
		case "b32", "i386":
			hasExecve32 = true
		default:
			hasExecve64 = true
		}
		for _, k := range ruleKeys {
			if k != "" {
				keySet[k] = true
			}
		}
	}
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return hasExecve64, hasExecve32, keys
}
