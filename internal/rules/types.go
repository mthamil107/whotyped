// Package rules loads YAML rule packs (agents, banners, styles, api hosts) and
// allowlist profiles. Types here are the frozen contract; loader.go implements
// loading, merging and validation.
package rules

// SchemaRules is the value of `schema:` in rule pack files.
const SchemaRules = "whotyped.rules.v1"

// SchemaAllowlist is the value of `schema:` in allowlist files.
const SchemaAllowlist = "whotyped.allowlist.v1"

// Agent describes one AI agent / tool.
type Agent struct {
	ID           string   `yaml:"id" json:"id"`
	Display      string   `yaml:"display" json:"display"`
	Vendor       string   `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	ProcessNames []string `yaml:"process_names,omitempty" json:"process_names,omitempty"` // matches comm or basename(exe)
	ArgvContains []string `yaml:"argv_contains,omitempty" json:"argv_contains,omitempty"` // substring of joined argv
	EnvVars      []string `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`           // presence in environ (NAME or NAME=value)
	EnvAIAgent   []string `yaml:"env_ai_agent,omitempty" json:"env_ai_agent,omitempty"`   // AI_AGENT values mapping to this id
	SkipFlags    []string `yaml:"skip_flags,omitempty" json:"skip_flags,omitempty"`
	APIHosts     []string `yaml:"api_hosts,omitempty" json:"api_hosts,omitempty"`
	SSHBanners   []string `yaml:"ssh_banners,omitempty" json:"ssh_banners,omitempty"` // regexes
	ToolWrappers []string `yaml:"tool_wrappers,omitempty" json:"tool_wrappers,omitempty"`
	Notes        string   `yaml:"notes,omitempty" json:"notes,omitempty"`
	References   []string `yaml:"references,omitempty" json:"references,omitempty"`
	Disabled     bool     `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// Banner classifies an SSH client software version string.
type Banner struct {
	ID       string `yaml:"id" json:"id"`
	Regex    string `yaml:"regex" json:"regex"`
	Kind     string `yaml:"kind" json:"kind"` // library | automation | human
	Agent    string `yaml:"agent,omitempty" json:"agent,omitempty"`
	Notes    string `yaml:"notes,omitempty" json:"notes,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// Style is a command-text pattern typical of tool-driven shells.
type Style struct {
	ID       string `yaml:"id" json:"id"`
	Regex    string `yaml:"regex" json:"regex"`
	Weight   int    `yaml:"weight" json:"weight"`
	Group    string `yaml:"group,omitempty" json:"group,omitempty"` // e.g. pager_guard (shared cap)
	Notes    string `yaml:"notes,omitempty" json:"notes,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// Host is an AI API destination.
type Host struct {
	Host     string `yaml:"host,omitempty" json:"host,omitempty"`
	CIDR     string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
	Port     int    `yaml:"port,omitempty" json:"port,omitempty"` // 0 = 443
	Agent    string `yaml:"agent,omitempty" json:"agent,omitempty"`
	Vendor   string `yaml:"vendor,omitempty" json:"vendor,omitempty"`
	Notes    string `yaml:"notes,omitempty" json:"notes,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// Match is the AND-of-conditions block of an allowlist profile.
type Match struct {
	Users         []string      `yaml:"users,omitempty" json:"users,omitempty"`
	SrcCIDRs      []string      `yaml:"src_cidrs,omitempty" json:"src_cidrs,omitempty"`
	Fingerprints  []string      `yaml:"fingerprints,omitempty" json:"fingerprints,omitempty"`
	AnyOf         []MatchClause `yaml:"any_of,omitempty" json:"any_of,omitempty"`
	MinMatchRatio float64       `yaml:"min_match_ratio,omitempty" json:"min_match_ratio,omitempty"`
}

// MatchClause is one OR-alternative inside Match.AnyOf. Required marks a
// clause that at least one exec channel must satisfy on its own, on top of
// the min_match_ratio over all clauses: "at least one command under
// ~/.vscode-server, and most commands either that or git polling". It is an
// additive, backwards-compatible field; profiles that omit it behave as
// before.
type MatchClause struct {
	CmdRegex    string `yaml:"cmd_regex,omitempty" json:"cmd_regex,omitempty"`
	Argv0Regex  string `yaml:"argv0_regex,omitempty" json:"argv0_regex,omitempty"`
	PathRegex   string `yaml:"path_regex,omitempty" json:"path_regex,omitempty"`
	BannerRegex string `yaml:"banner_regex,omitempty" json:"banner_regex,omitempty"`
	Required    bool   `yaml:"required,omitempty" json:"required,omitempty"`
}

// Profile is an allowlist profile.
type Profile struct {
	ID                  string   `yaml:"id" json:"id"`
	Description         string   `yaml:"description,omitempty" json:"description,omitempty"`
	Match               Match    `yaml:"match" json:"match"`
	Suppress            []string `yaml:"suppress" json:"suppress"` // clue ids or category names
	MaxScore            int      `yaml:"max_score,omitempty" json:"max_score,omitempty"`
	AllowAgentProcesses bool     `yaml:"allow_agent_processes,omitempty" json:"allow_agent_processes,omitempty"`
	Disabled            bool     `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// Pack is the merged, validated rule set the detectors use.
type Pack struct {
	Version  string    `json:"version"`
	Agents   []Agent   `json:"agents"`
	Banners  []Banner  `json:"banners"`
	Styles   []Style   `json:"styles"`
	APIHosts []Host    `json:"api_hosts"`
	Profiles []Profile `json:"profiles"`
}
