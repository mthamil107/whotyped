# Engineering rules for whotyped contributors

- Module `github.com/mthamil107/whotyped`, Go 1.26, `CGO_ENABLED=0`. Only dependency allowed: `gopkg.in/yaml.v3`. Everything else is stdlib.
- CI runs `go mod tidy -diff`; keep `go.mod` tidy.
- Core types in `internal/event`, `internal/session/types.go`, `internal/clues/clue.go`, `internal/score/verdict.go`, `internal/alert/alert.go` and `internal/rules/types.go` are a public contract between packages: change them additively and note it in the PR.
- Code must build and test on Linux, macOS and Windows; Linux-only readers live in `*_linux.go` with `*_other.go` stubs. Every `*_linux.go` file has a `*_other.go` (build tag `//go:build !linux`) stub that returns `readers.ErrUnsupportedPlatform` or a no-op. Parsers take `io.Reader`/`fs.FS`/strings and are tested with fixtures in `testdata/`.
- Also verify `GOOS=linux GOARCH=amd64 go build ./...` (cross-compile) before finishing.
- `gofmt -l .` must print nothing; `go vet ./...` must pass.
- Small readable code. Comments explain why. No telemetry, no network calls except configured sinks.
- Evidence strings in clues must be privacy-redacted: matched fragment, argv0, length; never a full command line unless `privacy.command_text: full`.
- Never re-parse text found inside another record as a log line (log-line injection defence).
