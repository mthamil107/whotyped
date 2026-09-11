# Engineering rules for whotyped contributors (and build agents)

- Module `github.com/whotyped/whotyped`, Go 1.26, `CGO_ENABLED=0`. Only dependency allowed: `gopkg.in/yaml.v3`. Everything else is stdlib.
- Do NOT run `go mod tidy` while other engineers are working; do not edit `go.mod`/`go.sum`.
- Frozen contracts (do not modify; ask the lead): `internal/event/event.go`, `internal/readers/reader.go`, `internal/clues/clue.go`, `internal/session/types.go`, `internal/score/verdict.go`, `internal/alert/alert.go`, `internal/rules/types.go`.
- The dev machine is Windows. `go build ./...` and `go test ./...` must pass on Windows. Linux-only code goes in `*_linux.go`; every such file has a `*_other.go` (build tag `//go:build !linux`) stub that returns `readers.ErrUnsupportedPlatform` or a no-op. Parsers take `io.Reader`/`fs.FS`/strings and are tested with fixtures in `testdata/`.
- Also verify `GOOS=linux GOARCH=amd64 go build ./...` (cross-compile) before finishing.
- `gofmt -l .` must print nothing; `go vet ./...` must pass.
- Small readable code. Comments explain why. No telemetry, no network calls except configured sinks.
- Evidence strings in clues must be privacy-redacted: matched fragment, argv0, length; never a full command line unless `privacy.command_text: full`.
- Never re-parse text found inside another record as a log line (log-line injection defence).
- Stay inside your owned files. If you need a helper from another package that does not exist yet, write a minimal local one in your package rather than editing theirs.
