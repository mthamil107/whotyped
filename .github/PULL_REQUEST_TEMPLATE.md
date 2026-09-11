## What

One or two sentences. Link the issue if there is one (`Closes #123`).

## Why

What problem this solves or what evidence prompted it (a false positive, a new agent, a distro whose logs we misparsed).

## How tested

- [ ] `go build ./... && go test ./... && go vet ./...` and `gofmt -l .` is empty
- [ ] `GOOS=linux GOARCH=amd64 go build ./...`
- [ ] Ran on a real host (which distro / OpenSSH?) or `whotyped run --replay` against a dataset case
- [ ] For rule-pack changes: `whotyped rules validate rules/` and a fixture or dataset case added
- [ ] For Sigma changes: `sigma check deploy/sigma/`
- [ ] For chart or role changes: `helm lint` / `ansible-lint`

## Checklist

- [ ] Commits are signed off (`git commit -s`, DCO)
- [ ] No new dependencies, no network calls outside configured sinks
- [ ] Evidence strings stay privacy-redacted
- [ ] Docs updated if behaviour or config changed
- [ ] No usernames, hostnames, IPs, fingerprints or secrets in fixtures and examples
- [ ] Changes to frozen contracts, scoring weights or the alert schema: discussed in an issue first (needs two maintainer approvals)

## Notes for the reviewer

Anything you are unsure about, or want a second opinion on.
