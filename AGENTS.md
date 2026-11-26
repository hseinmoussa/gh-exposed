# Notes for coding agents

- Go, one dependency (`gopkg.in/yaml.v3`). Do not add another without asking.
- Layout: `internal/workflow` (parse workflows and `uses:`), `internal/incident` (catalogue + verdict rules), `internal/ghapi` (read-only REST client), `internal/logscan` (log evidence), `internal/scan` (orchestration), `internal/report` (text/markdown/json), `internal/cli` (commands; `main.go` is a thin wrapper).
- Run `go test -race ./...` and `go vet ./...` before finishing. CI also runs golangci-lint v2.15.0, govulncheck and zizmor.
- Hard rule: a secret VALUE must never reach output, logs or errors. `logscan` extracts names only.
- Verdicts: only log evidence may produce `confirmed`; `Target.Assess` (file-based) never does.
- Incidents must cite a GitHub advisory; see CONTRIBUTING.md.
