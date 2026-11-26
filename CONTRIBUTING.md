# Contributing

Thanks for helping. The most valuable contribution is usually **a new incident**: the day a tag-rewrite attack is announced, people need it in the catalogue.

## Add an incident

Edit [`internal/incident/incidents.json`](internal/incident/incidents.json) and add one entry:

```json
{
  "id": "owner-action-2026",
  "title": "What happened, in one line",
  "advisory": "GHSA-xxxx-xxxx-xxxx",
  "cve": "CVE-2026-NNNNN",
  "url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
  "start": "2026-01-01T10:00:00Z",
  "end": "2026-01-01T14:00:00Z",
  "window_note": "Only if the advisory's window is approximate: say how you turned it into times.",
  "payload": "What the malicious code did, and whether it printed secrets to the log.",
  "targets": [
    {
      "action": "owner/action",
      "malicious_shas": ["<full 40-character SHA>"],
      "malicious_shas_complete": true,
      "safe_refs": ["v2.0.1"],
      "moved_refs": "tags",
      "any_ref": false
    }
  ],
  "indicators": ["a C2 domain or payload URL that would appear in a log"]
}
```

Rules:

- **Cite a GitHub advisory** (`url` must be `https://github.com/advisories/GHSA-...`). Every fact in the entry must come from the advisory or from a source it links.
- **Use full, lower-case commit SHAs.**
- Set **`malicious_shas_complete: true` only if the advisory lists every malicious commit.** It lets a clean commit in a log clear a run, so a wrong `true` hides real exposure.
- Set **`moved_refs: "tags"`** only if the advisory says the attacker moved tags (not branches). A reference to a branch of that name is then cleared.
- Set **`any_ref: true`** for an action that calls the compromised one internally with a movable ref: it was affected however it was pinned.
- A target whose window differs from the incident's gets its own `start` / `end`.

`go test ./internal/incident/` validates the catalogue.

## Code

```bash
go test -race ./...
go vet ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...
```

- One dependency is a feature: a tool run during a supply-chain incident should have a tiny supply chain. Discuss before adding one.
- Never let a secret value reach output, a log line or an error message. Tests assert this; keep them passing.
- Every action in `.github/workflows` is pinned to a full commit SHA, with the version in a comment.
