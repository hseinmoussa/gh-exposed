# gh-exposed

**A GitHub Action you use was compromised. Which of your runs executed it, can you prove it, and which secrets do you rotate first?**

`gh exposed` answers that in one command, across every repository in your organization, from GitHub's own run history and logs.

[![ci](https://github.com/hseinmoussa/gh-exposed/actions/workflows/ci.yml/badge.svg)](https://github.com/hseinmoussa/gh-exposed/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/hseinmoussa/gh-exposed)](https://github.com/hseinmoussa/gh-exposed/releases)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

```console
$ gh exposed scan --incident tj-actions-changed-files-2025 --owner acme

RESULT
======

1 run(s) CONFIRMED to have executed the compromised code, 1 more POSSIBLY did.
Rotate the secrets below, starting with critical.

SECRETS TO ROTATE
=================

Priority  Repository  Secret     Why                                            Runs
--------  ----------  ---------  ---------------------------------------------  -----------
CRITICAL  acme/web    NPM_TOKEN  its value is printed (encoded) in the run log  14012345678

RUNS
====

acme/web (public)
-----------------

CONFIRMED  run 14012345678  .github/workflows/ci.yml  push on main  started 2025-03-14T16:02:11Z
https://github.com/acme/web/actions/runs/14012345678
- evidence: the run log shows the runner downloaded the malicious commit 0e58ed8671d6
- evidence: the log contains an encoded memory dump with 1 secret value(s) in it
- job build: tj-actions/changed-files@v45 (pinned to "v45", a ref the attacker could move) via ci.yml:7
- secret names found in the log: NPM_TOKEN
- logs: scanned

POSSIBLE  run 14012399999  .github/workflows/a.yml  pull_request on -  started 2025-03-14T19:02:11Z
- the workflow used the action with a movable ref inside the window; the logs have
  expired, so this cannot be confirmed or cleared
- secrets readable: ALL (the job uses secrets: inherit, toJSON(secrets) or a dynamic secrets[...] lookup)
```

<sub>Example output with made-up repository names. Trimmed for length.</sub>

## Why this exists

Tag-rewrite attacks on GitHub Actions keep happening: [tj-actions/changed-files](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3) and [reviewdog](https://github.com/advisories/GHSA-qmg3-hpqr-gqvc) in March 2025, [xygeni-action](https://github.com/advisories/GHSA-f8q5-h5qh-33mh) and [trivy-action](https://github.com/advisories/GHSA-69fq-xp46-6x23) in March 2026. Every advisory ends with the same instruction: *review your workflow runs from the exposure window and rotate the secrets they could read.* Nobody tells you how. Doing it by hand means opening run after run, reading logs, decoding base64 and guessing which secrets each job had.

Tools like [zizmor](https://github.com/zizmorcore/zizmor), [pinact](https://github.com/suzuki-shunsuke/pinact) and [Harden-Runner](https://github.com/step-security/harden-runner) help you **prevent** or **detect** the next one. `gh exposed` is for **the day after**: the incident has happened and you need an answer.

## What it does

- **Finds every run in the exposure window** across one repository, an organization or a user, and reads the workflow file **at the commit that ran** (today's file is usually already fixed).
- **Follows the whole chain**: composite actions, local actions and reusable workflows, nested, with cycle detection. A compromised action three levels deep is still found, and the report shows the path (`ci.yml:12 -> setup/action.yml:4`).
- **Proves it from the logs.** The runner logs the exact commit it downloaded for every action (`Download action repository 'x@v45' (SHA:...)`). A malicious SHA there means **confirmed**. A clean SHA, when the advisory lists every malicious commit, **clears** the run.
- **Finds dumped secrets.** It decodes the double-base64 memory dumps that the tj-actions and reviewdog payloads printed into logs and reports the secret **names** inside. It never prints, stores or returns secret values.
- **Builds the rotation list.** It names the secrets each affected job could actually read (by name, plus `secrets: inherit`, `toJSON(secrets)` and dynamic `secrets[...]`), skips fork pull requests (no secrets), skips `GITHUB_TOKEN` (revoked when the job ends), and ranks secrets: **critical** (value is in a log, or in a public log), **high** (confirmed run), **medium** (possible run).
- **Knows the real incidents**, each sourced from its GitHub advisory: windows, malicious SHAs, refs that were never moved, and indicators of compromise. For a new incident, pass `--action`, `--since` and `--until` yourself.
- **Never calls an incomplete scan clean.** GitHub deletes old run records, so for an older incident an empty run list proves nothing: gh-exposed detects that and checks the workflow files as they were at the end of the window instead. A repository or run it could not read is reported, and the exit code is `1`, not `0`.
- **Works in CI**: text, Markdown or JSON output, and exit codes (`0` clean, `2` possible, `3` confirmed, `1` error or incomplete).
- **Small and auditable**: one Go binary, one dependency (`gopkg.in/yaml.v3`), read-only API calls, and signed build provenance on every release.

## Install

```bash
gh extension install hseinmoussa/gh-exposed
```

This needs the [GitHub CLI](https://cli.github.com). Or install with Go:

```bash
go install github.com/hseinmoussa/gh-exposed@latest
```

To verify a downloaded release binary was built by this repository's release workflow (releases from v0.1.1 on; v0.1.0 was built before attestations were enabled):

```bash
gh attestation verify <path-to-downloaded-binary> --repo hseinmoussa/gh-exposed
```

## Quick start

1. See the incidents it knows:

   ```bash
   gh exposed incidents
   ```

2. Scan your organization for one of them:

   ```bash
   gh exposed scan --incident trivy-action-2026 --owner my-org
   ```

3. A new incident that is not in the catalogue yet:

   ```bash
   gh exposed scan --action some/action --since 2026-11-20 --until 2026-11-22 \
     --malicious-sha 0123456789abcdef0123456789abcdef01234567 --owner my-org
   ```

4. Before the exposure window is even known, find where you use the action today:

   ```bash
   gh exposed usage --action some/action --owner my-org
   ```

Write the report to a file for the incident ticket:

```bash
gh exposed scan --incident tj-actions-changed-files-2025 --owner my-org --format markdown --out exposure.md
```

## Built-in incidents

| ID | Actions | Window (UTC) | Advisory |
|---|---|---|---|
| `trivy-action-2026` | aquasecurity/trivy-action, aquasecurity/setup-trivy | 2026-03-19 17:43 to 2026-03-20 05:40 | [GHSA-69fq-xp46-6x23](https://github.com/advisories/GHSA-69fq-xp46-6x23) |
| `xygeni-action-2026` | xygeni/xygeni-action | 2026-03-03 to 2026-03-10 | [GHSA-f8q5-h5qh-33mh](https://github.com/advisories/GHSA-f8q5-h5qh-33mh) |
| `tj-actions-changed-files-2025` | tj-actions/changed-files | 2025-03-14 to 2025-03-15 | [GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3) |
| `reviewdog-action-setup-2025` | reviewdog/action-setup and 5 actions that use it | 2025-03-11 18:42 to 20:31 | [GHSA-qmg3-hpqr-gqvc](https://github.com/advisories/GHSA-qmg3-hpqr-gqvc) |

Missing one? Adding an incident is a single JSON entry: see [CONTRIBUTING.md](CONTRIBUTING.md).

## How a run is judged

| Verdict | Meaning |
|---|---|
| **confirmed** | The run's log shows the malicious commit downloaded, an indicator of compromise, or a dumped secret. |
| **possible** | The workflow used the action with a movable ref (a tag or branch) inside the window, and no log evidence settles it (for example, the logs expired). Treat its secrets as exposed. |
| **not exposed** | The action was pinned to a full commit SHA that is not malicious; or used a ref the advisory says was never moved; or used a branch when the advisory says only tags were moved; or the log shows a clean commit and the advisory lists every malicious one. |

A run counts as "in the window" if any attempt of it was active during the window: a re-run days later does not hide a first attempt that ran inside it, and a run created before the window whose jobs were still running inside it is included.

## Flags

```text
gh exposed scan
  --incident ID           built-in incident (see `gh exposed incidents`)
  --action OWNER/REPO     or: a compromised action not in the catalogue, with
  --since / --until       the exposure window (YYYY-MM-DD or RFC 3339, UTC; a date --until means end of day)
  --malicious-sha SHA     a commit the attacker used; log evidence of it confirms a run (repeatable)
  --owner ORG             scan every repository of an organization or user (repeatable)
  --repo OWNER/REPO       scan one repository (repeatable)
  --deep                  scan the logs of EVERY run in the window, not only flagged ones
  --no-logs               skip logs (fast; nothing can be confirmed or cleared)
  --rerun-lookback-days N also list runs created up to N days (1-30, default 30) before the window, to catch re-runs inside it
  --format text|markdown|json   --out FILE   --fail-on possible|confirmed|never
  --concurrency N (default 4)   --max-log-mb N (default 500)   --api-url URL (GitHub Enterprise Server)
```

## Token and permissions

The token comes from `GH_TOKEN`, then `GITHUB_TOKEN`, then `gh auth token`. Every call is a read. A fine-grained token needs these repository permissions:

- **Metadata: read**, **Contents: read** and **Actions: read**: required (Actions covers runs, jobs and logs).
- **Secrets: read**: optional. Only used to list secret names when a job read every secret.

## Limits

- **Logs expire, and so do runs.** GitHub keeps run logs for 90 days by default and at most 400, and in testing it no longer listed runs from early 2025 at all. Runs without logs can only be judged from their workflow files, so they stay **possible**. When the run history does not reach the window, gh-exposed reads the workflows on the default branch as they were at the end of the window and flags each one that used the action; it cannot tell how many times, or whether, such a workflow ran in the window, and it does not see other branches.
- **Tags have no history.** A composite action reached through a movable ref is expanded from that ref's content *today*. A nested call the attacker added and later removed is invisible in the files. `--deep` reads every run's log to catch it while logs exist.
- **Pull requests** run the workflow from the merge commit; gh-exposed reads it at the pull request's head commit, which almost always holds the same workflow.
- **Local actions inside another repository's reusable workflow** are read from that workflow's repository; at run time GitHub may resolve them against the caller's checkout instead.
- **Refs are judged as they are today.** Whether a ref is a branch or a tag is read now; a name that was both during the window and lost its tag in the clean-up is treated as a branch.
- **Runs deleted by hand** are invisible. If a repository deleted its runs from the window but kept older ones, the history check cannot tell; use `usage` and the workflow history to check by hand.
- **Re-runs more than `--rerun-lookback-days` after a run was created** are not seen. GitHub allows re-runs for 30 days, the default.
- **More than 1,000 runs within two seconds** in one repository cannot be listed completely (GitHub caps a filtered listing at 1,000 results).
- **Environment secrets** are not listed by name; a job that reads all secrets is reported as "every secret this repository can use".
- **Runs, not artifacts.** It does not check binaries, images or packages a compromised run produced.

## Contributing

Bug reports, new incidents and fixes are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue in gh-exposed itself, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
