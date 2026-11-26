# Security policy

## Reporting a vulnerability in gh-exposed

Please report it privately through GitHub: **Security → Report a vulnerability** on this repository ([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)). Do not open a public issue.

You will get an answer within 7 days. A fix for a confirmed issue is released as soon as it is ready, with a GitHub security advisory.

## What gh-exposed promises

- **It only reads.** Every GitHub API call is a GET.
- **It never outputs a secret value.** It decodes memory dumps in logs only to read secret *names*; values are not stored, printed or written to the report. If you ever see a value in its output, that is a security bug: report it as above.
- **Downloaded logs are temporary.** Each log archive is written to the system temp directory, scanned, and deleted.
- **A new report file (`--out`) is created with mode 0600**, because it names secrets and runs. An existing file keeps its current permissions.

## Supported versions

Only the latest release gets fixes.
