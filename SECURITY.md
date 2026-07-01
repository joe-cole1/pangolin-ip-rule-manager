# Security Policy

## Supported versions

Only the latest released version on `master` is supported. Please upgrade to the
most recent release before reporting an issue.

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public issue
for anything security-sensitive.

Use GitHub's private vulnerability reporting for this repository:
**Security → Report a vulnerability** (the "Report a vulnerability" button on the
repository's Security tab). This opens a private advisory visible only to the
maintainers.

When reporting, please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept if possible).
- The affected version or commit.

You can expect an initial acknowledgement within a few days. Because this project
runs in a single production environment with no staging, please allow time for a
fix to be validated before any public disclosure.

## Scope notes

This service gates network access to protected resources. Findings in the
following areas are especially valued:

- The request authorization chain (`Remote-User` handling, resource filtering).
- IP extraction from forwarded headers.
- The `/update` endpoint and any HTML rendered from user-controlled input.
- Container/deployment configuration (Docker socket exposure, secrets handling).
