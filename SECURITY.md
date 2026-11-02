# Security policy

## Supported content

The `main` branch is the supported version of the course, labs, Learning Hub,
quiz, build tooling, and deployment workflows. Historical commits and local
forks may contain older protocol, SDK, dependency, or control assumptions.

## Report a vulnerability

Use **Security → Report a vulnerability** in this GitHub repository to send a
private report. Do not include exploit details, credentials, customer data, or
other sensitive evidence in a public issue or pull request.

Include the affected file or deployed route, a minimal reproduction, expected
and observed behavior, impact, and any safe remediation ideas. Reports about a
course claim should identify the exact protocol/SDK version and explain whether
the issue affects teaching content, executable enforcement, tests, or the
published site.

This repository contains credential-free teaching fixtures. Never test a
report against systems, tenants, accounts, or data you do not own or have
explicit permission to assess.

## Response and disclosure

The maintainer will acknowledge the report, validate scope, and coordinate a
fix and disclosure appropriate to its impact. A report is not considered
resolved until the relevant code or content, regression tests, lockfiles or
generated assets, and deployment evidence agree.
