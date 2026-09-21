# MCP Security Engineering

> A notebook-first course for securing Model Context Protocol servers, clients,
> tools, identities, dependencies, and agent-protocol workflows.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Learning materials](https://github.com/mahsa-teimourikia/mcp-security/actions/workflows/validate-learning.yml/badge.svg)](https://github.com/mahsa-teimourikia/mcp-security/actions/workflows/validate-learning.yml)

## Start here: MCP Security Learning Hub

**[Open the MCP Security Learning Hub →](https://mahsa-teimourikia.github.io/mcp-security/)**

The Hub is the main learning experience. Choose a level, open a topic, read the
chapter, run its credential-free lab and notebook, then complete the
[knowledge check](https://mahsa-teimourikia.github.io/mcp-security/quiz/).

## What you will learn

MCP makes tools, resources, and prompts interoperable. It does not make them
trusted. This course teaches the boundary that every lesson preserves:

```text
model or agent -> proposes, predicts, extracts, recommends
trusted application -> validates, authorizes, executes, verifies, records
```

| Level | Focus | Outcome |
| --- | --- | --- |
| Beginner | Lifecycle, trust boundaries, threat modeling, safe interfaces | Explain protocol authority and reject unsafe capabilities |
| Intermediate | Identity, authorization, delegation, isolation, supply chain | Enforce least privilege and evidence-based release gates |
| Advanced | Testing, composition, assurance, incidents, enterprise governance | Detect, contain, recover, and operate an MCP security program |

## Repository structure

```text
app/          Vite/React Learning Hub
assets/       Shared diagrams and brand assets
curriculum/   Canonical beginner, intermediate, and advanced lessons
quiz/         Standalone, tested knowledge check
scripts/      Course and link validators
tests/        Curriculum and production-site smoke tests
```

Every published lesson is colocated:

```text
curriculum/<level>/<number-topic>/
├── README.md     # theory, architecture, failures, and exercises
├── lab.py        # reusable credential-free implementation
└── *.ipynb       # guided execution and reflection
```

See the [course map](COURSE_MAP.md), [learning guide](LEARNING.md),
[course-by-course review plan](COURSE_REVIEW_PLAN.md), and [roadmap](ROADMAP.md)
for the full progression.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[contributor]'
make test-python
```

Launch the Learning Hub:

```bash
cd app
npm ci
npm run dev
```

Labs use synthetic data and avoid live side effects by default. Provider or
platform integrations must be explicitly optional and reuse the same
validation, authorization, and audit boundaries.

## Core references

- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/latest)
- [Official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OAuth 2.0 Security Best Current Practice (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [SLSA supply-chain levels](https://slsa.dev/)

## Contributing and license

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request. This repository is licensed under the [MIT License](LICENSE).
