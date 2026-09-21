# Learning Guide

Use the repository as an executable security course, not only as a reading
list. Each topic follows one repeatable loop:

1. Read the topic `README.md` and identify the trust boundary being protected.
2. Predict the normal and adversarial outcomes before running anything.
3. Run the colocated `lab.py` without credentials or external side effects.
4. Execute the notebook and inspect the policy decisions and evidence.
5. Change one input to trigger the deliberate failure mode.
6. Add or strengthen a test that proves the security invariant.
7. Complete the checkpoint in the Learning Hub or full quiz.

## Course thesis

A learner should be able to explain MCP trust boundaries, implement
least-privilege controls, evaluate them with adversarial evidence, and
productionize them with governance, observability, revocation, and recovery.

## The central security boundary

```text
model or agent -> proposes, predicts, extracts, recommends
trusted application -> validates, authorizes, executes, verifies, records
```

Tool descriptions, prompts, resource contents, model output, typed objects,
and peer-agent messages are inputs. None of them grants authority.

## Local study

Create an environment and install the course with contributor tools:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[contributor]'
```

Run a lab directly or open its notebook:

```bash
python curriculum/beginner/01-mcp-architecture-lifecycle-trust-boundaries/lab.py
jupyter notebook curriculum/beginner/01-mcp-architecture-lifecycle-trust-boundaries/
```

Run the repository checks with `make test`. The web Learning Hub can be
started with `make dev` and opened at the local address printed by Vite.
