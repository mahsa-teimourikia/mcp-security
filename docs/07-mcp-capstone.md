# Capstone: secure a support MCP server

Scenario: a support agent can read tickets and draft replies for one tenant. It must never execute shell commands, fetch arbitrary URLs, cross tenant boundaries, or send an external message without approval.

## Release gates

1. Inventory tools, data, credentials, destinations, owner, and recovery owner.
2. Complete the [threat-model worksheet](08-threat-model-worksheet.md).
3. Run `python3 labs/capstone_secure_server.py` and record allowed and denied calls.
4. Generate an SBOM and scan dependencies with Syft/OSV-Scanner when installed.
5. Verify the artifact digest/signature and deploy in a rootless sandbox.
6. Run the adversarial fixtures in `tests/adversarial_cases.json`.
7. Demonstrate revocation and rollback using the [operator checklist](09-operator-checklist.md).

Success means every denied case is rejected before a side effect, every decision has a correlation ID, and the rollback path is documented and tested.
