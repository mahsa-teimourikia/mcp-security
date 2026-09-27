"""Executable security claims for Course 06's OAuth resource-server boundary."""

import asyncio
import importlib.util
import json
from pathlib import Path
import sys

import jwt
import pytest


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/intermediate/06-mcp-authentication-oauth-security/lab.py"
SPEC = importlib.util.spec_from_file_location("course_06_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def run(coroutine):
    return asyncio.run(coroutine)


@pytest.fixture
def environment():
    return lab.build_environment()


def rejection_reason(environment, token):
    assert run(environment.verifier.verify_token(token)) is None
    return environment.verifier.events[-1].reason


def test_end_to_end_scenario_proves_http_authentication_and_tool_authorization():
    evidence = run(lab.run_scenario())
    assert evidence["missing_token_status"] == 401
    assert evidence["wrong_audience_status"] == 401
    assert evidence["valid_call_is_error"] is False
    assert evidence["cross_tenant_is_error"] is True
    assert evidence["revoked_status"] == 401
    assert evidence["raw_token_in_evidence"] is False


def test_protected_resource_metadata_supports_authorization_server_discovery(environment):
    metadata = run(lab.protected_resource_metadata(environment))
    assert metadata == {
        "resource": lab.RESOURCE,
        "authorization_servers": [lab.ISSUER],
        "scopes_supported": [lab.GLOBAL_SCOPE],
        "bearer_methods_supported": ["header"],
    }


def test_missing_token_is_401_with_discovery_challenge_before_handler(environment):
    response = run(lab.request_boundary(environment, token=None))
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"
    assert 'resource_metadata="https://support.example/.well-known/oauth-protected-resource/mcp"' in response.headers[
        "www-authenticate"
    ]
    assert environment.runtime.handler_calls == 0


def test_token_in_uri_is_never_accepted(environment):
    token = environment.authorization_server.issue()
    response = run(lab.request_boundary(environment, token=None, path=f"/mcp?access_token={token}"))
    assert response.status_code == 401
    assert environment.verifier.events == []


def test_valid_signature_wrong_global_scope_is_403_before_handler(environment):
    token = environment.authorization_server.issue(scopes=(lab.READ_SCOPE,))
    response = run(lab.request_boundary(environment, token=token))
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"
    assert "mcp:access" in response.headers["www-authenticate"]
    assert environment.runtime.handler_calls == 0


@pytest.mark.parametrize(
    ("token_kwargs", "reason"),
    [
        ({"issuer": "https://attacker.example/"}, "issuer_mismatch"),
        ({"audience": "https://inventory.example/api"}, "audience_mismatch"),
        ({"lifetime_seconds": -30, "issued_at_offset": -60}, "expired"),
        ({"not_before_offset": 30}, "not_yet_valid"),
        ({"token_type": "JWT"}, "wrong_token_type"),
        ({"lifetime_seconds": 600}, "lifetime_too_long"),
        ({"tenant_id": "../../admin"}, "invalid_tenant"),
        ({"scopes": (lab.GLOBAL_SCOPE, lab.GLOBAL_SCOPE)}, "invalid_scope"),
    ],
)
def test_claim_and_header_failures_are_closed(environment, token_kwargs, reason):
    token = environment.authorization_server.issue(**token_kwargs)
    assert rejection_reason(environment, token) == reason


def test_missing_required_claim_is_denied(environment):
    token = environment.authorization_server.issue(omit_claims=frozenset({"tenant_id"}))
    assert rejection_reason(environment, token) == "missing_tenant_id"


def test_signature_from_untrusted_key_is_denied_even_when_kid_matches(environment):
    attacker = lab.EphemeralAuthorizationServer()
    token = attacker.issue()
    assert rejection_reason(environment, token) == "invalid_signature"


def test_unknown_kid_is_denied(environment):
    attacker = lab.EphemeralAuthorizationServer()
    attacker.rotate("attacker-key")
    token = attacker.issue(kid="attacker-key")
    assert rejection_reason(environment, token) == "unknown_kid"


def test_algorithm_confusion_is_denied_before_key_use(environment):
    now = __import__("time").time()
    token = jwt.encode(
        {
            "iss": lab.ISSUER,
            "sub": "analyst-42",
            "aud": lab.RESOURCE,
            "exp": int(now) + 60,
            "nbf": int(now),
            "iat": int(now),
            "jti": "hs-attack",
            "client_id": "support-copilot",
            "scope": lab.GLOBAL_SCOPE,
            "tenant_id": "acme",
        },
        b"attacker-controlled-secret-at-least-32-bytes",
        algorithm="HS256",
        headers={"kid": "key-1", "typ": "at+jwt"},
    )
    assert rejection_reason(environment, token) == "algorithm_not_allowed"


def test_rotation_overlap_accepts_old_and_new_keys_then_retirement_denies_old(environment):
    issuer = environment.authorization_server
    old_token = issuer.issue(token_id="old")
    issuer.rotate("key-2")
    new_token = issuer.issue(token_id="new")
    assert run(environment.verifier.verify_token(old_token)) is not None
    assert run(environment.verifier.verify_token(new_token)) is not None
    issuer.retire("key-1")
    assert rejection_reason(environment, old_token) == "unknown_kid"


def test_revocation_is_checked_after_cryptographic_validation(environment):
    token = environment.authorization_server.issue(token_id="incident-7")
    assert run(environment.verifier.verify_token(token)) is not None
    environment.verifier.revoked_jtis.add("incident-7")
    assert rejection_reason(environment, token) == "revoked"


def test_valid_http_client_reaches_tool_with_validated_identity(environment):
    token = environment.authorization_server.issue()

    async def scenario():
        async with environment.app.router.lifespan_context(environment.app):
            return await lab.call_ticket(environment, token, "acme-100")

    result = run(scenario())
    assert result.is_error is False
    assert json.loads(result.content[0].text) == {
        "ticket_id": "acme-100",
        "title": "Invoice retry",
        "status": "open",
    }
    event = environment.runtime.authorization_events[-1]
    assert event.subject == "analyst-42"
    assert event.tenant_id == "acme"
    assert event.decision == "allow"


def test_tool_scope_is_distinct_from_global_transport_scope(environment):
    token = environment.authorization_server.issue(scopes=(lab.GLOBAL_SCOPE,))

    async def scenario():
        async with environment.app.router.lifespan_context(environment.app):
            return await lab.call_ticket(environment, token, "acme-100")

    result = run(scenario())
    assert result.is_error is True
    assert "not authorized" in result.content[0].text
    assert environment.runtime.handler_calls == 1
    assert environment.runtime.authorization_events[-1].reason == "missing_ticket_read_scope"


def test_cross_tenant_and_missing_ticket_have_same_external_failure(environment):
    token = environment.authorization_server.issue()

    async def scenario():
        async with environment.app.router.lifespan_context(environment.app):
            cross_tenant = await lab.call_ticket(environment, token, "globex-200")
            missing = await lab.call_ticket(environment, token, "acme-999")
            return cross_tenant, missing

    cross_tenant, missing = run(scenario())
    assert cross_tenant.is_error and missing.is_error
    assert cross_tenant.content[0].text == missing.content[0].text
    assert "unavailable" in cross_tenant.content[0].text


def test_bearer_token_is_replayable_until_expiry_or_revocation(environment):
    token = environment.authorization_server.issue()

    async def scenario():
        async with environment.app.router.lifespan_context(environment.app):
            first = await lab.call_ticket(environment, token, "acme-100")
            second = await lab.call_ticket(environment, token, "acme-100")
            return first, second

    first, second = run(scenario())
    assert first.is_error is False and second.is_error is False
    assert environment.runtime.handler_calls == 2


def test_audit_and_protocol_results_never_contain_raw_bearer_token(environment):
    token = environment.authorization_server.issue()

    async def scenario():
        async with environment.app.router.lifespan_context(environment.app):
            return await lab.call_ticket(environment, token, "acme-100")

    result = run(scenario())
    serialized = json.dumps(
        {
            "validation": [event.__dict__ for event in environment.verifier.events],
            "authorization": [event.__dict__ for event in environment.runtime.authorization_events],
            "result": result.model_dump(mode="json"),
        }
    )
    assert token not in serialized
    assert environment.verifier.fingerprint(token) in serialized
