"""Executable filesystem, SSRF, redirect, and egress invariants for Course 10."""

import asyncio
import importlib.util
import json
from hashlib import sha256
from pathlib import Path
import sys

from mcp import Client
import pytest
from pydantic import ValidationError


ROOT = Path(__file__).parents[1]
LAB_PATH = ROOT / "curriculum/intermediate/10-filesystem-network-ssrf-egress-security/lab.py"
SPEC = importlib.util.spec_from_file_location("course_10_lab", LAB_PATH)
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def run(coroutine):
    return asyncio.run(coroutine)


@pytest.fixture
def environment():
    value = lab.default_environment()
    try:
        yield value
    finally:
        value.close()


def request(path="/v1/tickets/acme-100", *, request_id="net-test-1"):
    return lab.EgressRequest(
        request_id=request_id,
        destination_id="dest-tickets-api",
        path=path,
    )


def assert_denied(call, code):
    with pytest.raises((lab.EgressDenied, lab.FileDenied)) as denied:
        call()
    assert denied.value.code == code


def test_end_to_end_scenario_blocks_forbidden_effects():
    evidence = run(lab.run_scenario())
    assert evidence["file_read_allowed"] is True
    assert evidence["ticket_lookup_allowed"] is True
    assert evidence["symlink_escape_denied"] is True
    assert evidence["cross_tenant_denied"] is True
    assert evidence["dns_rebinding_reason"] == "NON_GLOBAL_ADDRESS"
    assert evidence["metadata_redirect_reason"] == "SCHEME_NOT_ALLOWED"
    assert evidence["forbidden_effects_observed"] == 0


def test_registered_file_is_read_by_descriptor_and_digest(environment):
    result = environment.file_store.read(environment.identity, "file-support-policy")
    assert result["text"] == "Support exports require approval.\n"
    assert result["sha256"] == sha256(result["text"].encode()).hexdigest()
    assert environment.file_store.events[-1].reason_code == "FILE_READ_ALLOWED"


@pytest.mark.parametrize(
    "file_id,code",
    [
        ("file-unknown", "FILE_NOT_REGISTERED"),
        ("file-other-tenant", "TENANT_MISMATCH"),
        ("file-symlink-escape", "PATH_OR_SYMLINK_DENIED"),
    ],
)
def test_file_registry_and_symlink_controls_fail_closed(environment, file_id, code):
    assert_denied(lambda: environment.file_store.read(environment.identity, file_id), code)
    assert environment.file_store.events[-1].reason_code == code


@pytest.mark.parametrize("relative_path", ["../secret", "/etc/passwd", ".", "a\\b", "a/../b"])
def test_file_path_grammar_rejects_ambiguous_authority(tmp_path, relative_path):
    root = tmp_path / "root"
    root.mkdir()
    record = lab.FileRecord(
        file_id="file-path-test",
        tenant_id="acme",
        root_id="root-test",
        relative_path=relative_path,
        expected_sha256=sha256(b"x").hexdigest(),
    )
    store = lab.DescriptorFileStore({"root-test": root}, (record,))
    identity = lab.IdentityContext(subject="analyst-42", tenant_id="acme")
    assert_denied(lambda: store.read(identity, record.file_id), "PATH_INVALID")


def test_intermediate_symlink_cannot_escape_root(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (root / "link").symlink_to(outside, target_is_directory=True)
    record = lab.FileRecord(
        file_id="file-link-test",
        tenant_id="acme",
        root_id="root-test",
        relative_path="link/secret.txt",
        expected_sha256=sha256(b"secret").hexdigest(),
    )
    store = lab.DescriptorFileStore({"root-test": root}, (record,))
    identity = lab.IdentityContext(subject="analyst-42", tenant_id="acme")
    assert_denied(lambda: store.read(identity, record.file_id), "PATH_OR_SYMLINK_DENIED")


def test_file_size_and_catalog_digest_are_enforced(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "large.txt").write_bytes(b"12345")
    identity = lab.IdentityContext(subject="analyst-42", tenant_id="acme")
    too_large = lab.FileRecord(
        file_id="file-large-test",
        tenant_id="acme",
        root_id="root-test",
        relative_path="large.txt",
        expected_sha256=sha256(b"12345").hexdigest(),
        max_bytes=4,
    )
    stale = too_large.model_copy(
        update={"file_id": "file-stale-test", "max_bytes": 10, "expected_sha256": "0" * 64}
    )
    store = lab.DescriptorFileStore({"root-test": root}, (too_large, stale))
    assert_denied(lambda: store.read(identity, too_large.file_id), "FILE_SIZE_LIMIT_EXCEEDED")
    assert_denied(lambda: store.read(identity, stale.file_id), "CONTENT_DIGEST_MISMATCH")


def test_non_regular_file_and_missing_root_are_denied(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "directory").mkdir()
    identity = lab.IdentityContext(subject="analyst-42", tenant_id="acme")
    directory = lab.FileRecord(
        file_id="file-directory-test",
        tenant_id="acme",
        root_id="root-test",
        relative_path="directory",
        expected_sha256=sha256(b"").hexdigest(),
    )
    missing = directory.model_copy(
        update={"file_id": "file-root-test", "root_id": "root-missing"}
    )
    store = lab.DescriptorFileStore({"root-test": root}, (directory, missing))
    assert_denied(lambda: store.read(identity, directory.file_id), "NOT_REGULAR_FILE")
    assert_denied(lambda: store.read(identity, missing.file_id), "ROOT_NOT_AVAILABLE")


def test_file_events_do_not_contain_content_or_outside_secret(environment):
    environment.file_store.read(environment.identity, "file-support-policy")
    assert_denied(
        lambda: environment.file_store.read(environment.identity, "file-symlink-escape"),
        "PATH_OR_SYMLINK_DENIED",
    )
    serialized = json.dumps([event.__dict__ for event in environment.file_store.events])
    assert "Support exports" not in serialized
    assert "cloud-token" not in serialized


def test_exact_https_destination_resolves_all_answers_and_pins_connect_ip(environment):
    result = environment.egress.fetch_json(request())
    assert result["ticket_id"] == "acme-100"
    assert environment.resolver.calls[lab.TICKET_HOST] == 1
    call = environment.transport.calls[-1]
    assert call.connect_ip == lab.PUBLIC_TICKET_IP
    assert call.tls_server_name == lab.TICKET_HOST


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.4",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:169.254.169.254",
    ],
)
def test_non_global_dns_answers_are_rejected(address):
    resolver = lab.ScriptedResolver({lab.TICKET_HOST: ((address,),)})
    gate = lab.URLGate(resolver)
    policy = lab.DestinationPolicy(
        destination_id="dest-tickets-api", host=lab.TICKET_HOST, path_prefix="/v1/tickets/"
    )
    assert_denied(
        lambda: gate.approve(
            lab.canonical_ticket_url("acme-100"), policy, request_id="net-address-1", hop=0
        ),
        "NON_GLOBAL_ADDRESS",
    )
    assert gate.events[-1].decision == "deny"


def test_mixed_public_and_private_dns_answer_rejects_entire_set():
    resolver = lab.ScriptedResolver(
        {lab.TICKET_HOST: ((lab.PUBLIC_TICKET_IP, lab.METADATA_IP),)}
    )
    gate = lab.URLGate(resolver)
    policy = lab.DestinationPolicy(
        destination_id="dest-tickets-api", host=lab.TICKET_HOST, path_prefix="/v1/tickets/"
    )
    assert_denied(
        lambda: gate.approve(
            lab.canonical_ticket_url("acme-100"), policy, request_id="net-mixed-1", hop=0
        ),
        "NON_GLOBAL_ADDRESS",
    )


@pytest.mark.parametrize(
    "url,code",
    [
        ("http://tickets.example.com/v1/tickets/acme-100", "SCHEME_NOT_ALLOWED"),
        ("https://evil.example/v1/tickets/acme-100", "HOST_NOT_ALLOWED"),
        ("https://tickets.example.com.:443/v1/tickets/acme-100", "HOST_SYNTAX_INVALID"),
        ("https://user@tickets.example.com/v1/tickets/acme-100", "USERINFO_OR_ENCODED_AUTHORITY_DENIED"),
        ("https://tickets%2eexample.com/v1/tickets/acme-100", "USERINFO_OR_ENCODED_AUTHORITY_DENIED"),
        ("https://tickets.example.com:444/v1/tickets/acme-100", "PORT_NOT_ALLOWED"),
        ("https://tickets.example.com/v1/admin", "PATH_NOT_ALLOWED"),
        ("https://tickets.example.com/v1/tickets/%2e%2e/admin", "PATH_AMBIGUOUS"),
        ("https://tickets.example.com/v1/tickets/%252e%252e/admin", "PATH_AMBIGUOUS"),
        ("https://tickets.example.com/v1/tickets/a#fragment", "URL_SYNTAX_INVALID"),
        ("https://tickets.example.com/v1/tickets/a\\@evil", "URL_SYNTAX_INVALID"),
    ],
)
def test_url_parser_boundary_rejects_ambiguous_or_unapproved_targets(environment, url, code):
    assert_denied(
        lambda: environment.gate.approve(
            url, environment.destination, request_id="net-url-1", hop=0
        ),
        code,
    )


@pytest.mark.parametrize(
    "answers,code",
    [
        ((), "DNS_NO_ANSWER"),
        ((("not-an-ip",),), "DNS_ANSWER_INVALID"),
        ((tuple("1.1.1.%d" % i for i in range(1, 10)),), "DNS_ANSWER_COUNT_INVALID"),
    ],
)
def test_dns_answer_shape_fails_closed(answers, code):
    resolver = lab.ScriptedResolver({lab.TICKET_HOST: answers})
    gate = lab.URLGate(resolver)
    policy = lab.DestinationPolicy(
        destination_id="dest-tickets-api", host=lab.TICKET_HOST, path_prefix="/v1/tickets/"
    )
    assert_denied(
        lambda: gate.approve(
            lab.canonical_ticket_url("acme-100"), policy, request_id="net-dns-1", hop=0
        ),
        code,
    )
    assert gate.events[-1].reason_code == code


def test_dns_rebinding_on_redirect_is_rechecked_and_denied():
    resolver = lab.ScriptedResolver(
        {lab.TICKET_HOST: ((lab.PUBLIC_TICKET_IP,), (lab.METADATA_IP,))}
    )
    gate = lab.URLGate(resolver)
    policy = lab.DestinationPolicy(
        destination_id="dest-tickets-api", host=lab.TICKET_HOST, path_prefix="/v1/tickets/"
    )
    transport = lab.ScriptedTransport()
    first_url = lab.canonical_ticket_url("acme-start")
    transport.add(
        connect_ip=lab.PUBLIC_TICKET_IP,
        method="GET",
        url=first_url,
        result=lab.FakeResponse(status=302, headers={"Location": "/v1/tickets/acme-next"}),
    )
    client = lab.EgressClient(
        (policy,), gate, transport, lab.CredentialBroker({"tickets-api": "secret"})
    )
    assert_denied(
        lambda: client.fetch_json(request("/v1/tickets/acme-start")),
        "NON_GLOBAL_ADDRESS",
    )
    assert len(transport.calls) == 1


def test_redirect_cycle_is_detected(environment):
    environment.transport.routes.clear()
    environment.transport.add(
        connect_ip=lab.PUBLIC_TICKET_IP,
        method="GET",
        url=lab.canonical_ticket_url("acme-100"),
        result=lab.FakeResponse(302, {"Location": "/v1/tickets/acme-100"}),
    )
    assert_denied(lambda: environment.egress.fetch_json(request()), "REDIRECT_CYCLE")


def test_redirect_limit_is_enforced_before_third_request():
    resolver = lab.ScriptedResolver({lab.TICKET_HOST: ((lab.PUBLIC_TICKET_IP,),)})
    gate = lab.URLGate(resolver)
    policy = lab.DestinationPolicy(
        destination_id="dest-tickets-api",
        host=lab.TICKET_HOST,
        path_prefix="/v1/tickets/",
        max_redirects=1,
    )
    transport = lab.ScriptedTransport()
    for source, target in (("acme-one", "acme-two"), ("acme-two", "acme-three")):
        transport.add(
            connect_ip=lab.PUBLIC_TICKET_IP,
            method="GET",
            url=lab.canonical_ticket_url(source),
            result=lab.FakeResponse(302, {"Location": f"/v1/tickets/{target}"}),
        )
    client = lab.EgressClient(
        (policy,), gate, transport, lab.CredentialBroker({"tickets-api": "secret"})
    )
    assert_denied(
        lambda: client.fetch_json(request("/v1/tickets/acme-one")),
        "REDIRECT_LIMIT_EXCEEDED",
    )
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    "response,code",
    [
        (lab.FakeResponse(302, {}), "REDIRECT_LOCATION_MISSING"),
        (lab.FakeResponse(500, {"Content-Type": "application/json"}), "UPSTREAM_STATUS_DENIED"),
        (lab.FakeResponse(200, {"Content-Type": "text/html"}, (b"{}",)), "CONTENT_TYPE_DENIED"),
        (lab.FakeResponse(200, {"Content-Type": "application/json", "Content-Length": "x"}, (b"{}",)), "CONTENT_LENGTH_INVALID"),
        (lab.FakeResponse(200, {"Content-Type": "application/json", "Content-Length": "999999"}, (b"{}",)), "RESPONSE_TOO_LARGE"),
        (lab.FakeResponse(200, {"Content-Type": "application/json"}, (b"not-json",)), "RESPONSE_JSON_INVALID"),
        (lab.FakeResponse(200, {"Content-Type": "application/json"}, (b"[]",)), "RESPONSE_SCHEMA_INVALID"),
    ],
)
def test_response_contract_fails_closed(environment, response, code):
    environment.transport.routes.clear()
    environment.transport.add(
        connect_ip=lab.PUBLIC_TICKET_IP,
        method="GET",
        url=lab.canonical_ticket_url("acme-100"),
        result=response,
    )
    assert_denied(lambda: environment.egress.fetch_json(request()), code)
    assert environment.egress.events[-1].reason_code == code


@pytest.mark.parametrize(
    "fault,code",
    [
        (lab.TransportTimeout("slow"), "UPSTREAM_TIMEOUT"),
        (ConnectionError("down"), "UPSTREAM_CONNECTION_FAILED"),
    ],
)
def test_transport_failures_are_generic_policy_denials(environment, fault, code):
    environment.transport.routes.clear()
    environment.transport.add(
        connect_ip=lab.PUBLIC_TICKET_IP,
        method="GET",
        url=lab.canonical_ticket_url("acme-100"),
        result=fault,
    )
    assert_denied(lambda: environment.egress.fetch_json(request()), code)


def test_chunked_body_cap_is_enforced_without_content_length(environment):
    environment.transport.routes.clear()
    environment.transport.add(
        connect_ip=lab.PUBLIC_TICKET_IP,
        method="GET",
        url=lab.canonical_ticket_url("acme-100"),
        result=lab.FakeResponse(
            200,
            {"Content-Type": "application/json"},
            (b"x" * 3000, b"x" * 3000),
        ),
    )
    assert_denied(lambda: environment.egress.fetch_json(request()), "RESPONSE_TOO_LARGE")


def test_credential_is_destination_bound_and_redacted(environment):
    environment.egress.fetch_json(request())
    serialized = lab.serialized_events(environment)
    assert environment.raw_token not in serialized
    assert "Authorization" in environment.transport.calls[-1].header_names
    assert environment.transport.calls[-1].authorization_fingerprint is not None


def test_query_value_is_not_recorded_in_gate_event(environment):
    environment.gate.approve(
        lab.canonical_ticket_url("acme-100") + "?token=query-secret",
        environment.destination,
        request_id="net-query-1",
        hop=0,
    )
    serialized = json.dumps(environment.gate.events[-1].__dict__)
    assert "query-secret" not in serialized
    assert environment.gate.events[-1].query_present is True


def test_destination_and_method_are_server_policy(environment):
    unknown = lab.EgressRequest(
        request_id="net-destination-1",
        destination_id="dest-unknown-api",
        path="/v1/tickets/acme-100",
    )
    head = request(request_id="net-method-1").model_copy(update={"method": "HEAD"})
    assert_denied(lambda: environment.egress.fetch_json(unknown), "DESTINATION_NOT_REGISTERED")
    assert_denied(lambda: environment.egress.fetch_json(head), "METHOD_NOT_ALLOWED")


def test_credential_broker_refuses_missing_audience(environment):
    approved = environment.gate.approve(
        lab.canonical_ticket_url("acme-100"),
        environment.destination,
        request_id="net-credential-1",
        hop=0,
    )
    broker = lab.CredentialBroker({})
    assert_denied(
        lambda: broker.headers_for(environment.destination, approved),
        "CREDENTIAL_UNAVAILABLE",
    )


def test_service_binds_response_to_requested_ticket_and_tenant(environment):
    environment.transport.routes.clear()
    environment.transport.add(
        connect_ip=lab.PUBLIC_TICKET_IP,
        method="GET",
        url=lab.canonical_ticket_url("acme-100"),
        result=lab.json_response(
            {"ticket_id": "acme-999", "tenant_id": "acme", "title": "Wrong ticket"}
        ),
    )
    assert_denied(lambda: environment.service.lookup_ticket("acme-100"), "RESPONSE_BINDING_INVALID")


def test_request_models_reject_caller_selected_authority():
    with pytest.raises(ValidationError):
        lab.EgressRequest(
            request_id="net-extra-1",
            destination_id="dest-tickets-api",
            path="/v1/tickets/acme-100",
            url="https://evil.example",
        )


def test_mcp_tool_schemas_expose_opaque_ids_not_paths_urls_or_headers(environment):
    server = lab.build_mcp_server(environment.service)

    async def inspect():
        async with Client(server) as client:
            return await client.list_tools()

    tools = run(inspect()).tools
    assert {tool.name for tool in tools} == {"workspace.read", "ticket.lookup"}
    schemas = json.dumps([tool.input_schema for tool in tools]).lower()
    assert "file_id" in schemas
    assert "ticket_id" in schemas
    for forbidden in ("url", "path", "host", "headers", "authorization", "tenant_id"):
        assert forbidden not in schemas


def test_mcp_denials_are_generic_while_protected_events_keep_reason(environment):
    server = lab.build_mcp_server(environment.service)

    async def invoke():
        async with Client(server, raise_exceptions=False) as client:
            return await client.call_tool("workspace.read", {"file_id": "file-symlink-escape"})

    result = run(invoke())
    assert result.is_error is True
    assert "file is unavailable" in result.content[0].text
    assert "PATH_OR_SYMLINK_DENIED" not in result.content[0].text
    assert environment.file_store.events[-1].reason_code == "PATH_OR_SYMLINK_DENIED"
