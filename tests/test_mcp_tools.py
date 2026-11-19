from app.adapters.local.mock_tools import build_default_registry

_EXPECTED = {
    "disable_credential",
    "block_ip",
    "revoke_sessions",
    "isolate_host",
    "create_ticket",
    "notify",
}


def test_registry_has_expected_tools():
    registry = build_default_registry()
    assert _EXPECTED <= set(registry.names())


def test_destructive_flags():
    registry = build_default_registry()
    assert registry.get("block_ip").destructive is True
    assert registry.get("revoke_sessions").destructive is True
    assert registry.get("create_ticket").destructive is False
    assert registry.get("notify").destructive is False


def test_tool_run_is_simulated():
    registry = build_default_registry()
    out = registry.get("block_ip").run({"ip": "1.2.3.4", "duration_hours": "24"})
    assert out["status"] == "simulated"
    assert out["action"] == "block_ip"
    assert out["args"]["ip"] == "1.2.3.4"


def test_schemas_are_json_schema_objects():
    registry = build_default_registry()
    for schema in registry.schemas():
        assert schema["parameters"]["type"] == "object"
        assert "properties" in schema["parameters"]
        assert "destructive" in schema
