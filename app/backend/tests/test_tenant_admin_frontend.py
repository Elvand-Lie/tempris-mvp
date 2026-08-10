from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_tenant_console_has_required_safe_administration_states():
    script = (ROOT / "frontend" / "extensions" / "tempris-modules.js").read_text(encoding="utf-8")
    required = [
        "Tenant &amp; Module Administration",
        "Administrative target only",
        "Selecting a tenant never changes your JWT",
        "/api/tenants?limit=100",
        "expected_version",
        "STALE_TENANT_CONFIGURATION",
        "Excluded'} by",
        "Reload selected tenant",
        "Unsaved entitlement changes",
        "Discard and switch",
        "Save then switch",
        "encodeURIComponent(tenantAdminState.selectedId)",
    ]
    for marker in required:
        assert marker in script
    tenant_section = script[script.index("function tenantAdminForm"):script.index("function safeHttpUrl")]
    assert "window.confirm" not in tenant_section
    assert "window.prompt" not in tenant_section


def test_tenant_console_has_responsive_and_selected_state_styles():
    styles = (ROOT / "frontend" / "extensions" / "tempris-modules.css").read_text(encoding="utf-8")
    for marker in [
        ".tmx-tenant-admin-layout",
        ".tmx-tenant-item.is-selected",
        ".tmx-dialog::backdrop",
        "@media (max-width: 1050px)",
    ]:
        assert marker in styles
