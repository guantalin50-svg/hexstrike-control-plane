from control_plane.models import Decision
from control_plane.policy import PolicyEngine, normalize_target


POLICY = {
    "targets": {
        "allow": ["*.test", "10.20.0.0/24", "safe.example.com"],
        "deny": ["blocked.test", "10.20.0.128/25"],
    },
    "tools": {
        "allow": ["nmap"],
        "require_approval": ["nikto"],
        "deny": ["hydra"],
        "default": "deny",
    },
    "parameters": {
        "nmap": ["scan_type", "ports", "use_recovery"],
        "nikto": [],
        "hydra": [],
    },
}


def test_normalizes_urls_and_ports():
    assert normalize_target("HTTPS://Safe.Example.com:443/path") == "safe.example.com"


def test_allows_known_tool_on_authorized_target():
    result = PolicyEngine(POLICY).evaluate("nmap", "api.test")
    assert result.decision is Decision.ALLOW


def test_requires_approval_for_elevated_tool():
    result = PolicyEngine(POLICY).evaluate("nikto", "10.20.0.20")
    assert result.decision is Decision.APPROVAL


def test_explicit_target_deny_wins_over_allow():
    result = PolicyEngine(POLICY).evaluate("nmap", "blocked.test")
    assert result.decision is Decision.DENY


def test_cidr_subset_deny_wins():
    result = PolicyEngine(POLICY).evaluate("nmap", "10.20.0.200")
    assert result.decision is Decision.DENY


def test_unknown_tool_fails_closed():
    result = PolicyEngine(POLICY).evaluate("unknown", "api.test")
    assert result.decision is Decision.DENY


def test_rejects_non_http_url_scheme():
    result = PolicyEngine(POLICY).evaluate("nmap", "file:///etc/passwd")
    assert result.decision is Decision.DENY


def test_rejects_shell_metacharacters_in_nmap_ports():
    result = PolicyEngine(POLICY).evaluate(
        "nmap",
        "api.test",
        {"ports": "443; curl attacker.invalid"},
    )
    assert result.decision is Decision.DENY
    assert result.risk == "invalid_parameters"


def test_rejects_unvalidated_argument_names():
    result = PolicyEngine(POLICY).evaluate(
        "nmap",
        "api.test",
        {"additional_args": "--script anything"},
    )
    assert result.decision is Decision.DENY

