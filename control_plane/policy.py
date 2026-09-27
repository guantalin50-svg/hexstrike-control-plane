from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .models import Decision, PolicyEvaluation


TOOL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")


def normalize_target(value: str) -> str:
    candidate = value.strip()
    if not candidate:
        raise ValueError("target cannot be empty")

    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("only http and https target URLs are supported")
        if parsed.username or parsed.password:
            raise ValueError("credentials are not allowed in target URLs")
        candidate = parsed.hostname or ""

    candidate = candidate.strip().rstrip(".").lower()
    if not candidate:
        raise ValueError("target does not contain a hostname or address")

    try:
        return str(ipaddress.ip_network(candidate, strict=False))
    except ValueError:
        pass

    if ":" in candidate:
        host, separator, port = candidate.rpartition(":")
        if separator and port.isdigit() and host:
            candidate = host

    labels = candidate.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("target hostname is malformed")
    hostname_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not hostname_re.fullmatch(label) for label in labels):
        raise ValueError("target hostname contains unsupported characters")
    return candidate


def _target_matches(target: str, pattern: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    try:
        target_net = ipaddress.ip_network(target, strict=False)
        pattern_net = ipaddress.ip_network(pattern, strict=False)
        return target_net.subnet_of(pattern_net)
    except ValueError:
        return fnmatch.fnmatchcase(target, pattern)


@dataclass
class PolicyEngine:
    policy: dict[str, Any]

    def evaluate(
        self,
        tool: str,
        target: str,
        arguments: dict[str, Any] | None = None,
    ) -> PolicyEvaluation:
        tool = tool.strip().lower().replace("_", "-")
        if not TOOL_RE.fullmatch(tool):
            return PolicyEvaluation(
                decision=Decision.DENY,
                normalized_target=target.strip(),
                risk="unknown",
                reasons=["tool name is malformed"],
            )

        try:
            normalized_target = normalize_target(target)
        except ValueError as exc:
            return PolicyEvaluation(
                decision=Decision.DENY,
                normalized_target=target.strip(),
                risk="unknown",
                reasons=[str(exc)],
            )

        targets = self.policy.get("targets", {})
        deny_patterns = targets.get("deny", [])
        allow_patterns = targets.get("allow", [])

        if any(_target_matches(normalized_target, pattern) for pattern in deny_patterns):
            return PolicyEvaluation(
                decision=Decision.DENY,
                normalized_target=normalized_target,
                risk="blocked",
                reasons=["target matches an explicit deny rule"],
            )

        if not any(_target_matches(normalized_target, pattern) for pattern in allow_patterns):
            return PolicyEvaluation(
                decision=Decision.DENY,
                normalized_target=normalized_target,
                risk="out_of_scope",
                reasons=["target is not in the authorized allowlist"],
            )

        tools = self.policy.get("tools", {})
        denied = set(tools.get("deny", []))
        approval = set(tools.get("require_approval", []))
        automatic = set(tools.get("allow", []))

        if tool in denied:
            return PolicyEvaluation(
                decision=Decision.DENY,
                normalized_target=normalized_target,
                risk="prohibited",
                reasons=["tool is prohibited by policy"],
            )

        argument_error = self._validate_arguments(tool, arguments or {})
        if argument_error:
            return PolicyEvaluation(
                decision=Decision.DENY,
                normalized_target=normalized_target,
                risk="invalid_parameters",
                reasons=[argument_error],
            )
        if tool in approval:
            return PolicyEvaluation(
                decision=Decision.APPROVAL,
                normalized_target=normalized_target,
                risk="elevated",
                reasons=["authorized target", "tool requires human approval"],
            )
        if tool in automatic:
            return PolicyEvaluation(
                decision=Decision.ALLOW,
                normalized_target=normalized_target,
                risk="standard",
                reasons=["authorized target", "tool is allowed by policy"],
            )

        default = tools.get("default", "deny")
        if default == "require_approval":
            return PolicyEvaluation(
                decision=Decision.APPROVAL,
                normalized_target=normalized_target,
                risk="unknown",
                reasons=["authorized target", "unknown tool requires human approval"],
            )
        return PolicyEvaluation(
            decision=Decision.DENY,
            normalized_target=normalized_target,
            risk="unknown",
            reasons=["tool is not present in policy"],
        )

    def _validate_arguments(self, tool: str, arguments: dict[str, Any]) -> str | None:
        parameter_policy = self.policy.get("parameters", {})
        allowed_names = set(parameter_policy.get(tool, []))
        unknown = set(arguments).difference(allowed_names)
        if unknown:
            return f"unsupported arguments for {tool}: {', '.join(sorted(unknown))}"

        for name, value in arguments.items():
            if tool == "nmap" and name == "scan_type":
                if value not in {"-sT", "-sS", "-sV", "-sCV", "-sn"}:
                    return "nmap scan_type is not in the safe allowlist"
            elif tool == "nmap" and name == "ports":
                if not isinstance(value, str) or not re.fullmatch(r"[0-9,-]{1,200}", value):
                    return "nmap ports must contain only digits, commas, and ranges"
            elif name == "use_recovery":
                if not isinstance(value, bool):
                    return "use_recovery must be a boolean"
            elif tool == "nuclei" and name == "severity":
                if not isinstance(value, str) or not re.fullmatch(
                    r"(?:info|low|medium|high|critical)(?:,(?:info|low|medium|high|critical))*",
                    value,
                ):
                    return "nuclei severity contains an unsupported value"
            elif tool == "nuclei" and name == "tags":
                if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9,_-]{1,200}", value):
                    return "nuclei tags contain unsupported characters"
            else:
                return f"no validator is defined for {tool}.{name}"
        return None

