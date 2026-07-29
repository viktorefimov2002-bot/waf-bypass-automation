from __future__ import annotations

from typing import Any


PRIMITIVE_MESSAGES: dict[str, str] = {
    "xss_event_handler": "XSS event-handler attribute detected in an HTML tag",
    "xss_fragmented_event_handler": "XSS event-handler name fragmented with embedded markup",
    "xss_javascript_scheme": "XSS JavaScript URI scheme detected",
    "xss_javascript_href": "XSS JavaScript URI used in an anchor href attribute",
    "xss_scriptable_tag": "XSS script-capable HTML or SVG tag detected",
    "xss_namespaced_script": "XSS namespaced script tag detected",
    "xss_bidi_script_tag": "XSS script tag obfuscated with bidirectional Unicode control characters",
    "xss_execution_sink": "XSS JavaScript execution function or dynamic import detected",
    "xss_call_apply": "XSS execution through JavaScript call or apply detected",
    "xss_array_callback": "XSS execution function used as an array callback",
    "xss_function_tag": "XSS tagged-template execution through Function or constructor",
    "xss_bracket_execution": "XSS computed JavaScript function call through a global object",
    "xss_location_assignment": "XSS browser location assignment detected",
    "xss_css_javascript_url": "XSS JavaScript URI embedded in a CSS URL value",
    "xss_concatenated_sink": "XSS execution function assembled through string concatenation",
    "xss_whitespace_sink": "XSS execution function obfuscated with inserted whitespace",
    "xss_parenthesized_sink": "XSS execution function invoked through a parenthesized reference",
    "xss_tagged_call": "XSS call or apply invocation used as a tagged template",
    "xss_computed_window_call": "XSS computed function invocation through window, self, or top",
    "xss_constructor_chain": "XSS dynamic execution through a constructor chain",
    "sqli_zero_width_union_select": "SQL injection UNION SELECT obfuscated with zero-width characters",
    "sqli_quoted_fragment_union_select": "SQL injection UNION SELECT split across quoted fragments",
    "sqli_split_keyword_tokens": "SQL injection keywords split across string tokens",
    "sqli_fragmented_union_select": "SQL injection UNION SELECT fragmented with escaped quotes",
    "sqli_union_select": "SQL injection UNION SELECT sequence detected",
    "sqli_union_select_comments": "SQL injection UNION SELECT obfuscated with SQL comments",
    "sqli_select_from": "SQL injection SELECT FROM sequence detected",
    "sqli_boolean": "Boolean-based SQL injection expression detected",
    "sqli_time_function": "Time-based SQL injection function detected",
    "jndi_lookup": "JNDI lookup expression associated with command execution",
    "command_separator": "Operating-system command following a shell separator",
    "command_substitution": "Shell command substitution expression detected",
    "command_obfuscated_cat": "Obfuscated shell command accessing a sensitive local file",
    "command_parameter_chain": "Command parameter chained to an operating-system command",
    "command_backslash_split_cat": "Shell cat command obfuscated with backslash-separated characters",
    "path_traversal": "Local file inclusion path traversal sequence detected",
    "sensitive_local_file": "Reference to a sensitive local system file detected",
    "windows_sensitive_file": "Reference to a sensitive Windows system file detected",
    "php_wrapper": "Remote file inclusion through a PHP stream wrapper",
    "data_wrapper": "Remote file inclusion through a data URI wrapper",
    "remote_include_url": "Remote script file inclusion URL detected",
    "internal_url": "SSRF request targeting a local or private network address",
    "non_http_scheme": "SSRF request using a non-HTTP protocol scheme",
    "remote_non_http_scheme": "SSRF request using a remote non-HTTP service scheme",
    "obfuscated_file_uri": "SSRF or local-file access through an obfuscated file URI",
    "nosql_operator": "NoSQL injection operator detected",
    "nosql_javascript_predicate": "NoSQL JavaScript predicate injection detected",
    "nosql_return_predicate": "NoSQL injected return predicate detected",
    "nosql_duplicate_roles": "NoSQL object with duplicate security-sensitive role fields",
    "ldap_filter_injection": "LDAP filter injection expression detected",
    "xpath_boolean_injection": "XPath boolean injection expression detected",
    "template_expression": "Server-side template injection expression detected",
    "smarty_expression": "Smarty template expression injection detected",
    "spel_expression": "Spring Expression Language injection detected",
    "thymeleaf_expression": "Thymeleaf expression injection detected",
    "at_expression": "Template expression using function-style at syntax",
    "ssi_directive": "Server-side include directive injection detected",
    "redirect_parameter": "Open redirect URL supplied through a redirect parameter",
    "redirect_scheme_relative": "Open redirect using a scheme-relative URL",
    "redirect_userinfo": "Open redirect using URL user-info confusion",
    "redirect_at_host": "Open redirect using an at-prefixed host",
    "redirect_ipv6_literal": "Open redirect using an IPv6 address literal",
    "redirect_crlf_location": "Open redirect combined with CRLF Location-header injection",
    "graphql_introspection": "GraphQL introspection query detected",
    "exposed_vcs": "Request for exposed version-control metadata",
    "backup_archive": "Request for an exposed backup or database archive",
    "webshell_php_path": "Request targeting a common PHP web-shell path",
}


def primitive_message(primitive: str, family: str) -> str:
    message = PRIMITIVE_MESSAGES.get(primitive)
    if message:
        return message
    readable = primitive.replace("_", " ").strip()
    return f"{family.upper()} pattern detected: {readable}"


def render_rule(rule: dict[str, Any]) -> str:
    phase = int(rule.get("phase") or 2)
    family = str(rule.get("family") or "generic").lower()
    primitive = str(rule.get("primitive") or "unknown_pattern")
    message = primitive_message(primitive, family)
    actions = [
        f"id:{rule['rule_id']}",
        f"phase:{phase}",
        "deny",
        *rule["transforms"],
        f"msg:'{message}'",
        "tag:'waf-bypass-candidate'",
        f"tag:'{family}'",
        f"tag:'primitive/{primitive}'",
        "severity:'CRITICAL'",
        "setvar:tx.anomaly_score=+5",
    ]
    action_lines = ",\\\n    ".join(actions)
    warning = ""
    if rule.get("generic_header_target"):
        warning = (
            "# HIGH-RISK TARGET: REQUEST_HEADERS scans all request-header values. "
            "This may increase false positives and per-request CPU cost; benchmark and tune before production.\n"
        )
    return (
        f"# Covers {rule['coverage_count']} confirmed bypass variant(s); phase={phase}; "
        f"targets={','.join(rule['targets'])}; encodings={','.join(rule['encodings'])}.\n"
        + warning
        + "# REVIEW REQUIRED: validate converter compatibility, coverage and false positives before production.\n"
        + f"SecRule {rule['target']} \"@rx {rule['pattern']}\" \\\n"
        + f"    \"{action_lines}\"\n"
    )


def apply_rule_metadata(rules_module: Any) -> None:
    rules_module._render_rule = render_rule
