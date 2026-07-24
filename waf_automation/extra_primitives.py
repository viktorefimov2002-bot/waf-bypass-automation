from __future__ import annotations

from typing import Final


EXTRA_SIGNATURES: Final[dict[str, list[tuple[str, str]]]] = {
    "sqli": [
        (
            "sqli_escaped_quoted_fragment_union_select",
            r"uni\x5c[\x22'][,]?\x5c[\x22']on\s+sel\x5c[\x22'][,]?\x5c[\x22']ect",
        ),
        (
            "sqli_fragmented_union_select",
            r"u(?:n|\x5c[\x22'][,]?\x5c[\x22']n)[\s\S]{0,24}ion[\s\S]{0,32}s(?:e|\x5c[\x22'][,]?\x5c[\x22']e)[\s\S]{0,24}lect",
        ),
    ],
    "command": [
        (
            "jndi_lookup",
            r"[$](?:\x5c)?[{][\s\S]{0,192}j[\s\S]{0,48}n[\s\S]{0,48}d[\s\S]{0,48}i[\s\S]{0,48}:",
        ),
        (
            "command_backslash_split_cat",
            r"(?:^|[;&|])[^\x0d\x0a]{0,96}c(?:\x5c[a-z0-9]?)*a(?:\x5c[a-z0-9]?)*t[^\x0d\x0a]{0,96}/e(?:\x5c[a-z0-9]?)*t(?:\x5c[a-z0-9]?)*c/passwd",
        ),
    ],
    "ssrf": [
        (
            "ssrf_template_file_path",
            r"\bfile\s*:(?:[$][{(][a-z_][a-z0-9_]*[})])*/?e(?:[$][{(][a-z_][a-z0-9_]*[})])?t(?:[$][{(][a-z_][a-z0-9_]*[})])?c/(?:pas(?:[$][{(][a-z_][a-z0-9_]*[})])?swd|shadow)",
        ),
        (
            "ssrf_suspicious_remote_script",
            r"\bhttps?://[^/\s]{1,255}/[^?\s]{0,128}(?:c99|r57|wso|shell)[^?\s]{0,64}[.]php(?:[?/#]|$)",
        ),
    ],
    "xss": [
        (
            "xss_fragmented_javascript_scheme",
            r"j[\s\x00-\x20]*a[\s\x00-\x20]*v[\s\x00-\x20]*a[\s\x00-\x20]*s[\s\x00-\x20]*c[\s\x00-\x20]*r[\s\x00-\x20]*i[\s\x00-\x20]*p[\s\x00-\x20]*t\s*:",
        ),
        (
            "xss_tagged_dangerous_call",
            r"(?:array[.]prototype[.]sort|[\[\].a-z0-9_]{0,64}[.]sort|reflect[.]set|apply)[.]call\s*`[\s\S]{0,192}(?:alert|location|navigation[.]navigate)",
        ),
        (
            "xss_css_escaped_javascript",
            r"background-image\s*:\s*url\s*[(][^)]{0,64}(?:\x5c[0-9a-f]{1,6}\s*){6,}",
        ),
        (
            "xss_malformed_svg_entity",
            r"(?:&?lt;|&#0*60;)\s*svg[^>]{0,128}\bonload\b",
        ),
    ],
    "exposure": [
        (
            "webshell_polyglot_path",
            r"/(?:wso|do)[.]php[^\x00-\x7f]{1,4}[.](?:png|jpe?g|gif)(?:$|[?#])",
        ),
    ],
}


def apply_extra_primitives(signatures: dict[str, list[tuple[str, str]]]) -> None:
    """Prepend reviewed signatures and replace legacy-incompatible patterns by name."""
    for family, additions in EXTRA_SIGNATURES.items():
        current = signatures.setdefault(family, [])
        replacement_names = {name for name, _ in additions}
        retained = [item for item in current if item[0] not in replacement_names]
        signatures[family] = list(additions) + retained
