"""Minimal Sigma rule metadata reader.

This is deliberately *not* a general YAML parser: pulling in PyYAML would
break the dependency-free convention this tool follows, and a full Sigma
`detection` block (arbitrary field modifiers, regexes, nested lists) is not
needed here. attackgap only cares about four fields every Sigma rule has in
a predictable, flat shape: ``title``, ``id``, ``status``, ``logsource``
(a small flat mapping) and ``tags`` (a flat list of scalars, flow or block
style). This module scans for exactly those, line by line, and ignores
everything else in the file.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import SigmaRule

_ATTACK_TAG_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)


def normalize_technique(tag: str) -> str | None:
    """Turn a Sigma ATT&CK tag ('attack.t1059.001') into 'T1059.001'."""
    match = _ATTACK_TAG_RE.match(tag.strip().lower())
    if not match:
        return None
    base, sub = match.groups()
    technique_id = f"T{base}"
    if sub:
        technique_id += f".{sub}"
    return technique_id


def _strip_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    return line


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _parse_flow_list(value: str) -> list[str]:
    inner = value.strip()
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]
    return [_unquote(item) for item in inner.split(",") if item.strip()]


def _consume_block(lines: list[str], i: int, parent_indent: int) -> tuple[list[str], int]:
    """Collect stripped, non-blank lines more indented than parent_indent."""
    block: list[str] = []
    n = len(lines)
    while i < n:
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= parent_indent:
            break
        block.append(line.strip())
        i += 1
    return block, i


def parse_sigma_text(text: str, source_name: str = "<string>") -> SigmaRule:
    lines = [_strip_comment(l.rstrip("\n")) for l in text.splitlines()]

    title = ""
    rule_id = ""
    status = ""
    logsource: dict[str, str] = {}
    technique_ids: set[str] = set()

    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        if not raw.strip():
            i += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if indent != 0 or ":" not in stripped:
            i += 1
            continue

        key, _, rest = stripped.partition(":")
        key = key.strip().lower()
        rest = rest.strip()

        if key == "title":
            title = _unquote(rest)
            i += 1
        elif key == "id":
            rule_id = _unquote(rest)
            i += 1
        elif key == "status":
            status = _unquote(rest)
            i += 1
        elif key == "logsource":
            block, i = _consume_block(lines, i + 1, indent)
            for entry in block:
                if ":" in entry:
                    sk, _, sv = entry.partition(":")
                    logsource[sk.strip().lower()] = _unquote(sv)
        elif key == "tags":
            if rest:
                for tag in _parse_flow_list(rest):
                    normalized = normalize_technique(tag)
                    if normalized:
                        technique_ids.add(normalized)
                i += 1
            else:
                block, i = _consume_block(lines, i + 1, indent)
                for entry in block:
                    if entry.startswith("-"):
                        tag = _unquote(entry[1:].strip())
                        normalized = normalize_technique(tag)
                        if normalized:
                            technique_ids.add(normalized)
        else:
            i += 1

    return SigmaRule(
        path=source_name,
        title=title,
        rule_id=rule_id,
        status=status,
        logsource=logsource,
        technique_ids=sorted(technique_ids),
    )


def parse_sigma_file(path: Path) -> SigmaRule:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_sigma_text(text, source_name=str(path))


def load_rules(rules_dir: Path) -> list[SigmaRule]:
    rules_dir = Path(rules_dir)
    paths = sorted(set(rules_dir.rglob("*.yml")) | set(rules_dir.rglob("*.yaml")))
    return [parse_sigma_file(p) for p in paths]
