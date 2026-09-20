from __future__ import annotations

from .models import Coverage, TechniqueResult

_LABELS = {
    Coverage.DETECTED_VISIBLE: "Detected & visible",
    Coverage.DETECTED_BLIND: "Detected but blind",
    Coverage.VISIBLE_UNDETECTED: "Visible but undetected",
    Coverage.NO_COVERAGE: "No coverage",
}

_SECTION_ORDER = (
    Coverage.DETECTED_BLIND,
    Coverage.VISIBLE_UNDETECTED,
    Coverage.NO_COVERAGE,
    Coverage.DETECTED_VISIBLE,
)


def render_markdown(
    results: dict[str, TechniqueResult],
    title: str = "ATT&CK detection coverage gap report",
) -> str:
    lines = [f"# {title}", ""]

    counts = {c: 0 for c in Coverage}
    for result in results.values():
        counts[result.coverage] += 1
    total = len(results) or 1

    lines.append("| Status | Count | % |")
    lines.append("|---|---|---|")
    for coverage in Coverage:
        pct = round(100 * counts[coverage] / total, 1)
        lines.append(f"| {_LABELS[coverage]} | {counts[coverage]} | {pct}% |")
    lines.append("")

    for coverage in _SECTION_ORDER:
        items = sorted(
            (r for r in results.values() if r.coverage == coverage),
            key=lambda r: r.technique_id,
        )
        if not items:
            continue
        lines.append(f"## {_LABELS[coverage]} ({len(items)})")
        lines.append("")
        for result in items:
            name = f" -- {result.name}" if result.name else ""
            lines.append(f"- **{result.technique_id}**{name}: {result.reason}")
        lines.append("")

    return "\n".join(lines)
