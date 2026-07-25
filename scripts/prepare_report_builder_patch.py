from pathlib import Path

workspace = Path('apps/web/src/components/OperationalWorkspace.tsx')
workspace_text = workspace.read_text()
call_old = "        `report-${crypto.randomUUID()}`,\n      );"
call_new = "        `report-${crypto.randomUUID()}`,\n        reportSections,\n      );"
if call_old not in workspace_text and call_new not in workspace_text:
    raise SystemExit('report enqueue call marker not found')
workspace.write_text(workspace_text.replace(call_old, call_new, 1))

path = Path('/tmp/implement.py')
text = path.read_text()
text = text.replace('from pathlib import Path\n', 'from pathlib import Path\nimport inspect\n', 1)
old = 'def replace(path: str, old: str, new: str) -> None:\n    file = Path(path)\n'
new = '''def replace(path: str, old: str, new: str) -> None:
    if path.endswith((".ts", ".tsx")):
        def normalize(value: str) -> str:
            trailing = "\\n" if value.endswith("\\n") else ""
            first = value.splitlines()[0]
            indent = len(first) - len(first.lstrip())
            cleaned = inspect.cleandoc(value)
            return "\\n".join((" " * indent + line) if line else line for line in cleaned.splitlines()) + trailing
        old = normalize(old)
        new = normalize(new)
    file = Path(path)
'''
if old not in text:
    raise SystemExit('replace function marker not found')
text = text.replace(old, new, 1)
text = text.replace(
    "    if old not in text:\n        raise SystemExit(f'Pattern not found in {path}: {old[:120]!r}')\n",
    "    if old not in text:\n        if path.endswith('OperationalWorkspace.tsx') and (\"setReportType('management')\" in old or 'report-${crypto.randomUUID()}' in old):\n            return\n        raise SystemExit(f'Pattern not found in {path}: {old[:120]!r}')\n",
    1,
)

text += r'''

# Compatibility and regression-test corrections applied after the generated patch.
reporting_file = Path('apps/api/src/traceless_api/services/reporting.py')
reporting_text = reporting_file.read_text()
reporting_text = reporting_text.replace(
    'def _report_payload(\n    snapshot: dict[str, Any], report_type: str, selected_sections: list[str]\n) -> dict[str, Any]:\n',
    'def _report_payload(\n    snapshot: dict[str, Any],\n    report_type: str,\n    selected_sections: list[str] | None = None,\n) -> dict[str, Any]:\n    selected_sections = resolve_report_sections(report_type, selected_sections)\n',
    1,
)
reporting_text = reporting_text.replace(
    'Paragraph(escape(item["title"]), styles["TracelessSmall"]),\n                        item["severity"],\n                        ", ".join(item["attack_patterns"]) or "–",',
    'Paragraph(escape(str(item.get("title") or item.get("name") or item.get("id") or "Okänt hot")), styles["TracelessSmall"]),\n                        item.get("severity", "unknown"),\n                        ", ".join(item.get("attack_patterns", [])) or "–",',
    1,
)
reporting_file.write_text(reporting_text)

test_file = Path('apps/api/tests/test_reporting.py')
test_text = test_file.read_text()
start = test_text.index('\ndef test_custom_report_sections_control_payload_and_are_frozen(')
end = test_text.index('\ndef test_report_create_rejects_duplicate_sections', start)
replacement = '''\ndef test_custom_report_sections_control_payload_and_are_frozen():
    from traceless_api.services.reporting import freeze_report_configuration, render_report

    snapshot = _snapshot()
    selected = freeze_report_configuration(
        snapshot,
        report_type="technical",
        sections=["executive_summary", "risks", "limitations"],
    )
    payload = json.loads(
        render_report(
            snapshot,
            format="json",
            report_type="technical",
            sections=selected,
        )
    )
    assert payload["selected_sections"] == ["executive_summary", "risks", "limitations"]
    assert "summary" in payload
    assert "risks" in payload
    assert "limitations" in payload
    assert "assets" not in payload
    assert "findings" not in payload
    assert snapshot["report_configuration"]["sections"] == selected

'''
test_file.write_text(test_text[:start] + replacement + test_text[end:])
'''
path.write_text(text)
