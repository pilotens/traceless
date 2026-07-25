from pathlib import Path

# Apply the call-site change using the current source layout before running the
# broader generated implementation script.
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
path.write_text(text)
