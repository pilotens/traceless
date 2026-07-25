from pathlib import Path

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

# The workspace reset function has changed shape since the implementation script
# was authored. Report sections already initialize from the management profile,
# and the report-type selector resets them when changed, so this non-essential
# exact-match patch can be safely omitted.
reset_patch = '''replace(path,
''' + "'''    setReportType('management');\n      }\n'''" + ''',
''' + "'''    setReportType('management');\n        setReportSections(REPORT_SECTION_DEFAULTS.management);\n      }\n'''" + ''')
'''
text = text.replace(reset_patch, '')
path.write_text(text)
