# secscan: Code Security & Quality Testing Tool

A lightweight static analysis tool that scans source code for **security vulnerabilities** (SQL injection, command injection, XSS, hardcoded secrets, weak crypto, unsafe deserialisation…) and **code quality problems** (high complexity, deep nesting, swallowed exceptions), then gives the codebase a security score.

Pure Python, no dependencies, works offline, and plugs into CI to block insecure code before it is merged.

```
$ python -m secscan examples/vulnerable_app.py --no-quality

HIGH     SEC001 Hardcoded password [CWE-798]
         examples/vulnerable_app.py:16
         > DB_PASSWORD = "SuperSecret123"
         Fix: Load secrets from environment variables or a secrets manager, never from source code.
...
============================================================
Files scanned     : 1
Security findings : 11  {'HIGH': 7, 'MEDIUM': 4}
Security score    : 14/100  (grade F)
```

## Features

- **27 security rules** mapped to CWE ids across Python, JavaScript/TypeScript, PHP and Java, plus language-agnostic secret detection (AWS keys, private keys, tokens)
- **Python code quality analysis** using the `ast` module: cyclomatic complexity, function length, nesting depth, bare `except`, silently ignored exceptions, `assert` misuse
- **Security score and grade** (0–100, A–F) so progress is easy to track
- **Three report formats**: coloured console, JSON (for tooling), and a standalone HTML report
- **CI gate**: `--fail-on HIGH` exits with code 1 when serious issues are found
- **Inline suppression**: mark a reviewed false positive with `# secscan: ignore`

## Install

```bash
git clone https://github.com/shreyash-1406/code-security-scanner.git
cd code-security-scanner
pip install .          # optional: gives you the `secscan` command
```

No install needed to try it: `python -m secscan <path>` works from the repo folder.

## Usage

```bash
# Scan a project
python -m secscan path/to/project

# Security issues only, HIGH and above
python -m secscan path/to/project --no-quality --min-severity HIGH

# HTML report
python -m secscan path/to/project -f html -o report.html

# JSON for other tools
python -m secscan path/to/project -f json -o report.json

# Use in CI: fail the build on HIGH or CRITICAL findings
python -m secscan src --fail-on HIGH

# See every rule
python -m secscan --list-rules
```

## Rule coverage

| Category | Examples | CWE |
|---|---|---|
| Secrets | Hardcoded passwords, API keys, AWS keys, private keys | CWE-798, CWE-321 |
| Injection | SQL string building, `shell=True`, `os.system`, `eval`, PHP shell functions, `Runtime.exec` | CWE-89, CWE-78, CWE-95 |
| XSS / templates | `innerHTML`, `dangerouslySetInnerHTML`, `echo $_GET`, `render_template_string` | CWE-79, CWE-1336 |
| Cryptography | MD5/SHA1, ECB mode, `Math.random` / `random` for tokens | CWE-327, CWE-338 |
| Configuration | TLS verification off, debug mode, wildcard CORS, plain HTTP | CWE-295, CWE-489, CWE-942, CWE-319 |
| Deserialisation & files | `pickle.loads`, unsafe `yaml.load`, `unserialize`, path traversal, `chmod 777` | CWE-502, CWE-22, CWE-732 |

## How it works

```
 target folder
      │
      ▼
 iter_source_files()  ── skips .git, node_modules, venv, files > 1 MB
      │
      ▼
 for each line ──► regex security rules (filtered by file extension)
      │
      ▼
 for .py files ──► ast parse ──► complexity / nesting / exception checks
      │
      ▼
 findings sorted by severity ──► score ──► console / JSON / HTML report
```

| File | Role |
|---|---|
| `secscan/rules.py` | Security rules: regex, severity, CWE, fix advice |
| `secscan/quality.py` | AST-based and line-based quality checks |
| `secscan/scanner.py` | File walking, matching, scoring |
| `secscan/report.py` | Console, JSON and HTML output |
| `secscan/cli.py` | Command line options |

## Try it on the demo files

`examples/` contains a deliberately vulnerable Flask app, a vulnerable JS file, and a clean file:

```bash
python -m secscan examples
python -m secscan examples/clean_app.py     # no security findings
```

## Tests

```bash
pip install pytest
pytest -q
```

GitHub Actions runs the tests on every push and also scans the tool's own source code.

## Limitations

This is a pattern-based scanner, not a full data-flow analyser. It can miss vulnerabilities that span several lines or files, and it will flag some safe code. Treat findings as leads for manual review. For deeper analysis it pairs well with tools such as Semgrep, Bandit or CodeQL.

## Roadmap

- [ ] Multi-line rules (e.g. user input flowing into a query a few lines later)
- [ ] Custom rules from a YAML file
- [ ] SARIF output for GitHub code scanning
- [ ] Quality checks for JavaScript using a JS parser

## Author

**Shreyash Uparkar** · [GitHub](https://github.com/shreyash-1406)

## License

MIT
