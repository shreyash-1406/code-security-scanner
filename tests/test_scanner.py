import json
import os

from secscan.scanner import scan_source, scan_path, security_score
from secscan.cli import main

HERE = os.path.dirname(__file__)
EXAMPLES = os.path.join(HERE, "..", "examples")


def ids(findings):
    return {f.rule_id for f in findings}


def test_detects_sql_injection():
    code = 'conn.execute(f"SELECT * FROM users WHERE id = {uid}")'
    assert "INJ001" in ids(scan_source(code, "a.py"))


def test_detects_hardcoded_password():
    assert "SEC001" in ids(scan_source('password = "hunter22"', "a.py"))


def test_detects_shell_true():
    code = 'subprocess.run(cmd, shell=True)'
    assert "INJ003" in ids(scan_source(code, "a.py"))


def test_detects_aws_key():
    assert "SEC003" in ids(scan_source('k = "AKIAIOSFODNN7EXAMPLE"', "a.js"))


def test_language_scoping():
    # innerHTML rule is JS-only, should not fire on a .py file
    assert "XSS001" not in ids(scan_source("x.innerHTML = y", "a.py"))
    assert "XSS001" in ids(scan_source("x.innerHTML = y", "a.js"))


def test_suppression_comment():
    code = 'password = "hunter22"  # secscan: ignore'
    assert scan_source(code, "a.py") == []


def test_bare_except_quality():
    code = "try:\n    x()\nexcept:\n    pass\n"
    found = ids(scan_source(code, "a.py"))
    assert {"QLT004", "QLT005"} <= found


def test_clean_file_has_no_security_findings():
    findings, _ = scan_path(os.path.join(EXAMPLES, "clean_app.py"))
    assert [f for f in findings if f.category == "security"] == []


def test_vulnerable_app_scores_badly():
    findings, scanned = scan_path(os.path.join(EXAMPLES, "vulnerable_app.py"))
    assert scanned == 1
    assert security_score(findings) < 40
    for rule in ["INJ001", "INJ003", "XSS005", "FIL001", "DES001", "CRY001", "CFG001", "CFG002"]:
        assert rule in ids(findings), rule


def test_cli_fail_on_exit_code(tmp_path, capsys):
    target = os.path.join(EXAMPLES, "vulnerable_app.py")
    assert main([target, "--fail-on", "HIGH", "--no-colour"]) == 1
    assert main([os.path.join(EXAMPLES, "clean_app.py"), "--fail-on", "HIGH"]) == 0


def test_cli_json_output(tmp_path):
    out = tmp_path / "r.json"
    main([EXAMPLES, "-f", "json", "-o", str(out)])
    data = json.loads(out.read_text())
    assert data["summary"]["files_scanned"] == 3
    assert data["summary"]["security_findings"] > 5
