"""
Walks a file or folder, runs the security rules and quality checks on every
supported source file, and returns a list of findings plus a score.
"""

import os
from dataclasses import dataclass, asdict

from .rules import RULES, SEVERITY_ORDER
from .quality import check_quality

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java",
    ".rb", ".go", ".cs", ".sh", ".yml", ".yaml", ".json", ".env",
}

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".idea", ".vscode", "vendor",
}

MAX_FILE_SIZE = 1_000_000  # 1 MB, skip minified bundles and data dumps

# Points removed from 100 for each finding of a given severity
PENALTY = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    category: str        # "security" or "quality"
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    code: str
    cwe: str = ""
    recommendation: str = ""

    def to_dict(self):
        return asdict(self)


def iter_source_files(target: str):
    """Yield every supported file under target (or target itself)."""
    if os.path.isfile(target):
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in SUPPORTED_EXTENSIONS or name == ".env":
                path = os.path.join(root, name)
                if os.path.getsize(path) <= MAX_FILE_SIZE:
                    yield path


def is_suppressed(line: str) -> bool:
    """Developers can silence a reviewed false positive with `# secscan: ignore`."""
    return "secscan: ignore" in line or "secscan:ignore" in line


def scan_source(source: str, path: str, include_quality: bool = True) -> list:
    """Scan a string of code. `path` is used for the extension and the report."""
    findings = []
    ext = os.path.splitext(path)[1].lower() or os.path.basename(path)
    lines = source.splitlines()

    for number, line in enumerate(lines, start=1):
        if is_suppressed(line):
            continue
        for rule in RULES:
            if rule.applies_to(ext) and rule.regex.search(line):
                findings.append(Finding(
                    category="security",
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    file=path,
                    line=number,
                    code=line.strip()[:200],
                    cwe=rule.cwe,
                    recommendation=rule.recommendation,
                ))

    if include_quality:
        for issue in check_quality(source, ext):
            code = lines[issue.line - 1].strip()[:200] if 0 < issue.line <= len(lines) else ""
            findings.append(Finding(
                category="quality",
                rule_id=issue.id,
                title=issue.title,
                severity=issue.severity,
                file=path,
                line=issue.line,
                code=code,
                recommendation=issue.detail,
            ))
    return findings


def scan_path(target: str, include_quality: bool = True, min_severity: str = "INFO"):
    """Scan a file or directory. Returns (findings, files_scanned)."""
    if not os.path.exists(target):
        raise FileNotFoundError(target)

    threshold = SEVERITY_ORDER[min_severity]
    findings, scanned = [], 0

    for path in iter_source_files(target):
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                source = handle.read()
        except OSError:
            continue
        scanned += 1
        findings.extend(
            f for f in scan_source(source, path, include_quality)
            if SEVERITY_ORDER[f.severity] >= threshold
        )

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
    return findings, scanned


def security_score(findings) -> int:
    """A simple 0-100 score. Only security findings count; quality is advisory."""
    score = 100
    for f in findings:
        if f.category == "security":
            score -= PENALTY[f.severity]
    return max(score, 0)


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
