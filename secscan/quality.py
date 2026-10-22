"""
Code quality checks.

Security bugs hide more easily in code that is long, deeply nested and hard to
read, so the scanner also reports a few quality signals:

* For Python files, the ast module gives accurate numbers: function length,
  cyclomatic complexity, nesting depth, bare `except:` blocks.
* For every language, simple line-based checks: very long lines, TODO/FIXME
  markers, and large files.
"""

import ast
from dataclasses import dataclass

MAX_FUNCTION_LINES = 50
MAX_COMPLEXITY = 10
MAX_NESTING = 4
MAX_LINE_LENGTH = 120
MAX_FILE_LINES = 800


@dataclass
class QualityIssue:
    id: str
    title: str
    severity: str
    line: int
    detail: str


# ---------------------------------------------------------------------------
# Python (ast-based)
# ---------------------------------------------------------------------------

BRANCH_NODES = (ast.If, ast.For, ast.While, ast.Try, ast.With,
                ast.ExceptHandler, ast.IfExp, ast.comprehension, ast.AsyncFor,
                ast.AsyncWith)


def cyclomatic_complexity(func: ast.AST) -> int:
    """McCabe complexity: 1 + number of decision points."""
    complexity = 1
    for node in ast.walk(func):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp,
                             ast.ExceptHandler, ast.AsyncFor, ast.comprehension)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            # `a and b and c` adds two decision points
            complexity += len(node.values) - 1
    return complexity


def max_nesting(node: ast.AST, depth: int = 0) -> int:
    deepest = depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, BRANCH_NODES):
            deepest = max(deepest, max_nesting(child, depth + 1))
        elif not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            deepest = max(deepest, max_nesting(child, depth))
    return deepest


def check_python(source: str) -> list:
    issues = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [QualityIssue("QLT000", "File could not be parsed", "LOW",
                             exc.lineno or 1, str(exc.msg))]

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            length = (node.end_lineno or node.lineno) - node.lineno + 1
            if length > MAX_FUNCTION_LINES:
                issues.append(QualityIssue(
                    "QLT001", "Long function", "LOW", node.lineno,
                    f"'{node.name}' is {length} lines (limit {MAX_FUNCTION_LINES}); split it up."))

            cc = cyclomatic_complexity(node)
            if cc > MAX_COMPLEXITY:
                issues.append(QualityIssue(
                    "QLT002", "High cyclomatic complexity", "MEDIUM", node.lineno,
                    f"'{node.name}' has complexity {cc} (limit {MAX_COMPLEXITY}); hard to test fully."))

            depth = max_nesting(node)
            if depth > MAX_NESTING:
                issues.append(QualityIssue(
                    "QLT003", "Deep nesting", "LOW", node.lineno,
                    f"'{node.name}' nests {depth} levels deep (limit {MAX_NESTING}); use early returns."))

        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(QualityIssue(
                "QLT004", "Bare except", "MEDIUM", node.lineno,
                "`except:` hides every error, including security failures. Catch specific exceptions."))

        if (isinstance(node, ast.ExceptHandler)
                and len(node.body) == 1 and isinstance(node.body[0], ast.Pass)):
            issues.append(QualityIssue(
                "QLT005", "Exception silently ignored", "LOW", node.lineno,
                "The except block only contains `pass`; at least log the error."))

        if isinstance(node, ast.Assert):
            issues.append(QualityIssue(
                "QLT006", "assert used for a check", "LOW", node.lineno,
                "asserts are removed with `python -O`; don't use them for security checks."))

    return issues


# ---------------------------------------------------------------------------
# Any language (line-based)
# ---------------------------------------------------------------------------

def check_generic(source: str) -> list:
    issues = []
    lines = source.splitlines()

    if len(lines) > MAX_FILE_LINES:
        issues.append(QualityIssue(
            "QLT010", "Large file", "INFO", 1,
            f"{len(lines)} lines (limit {MAX_FILE_LINES}); consider splitting into modules."))

    for number, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            issues.append(QualityIssue(
                "QLT011", "Very long line", "INFO", number,
                f"{len(line)} characters (limit {MAX_LINE_LENGTH})."))
        upper = line.upper()
        if "TODO" in upper or "FIXME" in upper or "HACK" in upper:
            issues.append(QualityIssue(
                "QLT012", "Unfinished work marker", "INFO", number,
                line.strip()[:100]))
    return issues


def check_quality(source: str, extension: str) -> list:
    issues = check_generic(source)
    if extension == ".py":
        issues.extend(check_python(source))
    return issues
