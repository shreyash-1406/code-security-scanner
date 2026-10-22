"""
Security rules for the scanner.

Each rule is a regular expression that matches a risky pattern in source code,
plus the metadata needed to explain the finding: severity, CWE id, and a fix.

Rules are deliberately simple and readable. Regex-based scanning will produce
some false positives; every finding should be reviewed by a human.
"""

from dataclasses import dataclass, field
import re


@dataclass
class Rule:
    id: str
    title: str
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cwe: str
    pattern: str
    recommendation: str
    languages: list = field(default_factory=lambda: ["*"])   # file extensions, "*" = all
    flags: int = re.IGNORECASE

    def __post_init__(self):
        self.regex = re.compile(self.pattern, self.flags)

    def applies_to(self, extension: str) -> bool:
        return "*" in self.languages or extension in self.languages


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

PY = [".py"]
JS = [".js", ".jsx", ".ts", ".tsx"]
PHP = [".php"]
JAVA = [".java"]
WEB = PY + JS + PHP + JAVA


RULES = [
    # ---------------- Secrets ----------------
    Rule(
        id="SEC001",
        title="Hardcoded password",
        severity="HIGH",
        cwe="CWE-798",
        pattern=r"""(password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{4,}["']""",
        recommendation="Load secrets from environment variables or a secrets manager, never from source code.",
    ),
    Rule(
        id="SEC002",
        title="Hardcoded API key or token",
        severity="HIGH",
        cwe="CWE-798",
        pattern=r"""(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']""",
        recommendation="Move the key to an environment variable and rotate the exposed key.",
    ),
    Rule(
        id="SEC003",
        title="AWS access key ID",
        severity="CRITICAL",
        cwe="CWE-798",
        pattern=r"\bAKIA[0-9A-Z]{16}\b",
        recommendation="Revoke this key in AWS IAM immediately and use IAM roles or environment variables.",
        flags=0,
    ),
    Rule(
        id="SEC004",
        title="Private key in source",
        severity="CRITICAL",
        cwe="CWE-321",
        pattern=r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        recommendation="Remove the key from the repository, rotate it, and purge it from git history.",
        flags=0,
    ),

    # ---------------- Injection ----------------
    Rule(
        id="INJ001",
        title="SQL query built with string formatting",
        severity="HIGH",
        cwe="CWE-89",
        pattern=r"""(execute|query|raw)\s*\(\s*(f["']|["'][^"']*["']\s*(%|\+|\.format))[^)]*(select|insert|update|delete)""",
        recommendation="Use parameterised queries (placeholders such as %s or ?) instead of building SQL strings.",
        languages=WEB,
    ),
    Rule(
        id="INJ002",
        title="SQL keywords concatenated with variables",
        severity="MEDIUM",
        cwe="CWE-89",
        pattern=r"""["'](select|insert into|update|delete from)\b[^"']*["']\s*(\+|%|\.)\s*\w""",
        recommendation="Use parameterised queries or an ORM.",
        languages=WEB,
    ),
    Rule(
        id="INJ003",
        title="OS command execution with shell=True",
        severity="HIGH",
        cwe="CWE-78",
        pattern=r"subprocess\.(call|run|Popen|check_output|check_call)\([^)]*shell\s*=\s*True",
        recommendation="Pass arguments as a list and keep shell=False; validate any user input.",
        languages=PY,
    ),
    Rule(
        id="INJ004",
        title="os.system / os.popen call",
        severity="MEDIUM",
        cwe="CWE-78",
        pattern=r"\bos\.(system|popen)\s*\(",
        recommendation="Use subprocess.run with a list of arguments instead.",
        languages=PY,
    ),
    Rule(
        id="INJ005",
        title="Use of eval/exec",
        severity="HIGH",
        cwe="CWE-95",
        pattern=r"(?<![\w.])(eval|exec)\s*\(",
        recommendation="Avoid eval/exec. Use ast.literal_eval or JSON parsing for data.",
        languages=PY + JS + PHP,
    ),
    Rule(
        id="INJ006",
        title="PHP command execution function",
        severity="HIGH",
        cwe="CWE-78",
        pattern=r"\b(shell_exec|passthru|proc_open|popen|system)\s*\(\s*\$",
        recommendation="Avoid shell functions; if unavoidable, escape with escapeshellarg().",
        languages=PHP,
    ),
    Rule(
        id="INJ007",
        title="Java Runtime.exec call",
        severity="MEDIUM",
        cwe="CWE-78",
        pattern=r"Runtime\.getRuntime\(\)\.exec\(",
        recommendation="Use ProcessBuilder with a fixed command and validated arguments.",
        languages=JAVA,
        flags=0,
    ),

    # ---------------- XSS ----------------
    Rule(
        id="XSS001",
        title="Assignment to innerHTML",
        severity="MEDIUM",
        cwe="CWE-79",
        pattern=r"\.innerHTML\s*=",
        recommendation="Use textContent, or sanitise HTML with a library such as DOMPurify.",
        languages=JS,
    ),
    Rule(
        id="XSS002",
        title="React dangerouslySetInnerHTML",
        severity="MEDIUM",
        cwe="CWE-79",
        pattern=r"dangerouslySetInnerHTML",
        recommendation="Sanitise the HTML before rendering, or render plain text.",
        languages=JS,
        flags=0,
    ),
    Rule(
        id="XSS003",
        title="document.write call",
        severity="LOW",
        cwe="CWE-79",
        pattern=r"document\.write\s*\(",
        recommendation="Build DOM nodes with createElement/textContent instead.",
        languages=JS,
    ),
    Rule(
        id="XSS004",
        title="PHP echo of request data",
        severity="HIGH",
        cwe="CWE-79",
        pattern=r"echo\s+\$_(GET|POST|REQUEST|COOKIE)",
        recommendation="Escape output with htmlspecialchars($value, ENT_QUOTES, 'UTF-8').",
        languages=PHP,
    ),
    Rule(
        id="XSS005",
        title="Flask template rendered from a string",
        severity="MEDIUM",
        cwe="CWE-1336",
        pattern=r"render_template_string\s*\(",
        recommendation="Use render_template with a file; never put user input into a template string (SSTI).",
        languages=PY,
    ),

    # ---------------- Crypto ----------------
    Rule(
        id="CRY001",
        title="Weak hash algorithm (MD5/SHA1)",
        severity="MEDIUM",
        cwe="CWE-327",
        pattern=r"\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)|MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"",
        recommendation="Use SHA-256 or stronger; for passwords use bcrypt, scrypt or Argon2.",
    ),
    Rule(
        id="CRY002",
        title="Insecure random number generator for security use",
        severity="LOW",
        cwe="CWE-338",
        pattern=r"(random\.(random|randint|choice)|Math\.random)\s*\(",
        recommendation="Use the secrets module (Python) or crypto.getRandomValues (JS) for tokens and keys.",
        languages=PY + JS,
    ),
    Rule(
        id="CRY003",
        title="ECB block cipher mode",
        severity="MEDIUM",
        cwe="CWE-327",
        pattern=r"(MODE_ECB|/ECB/|AES/ECB)",  # secscan: ignore
        recommendation="Use an authenticated mode such as AES-GCM.",
        flags=0,
    ),

    # ---------------- Config / transport ----------------
    Rule(
        id="CFG001",
        title="TLS certificate verification disabled",
        severity="HIGH",
        cwe="CWE-295",
        pattern=r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)",
        recommendation="Keep certificate verification on; add the internal CA to the trust store if needed.",
    ),
    Rule(
        id="CFG002",
        title="Debug mode enabled",
        severity="MEDIUM",
        cwe="CWE-489",
        pattern=r"(debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)",
        recommendation="Disable debug mode in production; it can expose an interactive console.",
        languages=PY,
    ),
    Rule(
        id="CFG003",
        title="Plain HTTP URL",
        severity="INFO",
        cwe="CWE-319",
        pattern=r"""["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"']+["']""",
        recommendation="Use HTTPS for all external endpoints.",
    ),
    Rule(
        id="CFG004",
        title="Wildcard CORS origin",
        severity="MEDIUM",
        cwe="CWE-942",
        pattern=r"""(Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|origins?\s*=\s*["']\*["']|CORS\([^)]*origins\s*=\s*["']\*)""",
        recommendation="Allow only the specific origins that need access.",
    ),

    # ---------------- Deserialisation / files ----------------
    Rule(
        id="DES001",
        title="Unsafe deserialisation (pickle/yaml.load)",
        severity="HIGH",
        cwe="CWE-502",
        pattern=r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*SafeLoader)",
        recommendation="Never unpickle untrusted data; use yaml.safe_load and JSON.",
        languages=PY,
    ),
    Rule(
        id="DES002",
        title="PHP unserialize on user input",
        severity="HIGH",
        cwe="CWE-502",
        pattern=r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        recommendation="Use json_decode for user-supplied data.",
        languages=PHP,
    ),
    Rule(
        id="FIL001",
        title="File path built from request data",
        severity="HIGH",
        cwe="CWE-22",
        pattern=r"(open|send_file|readFile|readFileSync|file_get_contents|include|require)\s*\([^)]*(request\.|req\.(query|params|body)|\$_(GET|POST|REQUEST))",
        recommendation="Validate the filename against an allowlist and resolve it inside a fixed base directory.",
        languages=WEB,
    ),
    Rule(
        id="FIL002",
        title="World-writable file permissions",
        severity="MEDIUM",
        cwe="CWE-732",
        pattern=r"chmod\s*\(?[^)\n]*0?o?777",
        recommendation="Use the least permissive mode needed, e.g. 0o640 or 0o750.",
    ),
]
