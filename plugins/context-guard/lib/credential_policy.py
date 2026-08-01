"""Pure shared credential classification and high-confidence redaction policy."""
from __future__ import annotations

import re


SECRET_KEY = (
    r"[A-Za-z0-9_.-]*(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|"
    r"private[_-]?key|access[_-]?key|client[_-]?secret|credential|signature|sig|"
    r"ssh[_-]?key|ssh[_-]?command|pgp[_-]?private[_-]?key)[A-Za-z0-9_.-]*"
    r"|(?:pass|smtp[_-]?pass|[A-Za-z0-9_.-]+[._-]pass)"
    r"|(?:session(?:[_-]?(?:id|token))?|sessionid|sid|jsessionid|"
    r"csrf(?:[_-]?token)?|xsrf(?:[_-]?token)?)"
    r"|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
    r"GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET"
)
URL_LIKE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s]+")
URL_SECRET_PARAM_RE = re.compile(rf"(?i)([?&#;](?:{SECRET_KEY})=)[^\s?&#;]+")
SCHEMELESS_SECRET_PARAM_RE = re.compile(rf"(?i)([?&#](?:{SECRET_KEY})=)[^\s?&#;]+")
CAMEL_ACRONYM_BOUNDARY_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
CAMEL_WORD_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
EXACT_SENSITIVE_KEYS = frozenset(
    {
        "access_key",
        "access_key_id",
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "azure_client_secret",
        "client_secret",
        "cookie",
        "credential",
        "credential_helper",
        "credentials",
        "csrf",
        "csrf_token",
        "google_application_credentials",
        "id_token",
        "jsessionid",
        "jwt",
        "pass",
        "password",
        "passwd",
        "private_key",
        "privatekey",
        "proxy_authorization",
        "pwd",
        "refresh_token",
        "secret",
        "session",
        "session_id",
        "session_token",
        "sessionid",
        "set_cookie",
        "sid",
        "sig",
        "signature",
        "smtp_pass",
        "smtppass",
        "ssh_command",
        "ssh_key",
        "sshkey",
        "token",
        "x_amz_credential",
        "x_amz_security_token",
        "x_amz_signature",
        "xsrf",
        "xsrf_token",
    }
)
SENSITIVE_KEY_SUFFIXES = (
    "_access_key",
    "_access_token",
    "_api_key",
    "_client_secret",
    "_credential",
    "_credentials",
    "_password",
    "_private_key",
    "_refresh_token",
    "_secret",
    "_secret_key",
    "_session_token",
    "_ssh_command",
    "_token",
)
SENSITIVE_KEY_QUALIFIER_RE = re.compile(
    r"(?:^|_)(?:api_?key|apikey|token|secret|password|passwd|pass|pwd|"
    r"private_key|access_key|client_secret|credential|signature|sig|"
    r"session_id|session_token)(?:_(?:v\d+|prod|production|dev|test|backup))?$"
)
INLINE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)(--(?:api[_-]?key|token|secret|password|client[_-]?secret)\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(--(?:api[_-]?key|token|secret|password|client[_-]?secret)=)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:-p|-u|--user)\s+)\S+:\S+"), r"\1[REDACTED]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"), "[REDACTED]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "[REDACTED]"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{12,}"), "[REDACTED]"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED]"),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "[REDACTED]"),
    (re.compile(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"), "[REDACTED]"),
    (re.compile(r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}"), "[REDACTED]"),
    (re.compile(r"sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}"), "[REDACTED]"),
    (re.compile(r"npm_[A-Za-z0-9]{20,}"), "[REDACTED]"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "[REDACTED]"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), "[REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED]"),
    # FIX-6: URL userinfo 리댁션 — 비밀번호 파트(`:pass`)를 선택적으로 만들어
    # `scheme://TOKEN@host`(콜론 없는 토큰 전용 형태, 가장 흔한 PAT 임베딩 방식)도
    # 함께 잡는다. 기존 패턴은 `user:pass@` 두 부분을 모두 요구해 벤더 접두사가
    # 없는 토큰(Azure DevOps PAT, 사내 PAT, 범용 토큰 등 — `ghp_`/`github_pat_`/
    # `glpat-`처럼 위에서 별도 패턴이 잡는 벤더가 아닌 토큰)을 통과시켰다(실측
    # 3/3 누수). `scheme://` 접두사는 여전히 필수이므로 `git log` 저자 줄의
    # `<user@host>` 같은 스킴 없는 평범한 이메일 언급은 과잉 리댁션하지 않는다
    # — 이 경계는 sanitizer_mode_cases의 `bare_userinfo_without_scheme` 음성
    # 케이스로 고정한다(tests/context_guard_a1_oracles.py).
    (re.compile(r"([a-z][a-z0-9+.-]*://)[^/\s:@]+(?::[^/\s@]+)?@", re.IGNORECASE), r"\1[REDACTED]@"),
)


def normalize_sensitive_key(key: str) -> str:
    key = CAMEL_ACRONYM_BOUNDARY_RE.sub("_", key)
    key = CAMEL_WORD_BOUNDARY_RE.sub("_", key)
    key = re.sub(r"[_.-]+", "_", key)
    return re.sub(r"_+", "_", key).strip("_").lower()


def is_sensitive_key(key: str) -> bool:
    normalized = normalize_sensitive_key(key.strip().strip("\"'"))
    return (
        normalized in EXACT_SENSITIVE_KEYS
        or normalized.endswith(SENSITIVE_KEY_SUFFIXES)
        or SENSITIVE_KEY_QUALIFIER_RE.search(normalized) is not None
    )


def redact_url_like_secret_params(line: str) -> tuple[str, bool]:
    redacted = False

    def url_repl(match: re.Match[str]) -> str:
        nonlocal redacted

        def param_repl(param_match: re.Match[str]) -> str:
            nonlocal redacted
            prefix = param_match.group(1)
            key = prefix[1:].split("=", 1)[0]
            if not is_sensitive_key(key):
                return param_match.group(0)
            redacted = True
            return prefix + "[REDACTED]"

        return URL_SECRET_PARAM_RE.sub(param_repl, match.group(0))

    line = URL_LIKE_RE.sub(url_repl, line)

    def fragment_repl(param_match: re.Match[str]) -> str:
        nonlocal redacted
        prefix = param_match.group(1)
        key = prefix[1:].split("=", 1)[0]
        if not is_sensitive_key(key):
            return param_match.group(0)
        redacted = True
        return prefix + "[REDACTED]"

    return SCHEMELESS_SECRET_PARAM_RE.sub(fragment_repl, line), redacted


def redact_high_confidence_credentials(text: str) -> tuple[str, int]:
    """Redact context-independent credential values without path policy."""
    redactions = 0
    text, url_redacted = redact_url_like_secret_params(text)
    if url_redacted:
        redactions += 1
    for pattern, replacement in INLINE_PATTERNS:
        text, count = pattern.subn(replacement, text)
        redactions += count
    return text, redactions
