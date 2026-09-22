"""
security.py
============

Implements the two best practices for Assignment 4:

  1. Input Sanitization  -> prevents SQL/command-style injection payloads
     and email-header injection (CRLF injection used to add bogus
     Bcc/Cc headers) from ever reaching stored data or the "email
     service".
  2. Rate Limiting        -> a simple fixed-window limiter shared across
     tool calls, per tool name, to bound abuse of either tool.

Everything here is original code written for this assignment (no
external snippets used in this file).
"""

import re
import time
from collections import defaultdict, deque

# ---------------------------------------------------------------------------
# 1. Input Sanitization
# ---------------------------------------------------------------------------

# Characters/patterns commonly used in SQL / command injection attempts.
# This is intentionally conservative: task titles and email fields are
# plain human text, so we simply reject anything containing shell/SQL
# metacharacters rather than trying to "clean" them (cleaning injection
# payloads is error-prone; rejecting is safer for a student project).
_DANGEROUS_PATTERN = re.compile(
    r"""[;&|`$]|          # shell metacharacters
        --|                # SQL comment
        /\*|\*/|           # SQL block comment
        \bDROP\b|\bDELETE\b|\bINSERT\b|\bUPDATE\b|\bSELECT\b|\bUNION\b|
        <script|           # basic XSS payload marker
        \.\./              # path traversal
    """,
    re.IGNORECASE | re.VERBOSE,
)

_MAX_TITLE_LEN = 200
_MAX_FIELD_LEN = 200
_MAX_BODY_LEN = 5000

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def sanitize_task_title(title: str) -> str:
    """Reject SQL/command-injection-style task titles; enforce length."""
    if not isinstance(title, str) or not title.strip():
        raise ValueError("Task title must be a non-empty string.")
    title = title.strip()
    if len(title) > _MAX_TITLE_LEN:
        raise ValueError(f"Task title exceeds {_MAX_TITLE_LEN} characters.")
    if _DANGEROUS_PATTERN.search(title):
        raise ValueError("Task title contains disallowed characters/patterns.")
    return title


def sanitize_email_field(value: str, field_name: str = "field") -> str:
    """
    Sanitize a single-line email field (recipient or subject).

    Specifically guards against email header injection: an attacker
    embedding \\r\\n (CRLF) followed by extra headers like
    'Bcc: attacker@evil.com' to hijack the message -- a classic
    injection attack against naive email-sending code.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string.")
    value = value.strip()
    if len(value) > _MAX_FIELD_LEN:
        raise ValueError(f"{field_name} exceeds {_MAX_FIELD_LEN} characters.")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{field_name} must not contain newline characters (header injection).")
    if _DANGEROUS_PATTERN.search(value):
        raise ValueError(f"{field_name} contains disallowed characters/patterns.")
    if field_name == "recipient_email" and not _EMAIL_RE.match(value):
        raise ValueError("recipient_email is not a valid email address.")
    return value


def sanitize_email_body(body: str) -> str:
    """Sanitize a multi-line email body (newlines allowed, injection patterns are not)."""
    if not isinstance(body, str) or not body.strip():
        raise ValueError("Email body must be a non-empty string.")
    body = body.strip()
    if len(body) > _MAX_BODY_LEN:
        raise ValueError(f"Email body exceeds {_MAX_BODY_LEN} characters.")
    if _DANGEROUS_PATTERN.search(body):
        raise ValueError("Email body contains disallowed characters/patterns.")
    return body


# ---------------------------------------------------------------------------
# 2. Rate Limiting
# ---------------------------------------------------------------------------

class RateLimitExceeded(Exception):
    """Raised when a caller exceeds the configured rate limit."""


class RateLimiter:
    """
    Simple fixed-window-per-call (sliding log) rate limiter.

    Tracks call timestamps per "key" (here: tool name) and rejects a
    call if more than `max_calls` have happened in the trailing
    `window_seconds`. In-memory and per-process -- documented
    limitation for a single-user local MCP server (see README).
    """

    def __init__(self, max_calls: int, window_seconds: float):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._calls: dict[str, deque] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        q = self._calls[key]
        while q and now - q[0] > self.window_seconds:
            q.popleft()
        if len(q) >= self.max_calls:
            raise RateLimitExceeded(
                f"Rate limit exceeded for '{key}': "
                f"max {self.max_calls} calls per {self.window_seconds}s."
            )
        q.append(now)
