"""
Personal Productivity MCP Server
=================================

Assignment 4: Calling services - Model Context Protocol

Domain: Personal Productivity (task tracking + email drafting)

Exposes:
  - Tool:   add_task            -> adds a task to a local JSON task store
  - Tool:   write_email_draft   -> writes/"sends" an email draft via a
                                    (simulated) authenticated email service
  - Prompt: prioritize_tasks    -> prompt template that asks an LLM to
                                    turn the current task list into a
                                    prioritized daily plan

Best practices implemented (2 of 4 required):
  1. Input Sanitization  -> see security.py: sanitize_task_title(),
     sanitize_email_field(), sanitize_email_body()
  2. Rate Limiting       -> see security.py: RateLimiter

Secret management:
  EMAIL_API_KEY is loaded from a .env file via python-dotenv (never
  hard-coded, never a system-wide env var). See .env.example.

Citations:
  The overall FastMCP server shape (the `FastMCP(...)`, `@mcp.tool()`,
  `@mcp.prompt()` pattern and `mcp.run()` entrypoint) follows the
  official MCP Python SDK README / quickstart example:
  https://github.com/modelcontextprotocol/python-sdk
  (see README.md "Code citations" section for the full list).
"""

import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from security import (
    RateLimiter,
    RateLimitExceeded,
    sanitize_email_body,
    sanitize_email_field,
    sanitize_task_title,
)

# ---------------------------------------------------------------------------
# Secret management: load from .env (pathlib-based, never os hardcoded path,
# never a system environment variable set outside the project).
# ---------------------------------------------------------------------------
ENV_PATH = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

EMAIL_API_KEY = os.getenv("EMAIL_API_KEY")
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
TASKS_FILE = DATA_DIR / "tasks.json"
EMAILS_FILE = DATA_DIR / "sent_emails.json"

# ---------------------------------------------------------------------------
# Rate limiter: shared, in-memory, 5 calls / 60 seconds per tool per process.
# This is intentionally simple (documented, not a distributed limiter) --
# good enough for a local single-user MCP server. See README "Limitations".
# ---------------------------------------------------------------------------
add_task_limiter = RateLimiter(max_calls=5, window_seconds=60)
email_limiter = RateLimiter(max_calls=5, window_seconds=60)

mcp = FastMCP("personal-productivity")


def _load_json(path: Path) -> list:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, data: list) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _fake_authenticate_email_service() -> bool:
    """
    Simulated authentication step against an external "email service".
    A real integration would use EMAIL_API_KEY as a Bearer token in an
    HTTPS request; here we just verify the secret is present and
    non-empty so the tool degrades safely if .env is missing.
    """
    return bool(EMAIL_API_KEY) and len(EMAIL_API_KEY) >= 8


@mcp.tool()
def add_task(title: str, due_date: str = "", priority: str = "medium") -> dict:
    """
    Add a task to the user's task list.

    Args:
        title: Short description of the task (max 200 chars).
        due_date: Optional due date, free text (e.g. "2026-09-30").
        priority: One of "low", "medium", "high". Defaults to "medium".

    Returns:
        dict with the created task, or an error message if input was
        rejected by input sanitization or the rate limiter.
    """
    try:
        add_task_limiter.check("add_task")
    except RateLimitExceeded as exc:
        # Error Disclosure-safe: generic message, no internals leaked.
        return {"error": "Too many requests. Please try again shortly.", "detail": str(exc)}

    try:
        clean_title = sanitize_task_title(title)
    except ValueError as exc:
        return {"error": "Invalid task title.", "detail": str(exc)}

    if priority not in {"low", "medium", "high"}:
        priority = "medium"

    tasks = _load_json(TASKS_FILE)
    task = {
        "id": len(tasks) + 1,
        "title": clean_title,
        "due_date": due_date[:32],  # bound length defensively
        "priority": priority,
        "created_at": time.time(),
        "done": False,
    }
    tasks.append(task)
    _save_json(TASKS_FILE, tasks)
    return {"status": "ok", "task": task}


@mcp.tool()
def write_email_draft(recipient_email: str, subject: str, body: str) -> dict:
    """
    Write (and simulate sending) an email draft through an authenticated
    email service.

    Args:
        recipient_email: Destination address.
        subject: Email subject line.
        body: Email body text.

    Returns:
        dict confirming the draft was written, or an error message.
    """
    try:
        email_limiter.check("write_email_draft")
    except RateLimitExceeded as exc:
        return {"error": "Too many requests. Please try again shortly.", "detail": str(exc)}

    if not _fake_authenticate_email_service():
        # Error Disclosure-safe: doesn't reveal whether key is missing,
        # malformed, or expired -- just that auth failed.
        return {"error": "Email service authentication failed."}

    try:
        clean_recipient = sanitize_email_field(recipient_email, field_name="recipient_email")
        clean_subject = sanitize_email_field(subject, field_name="subject")
        clean_body = sanitize_email_body(body)
    except ValueError as exc:
        return {"error": "Invalid email content.", "detail": str(exc)}

    emails = _load_json(EMAILS_FILE)
    draft = {
        "id": len(emails) + 1,
        "to": clean_recipient,
        "subject": clean_subject,
        "body": clean_body,
        "created_at": time.time(),
    }
    emails.append(draft)
    _save_json(EMAILS_FILE, emails)
    return {"status": "ok", "draft": draft}


@mcp.prompt()
def prioritize_tasks() -> str:
    """
    Prompt template: ask the LLM to read the current task list and
    produce a prioritized daily plan.
    """
    tasks = _load_json(TASKS_FILE)
    task_lines = "\n".join(
        f"- [{t['priority']}] {t['title']} (due: {t.get('due_date') or 'n/a'})"
        for t in tasks
        if not t.get("done")
    ) or "(no open tasks)"

    return (
        "You are a productivity assistant. Here is the user's current "
        "open task list:\n\n"
        f"{task_lines}\n\n"
        "Group these into a realistic plan for today, ordered by "
        "priority and due date. For each task, suggest a time block "
        "and flag anything that looks overdue or unrealistic to fit "
        "into one day."
    )


if __name__ == "__main__":
    mcp.run()
