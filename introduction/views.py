# File: introduction/views.py
#
# NOTE:
# This file contains ONLY the security-relevant fixed snippets that would
# replace the vulnerable regions around:
#   - L253: XML parsing (XXE)
#   - L423: OS command construction
#   - L453: Dynamic code execution
#   - L697: Loop bounds from user input
#   - L920: Path construction from user input
#   - L956: URL construction from user input
#
# Integrate these functions into your existing views.py, replacing the
# corresponding vulnerable implementations while preserving other logic.

import os
import shlex
import subprocess
from pathlib import Path
from typing import Iterable

from django.conf import settings
from django.core.exceptions import SuspiciousFileOperation
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from defusedxml import ElementTree as DefusedET  # safe XML parsing


# ---------------------------------------------------------------------------
# Safe XML parsing  fixes "Disable access to external entities in XML parsing."
#   (originally around L253)
# ---------------------------------------------------------------------------

def parse_user_xml(request: HttpRequest) -> HttpResponse:
    """
    Safely parse user-supplied XML without allowing external entities (XXE).

    Original issue:
      - Using xml.etree.ElementTree.fromstring or similar directly on
        user-controlled XML, with XXE enabled.

    Fix:
      - Use defusedxml.ElementTree to disable external entities and
        dangerous constructions.
    """
    if request.method != "POST":
        return HttpResponseBadRequest("Invalid method.")

    xml_data = request.body.decode("utf-8", errors="replace").strip()
    if not xml_data:
        return HttpResponseBadRequest("Empty XML payload.")

    try:
        root = DefusedET.fromstring(xml_data)
    except DefusedET.ParseError:
        return HttpResponseBadRequest("Invalid XML.")
    # Process the XML safely using 'root' (read-only style, no external fetches)
    # Example: extract simple fields
    items: Iterable[str] = [elem.text or "" for elem in root.iterfind(".//item")]
    return JsonResponse({"items": list(items)})


# ---------------------------------------------------------------------------
# Safe OS command execution  fixes "construct the OS command from
# user-controlled data." (originally around L423)
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS = {
    "whoami": ["/usr/bin/whoami", "/bin/whoami"],
    "date": ["/usr/bin/date", "/bin/date"],
    "uptime": ["/usr/bin/uptime", "/usr/bin/uptime"],
}


def _resolve_command_name(name: str) -> list[str]:
    cmd = (name or "").strip().lower()
    if cmd not in ALLOWED_COMMANDS:
        raise ValueError("Unsupported command")

    for path in ALLOWED_COMMANDS[cmd]:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return [path]
    raise ValueError("Command not executable on this system")


def run_diagnostics(request: HttpRequest) -> HttpResponse:
    """
    Execute a whitelisted diagnostic OS command.

    Original issue:
      - Built an OS command string directly from user input and executed
        it via os.system or subprocess with shell=True.

    Fix:
      - Whitelist command names.
      - Use subprocess.run with args list and shell=False.
    """
    if request.method != "POST":
        return HttpResponseBadRequest("Invalid method.")

    cmd_name = request.POST.get("cmd", "")
    try:
        cmd = _resolve_command_name(cmd_name)
    except ValueError:
        return HttpResponseBadRequest("Command not allowed.")

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.SubprocessError:
        return HttpResponse("Command execution failed.", status=500)

    return JsonResponse(
        {
            "command": cmd_name,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "returncode": completed.returncode,
        }
    )


# ---------------------------------------------------------------------------
# Safe dynamic expression handling  fixes "dynamically execute code
# influenced by user-controlled data." (originally around L453)
# ---------------------------------------------------------------------------


def _safe_math_expression(expr: str) -> str:
    """
    Extremely restricted expression evaluator for arithmetic only.

    Allowed:
      - digits
      - whitespace
      - + - * / ( )
    """
    expr = (expr or "").strip()
    if not expr:
        raise ValueError("Empty expression")

    allowed_chars = set("0123456789+-*/() ")
    if any(ch not in allowed_chars for ch in expr):
        raise ValueError("Unsupported characters in expression")

    # Evaluate with builtins removed
    try:
        result = eval(expr, {"__builtins__": {}}, {})
    except Exception as exc:
        raise ValueError("Invalid expression") from exc

    return str(result)


def calc_view(request: HttpRequest) -> HttpResponse:
    """
    Demonstration calculator that avoids arbitrary code execution.

    Original issue:
      - Used eval/exec on raw user input.

    Fix:
      - Restrict to arithmetic expressions only, validated via whitelist.
    """
    if request.method != "POST":
        return HttpResponseBadRequest("Invalid method.")

    expr = request.POST.get("expr", "")
    try:
        result = _safe_math_expression(expr)
    except ValueError as exc:
        return HttpResponseBadRequest(str(exc))

    return JsonResponse({"expr": expr, "result": result})


# ---------------------------------------------------------------------------
# Safe loop bounds  fixes "set loop bounds directly from user-controlled
# data." (originally around L697)
# ---------------------------------------------------------------------------

MAX_LOOP = 10_000  # hard upper limit to avoid DoS via large loop bounds


def limited_loop_view(request: HttpRequest) -> HttpResponse:
    """
    Use a safe upper bound for any loop count derived from user input.

    Original issue:
      - for i in range(int(request.GET['n'])): ...
        allowing unbounded loops from user input.

    Fix:
      - Validate that n is an integer within [0, MAX_LOOP].
    """
    raw_n = request.GET.get("n", "")
    try:
        n = int(raw_n)
    except (TypeError, ValueError):
        return HttpResponseBadRequest("Invalid n")

    if n < 0 or n > MAX_LOOP:
        return HttpResponseBadRequest("n out of allowed range")

    # Example: produce a trivial sequence
    values = list(range(n))
    return JsonResponse({"count": n, "values": values})


# ---------------------------------------------------------------------------
# Safe path handling  fixes "construct the path from user-controlled data."
#   (originally around L920)
# ---------------------------------------------------------------------------

SAFE_BASE_DIR = Path(settings.BASE_DIR) / "user_content"


def _safe_join_user_path(relative: str) -> Path:
    """
    Join an untrusted relative path to SAFE_BASE_DIR safely.

    - Normalizes the path.
    - Ensures the final resolved path remains within SAFE_BASE_DIR.
    - Rejects absolute paths and attempts at traversal.
    """
    rel = (relative or "").strip()
    if not rel:
        raise SuspiciousFileOperation("Empty path")

    # Disallow absolute paths
    if os.path.isabs(rel):
        raise SuspiciousFileOperation("Absolute paths are not allowed")

    # Normalization
    candidate = (SAFE_BASE_DIR / rel).resolve()

    # Enforce base directory constraint
    try:
        candidate.relative_to(SAFE_BASE_DIR)
    except ValueError:
        raise SuspiciousFileOperation("Path traversal detected")

    return candidate


def serve_user_file(request: HttpRequest) -> HttpResponse:
    """
    Serve a file from SAFE_BASE_DIR based on a user-supplied relative path.

    Original issue:
      - Directly concatenated user-supplied file/path to get a filesystem path,
        allowing directory traversal or access outside intended directory.

    Fix:
      - Normalize and constrain the path to SAFE_BASE_DIR.
    """
    rel_path = request.GET.get("path", "")
    try:
        file_path = _safe_join_user_path(rel_path)
    except SuspiciousFileOperation:
        return HttpResponseBadRequest("Invalid path")

    if not file_path.exists() or not file_path.is_file():
        return HttpResponseBadRequest("File not found")

    # For brevity, return basic content; in the real app, use Django's
    # FileResponse or serve_static appropriately.
    with file_path.open("rb") as f:
        data = f.read()
    return HttpResponse(data, content_type="application/octet-stream")


# ---------------------------------------------------------------------------
# Safe redirect / URL construction  fixes "construct the URL from
# user-controlled data." (originally around L956)
# ---------------------------------------------------------------------------

ALLOWED_REDIRECT_PATHS = {
    "home": "home",  # Django named URL
    "profile": "profile",
    "dashboard": "dashboard",
}


def safe_redirect_view(request: HttpRequest) -> HttpResponse:
    """
    Redirect based on a user-provided target, but use a whitelist of
    allowed, named URLs instead of raw user-supplied URLs.

    Original issue:
      - redirect(request.GET['next']) or similar, allowing open redirect.

    Fix:
      - Accept a short token (e.g., 'home', 'profile') and map it to a
      
