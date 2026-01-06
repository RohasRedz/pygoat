import os
import shlex
import subprocess
from typing import List
from flask import Flask, request, render_template, abort

app = Flask(__name__)

ALLOWED_COMMANDS = {
    "ls": ["/bin/ls", "/usr/bin/ls"],
    "whoami": ["/usr/bin/whoami"],
    "date": ["/bin/date", "/usr/bin/date"],
}


def _resolve_command(user_cmd: str) -> List[str]:
    """
    Map a simple, whitelisted command name to an actual executable path.

    Prevents arbitrary command execution.
    """
    cmd = (user_cmd or "").strip().lower()
    if cmd not in ALLOWED_COMMANDS:
        raise ValueError("Command not allowed.")

    for path in ALLOWED_COMMANDS[cmd]:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return [path]

    raise ValueError("Configured command is not executable on this system.")


def _safe_eval_expression(expr: str) -> str:
    """
    Extremely restricted evaluator for demo only.

    Only allows arithmetic expressions using digits and + - * / ( ).
    """
    expr = (expr or "").strip()
    if not expr:
        raise ValueError("Empty expression")

    allowed_chars = set("0123456789+-*/() ")
    if any(ch not in allowed_chars for ch in expr):
        raise ValueError("Unsupported characters in expression")

    try:
        result = eval(expr, {"__builtins__": {}}, {})
    except Exception as exc:
        raise ValueError("Invalid expression") from exc

    return str(result)


@app.route("/run-command", methods=["POST"])
def run_command():
    """
    FIX for: 'Change this code to not construct the OS command from user-controlled data.'

    Original pattern (insecure):
        cmd = request.form['cmd']
        os.system("sh -c '%s'" % cmd)

    Fixed:
      - Whitelist command names only.
      - Use subprocess.run with a list and shell=False.
    """
    user_cmd = request.form.get("cmd")
    try:
        cmd_list = _resolve_command(user_cmd)
    except ValueError as exc:
        return render_template("command.html", error=str(exc)), 400

    try:
        completed = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.SubprocessError:
        return render_template("command.html", error="Command execution failed."), 500

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    return render_template("command.html", command=user_cmd, stdout=stdout, stderr=stderr)


@app.route("/calc", methods=["POST"])
def calc():
    """
    FIX for: 'Change this code to not dynamically execute code influenced by user-controlled data.'

    Original pattern (insecure):
        expr = request.form['expr']
        result = eval(expr)

    Fixed:
      - Implement a restricted, whitelisted evaluator.
      - Reject any unexpected characters or constructs.
    """
    expr = request.form.get("expr", "")
    try:
        result = _safe_eval_expression(expr)
    except ValueError as exc:
        return render_template("calc.html", error=str(exc)), 400

    return render_template("calc.html", expr=expr, result=result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
