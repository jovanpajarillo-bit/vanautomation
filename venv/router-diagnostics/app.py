"""
Router Diagnostics - Flask backend
Connects to a Cisco router in EVE-NG over Telnet (console port) and runs show commands.

Run:  python app.py      then open http://127.0.0.1:5000
Only needs Flask (no telnetlib, so it also works on Python 3.13+).
"""
import re
import socket
import time

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ---- Defaults shown in the UI (change to match your EVE-NG node) ----
DEFAULT_HOST = "192.168.50.31"   # EVE-NG VM IP (VirtualBox)
DEFAULT_PORT = 32770             # telnet port of the router node in EVE-NG
DEFAULT_COMMANDS = [
    "show version",
    "show ip interface brief",
    "show running-config",
]

# ---- Telnet protocol bytes ----
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240

PROMPT_RE = re.compile(r"[\w.\-/()]+[>#]\s*$")
USER_RE = re.compile(r"[Uu]sername:\s*$")
PASS_RE = re.compile(r"[Pp]assword:\s*$")
MORE_RE = re.compile(r"--\s?More\s?--")


class TelnetSession:
    def __init__(self, host: str, port: int, timeout: float = 8):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(1.0)

    # --- low level ---
    def _strip_iac(self, data: bytes) -> str:
        out, i = bytearray(), 0
        while i < len(data):
            b = data[i]
            if b == IAC and i + 1 < len(data):
                cmd = data[i + 1]
                if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data):
                    opt = data[i + 2]
                    if cmd == DO:
                        self.sock.sendall(bytes([IAC, WONT, opt]))
                    elif cmd == WILL:
                        self.sock.sendall(bytes([IAC, DONT, opt]))
                    i += 3
                    continue
                if cmd == SB:
                    end = data.find(bytes([IAC, SE]), i)
                    i = end + 2 if end != -1 else len(data)
                    continue
                if cmd == IAC:
                    out.append(255)
                i += 2
                continue
            out.append(b)
            i += 1
        return out.decode("utf-8", "ignore")

    def send(self, text: str):
        self.sock.sendall(text.encode() + b"\r\n")

    def read_until(self, patterns, timeout: float = 20):
        """Read until the tail of the buffer matches one of the patterns."""
        buf, end = "", time.time() + timeout
        while time.time() < end:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
            except socket.timeout:
                chunk = b""
            if chunk:
                buf += self._strip_iac(chunk)
                if MORE_RE.search(buf[-40:]):
                    self.sock.sendall(b" ")
            for idx, pat in enumerate(patterns):
                if pat.search(buf):
                    return buf, idx
        return buf, -1

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def login(t: TelnetSession, username: str, password: str, enable: str):
    """Get to a privileged prompt (#). Handles empty consoles and login prompts."""
    t.send("")
    buf, idx = t.read_until([USER_RE, PASS_RE, PROMPT_RE], timeout=6)
    if idx == -1:
        t.send("")
        buf, idx = t.read_until([USER_RE, PASS_RE, PROMPT_RE], timeout=6)

    for _ in range(4):
        if idx == 0:
            t.send(username)
        elif idx == 1:
            t.send(password)
        elif idx == 2:
            break
        else:
            raise RuntimeError("No prompt from the router. Is the node started and the port correct?")
        buf, idx = t.read_until([USER_RE, PASS_RE, PROMPT_RE], timeout=8)

    if buf.rstrip().endswith(">"):
        t.send("enable")
        buf, idx = t.read_until([PASS_RE, PROMPT_RE], timeout=6)
        if idx == 0:
            t.send(enable)
            buf, idx = t.read_until([PASS_RE, PROMPT_RE], timeout=6)
        if not buf.rstrip().endswith("#"):
            raise RuntimeError("Could not enter enable mode. Check the enable password.")


def run_command(t: TelnetSession, command: str) -> str:
    t.send(command)
    buf, _ = t.read_until([PROMPT_RE], timeout=30)
    lines = buf.replace("\r", "").split("\n")
    if lines and command in lines[0]:
        lines = lines[1:]                      # drop echoed command
    if lines and PROMPT_RE.search(lines[-1]):
        lines = lines[:-1]                     # drop trailing prompt
    return "\n".join(lines).strip()


@app.route("/")
def index():
    return render_template(
        "index.html",
        host=DEFAULT_HOST,
        port=DEFAULT_PORT,
        commands=DEFAULT_COMMANDS,
    )


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json(force=True)
    host = str(data.get("host", "")).strip()
    try:
        port = int(data.get("port", 0))
    except ValueError:
        port = 0
    commands = [c.strip() for c in data.get("commands", []) if c.strip()]

    if not host or not (1 <= port <= 65535):
        return jsonify(error="Enter a valid address and port."), 400
    if not commands:
        return jsonify(error="Pick at least one command."), 400
    # Read-only safety: only allow "show ..." commands
    if any(not c.lower().startswith("show ") for c in commands):
        return jsonify(error="Only show commands are allowed."), 400

    results, t = [], None
    try:
        t = TelnetSession(host, port)
        login(t, data.get("username", ""), data.get("password", ""), data.get("enable", ""))
        t.send("terminal length 0")
        t.read_until([PROMPT_RE], timeout=5)

        for cmd in commands:
            start = time.time()
            try:
                output = run_command(t, cmd)
                results.append(dict(command=cmd, ok=True, output=output,
                                    seconds=round(time.time() - start, 1)))
            except Exception as exc:  # noqa: BLE001
                results.append(dict(command=cmd, ok=False, output=str(exc),
                                    seconds=round(time.time() - start, 1)))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return jsonify(error=f"Could not reach {host}:{port}. {exc}"), 502
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 502
    finally:
        if t:
            t.close()

    return jsonify(results=results)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
