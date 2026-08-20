#!/usr/bin/env python3
import base64
import hashlib
import hmac
import html
import io
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
import re
from datetime import datetime, timezone
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server


APP_ROOT = Path(__file__).resolve().parent
DATA_DIR = APP_ROOT / "data"
DB_PATH = Path(os.environ.get("MYTAIL_DB_PATH", DATA_DIR / "mytail.db"))


def env_or_file(name, default=""):
    value = os.environ.get(name)
    if value is not None:
        return value
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    return default


APP_URL = os.environ.get("APP_URL", "https://support.innexo.solutions")
SESSION_COOKIE = os.environ.get("SESSION_COOKIE_NAME", "mytail_session")
SESSION_SECRET = env_or_file("SESSION_SECRET", "change-me-session-secret")
OPERATOR_EMAIL = os.environ.get("OPERATOR_EMAIL", "operator@innexo.local")
OPERATOR_PASSWORD = env_or_file("OPERATOR_PASSWORD", "change-me-operator-password")
DEFAULT_DURATIONS = os.environ.get("DEFAULT_ACCESS_DURATIONS", "15,30,60,120")
PORT = int(os.environ.get("PORT", "8080"))
RELAY_HOST = os.environ.get("RELAY_HOST", "relay.hirableaiagents.com")
RELAY_SSH_PORT = int(os.environ.get("RELAY_SSH_PORT", "22"))
RELAY_USER = os.environ.get("RELAY_USER", "mytail-relay")
RELAY_TRANSPORT = os.environ.get("RELAY_TRANSPORT", "direct")
RELAY_PORT_BASE = int(os.environ.get("RELAY_PORT_BASE", "22000"))
RELAY_PORT_MAX = int(os.environ.get("RELAY_PORT_MAX", "29999"))
RELAY_KNOWN_HOSTS = env_or_file("RELAY_KNOWN_HOSTS", "")
RELAY_AUTHORIZED_KEYS = os.environ.get("RELAY_AUTHORIZED_KEYS", "")
OPERATOR_KNOWN_HOSTS = os.environ.get("OPERATOR_KNOWN_HOSTS", "")
OPERATOR_SSH_PUBLIC_KEY = env_or_file("OPERATOR_SSH_PUBLIC_KEY", "")
SSH_KEY_RE = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]{40,1200}(?: .{0,200})?$")
REMOTE_USER_RE = re.compile(r"^[A-Za-z0-9_.@\\-]{1,80}$")
relay_keys_lock = threading.Lock()
login_attempts = {}
login_attempts_lock = threading.Lock()


def now_utc():
    return datetime.now(timezone.utc)


def now_ts():
    return int(time.time())


def format_dt(ts):
    if not ts:
        return "n/a"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def parse_duration_list(raw):
    values = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            minutes = int(item)
        except ValueError:
            continue
        if 5 <= minutes <= 480:
            values.append(minutes)
    return values or [15, 30, 60, 120]


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    ensure_data_dir()
    conn = db()
    cur = conn.cursor()
    cur.executescript(
        """
        pragma journal_mode = wal;

        create table if not exists machines (
            id integer primary key autoincrement,
            customer_name text not null,
            machine_name text not null,
            machine_token text not null unique,
            consent_code text not null unique,
            notes text not null default '',
            created_at integer not null,
            last_seen_at integer,
            last_ip text
        );

        create table if not exists access_requests (
            id integer primary key autoincrement,
            machine_id integer not null references machines(id) on delete cascade,
            operator_email text not null,
            reason text not null,
            requested_minutes integer not null,
            status text not null,
            consent_token text not null unique,
            created_at integer not null,
            responded_at integer,
            approved_minutes integer,
            expires_at integer,
            requested_by_ip text
        );

        create table if not exists audit_events (
            id integer primary key autoincrement,
            machine_id integer,
            access_request_id integer,
            event_type text not null,
            actor text not null,
            details_json text not null,
            created_at integer not null
        );
        """
    )
    columns = {row[1] for row in cur.execute("pragma table_info(machines)")}
    migrations = {
        "ssh_public_key": "alter table machines add column ssh_public_key text",
        "remote_user": "alter table machines add column remote_user text",
        "platform": "alter table machines add column platform text",
        "relay_port": "alter table machines add column relay_port integer",
        "relay_key_updated_at": "alter table machines add column relay_key_updated_at integer",
        "local_ssh_host_key": "alter table machines add column local_ssh_host_key text",
    }
    for column, statement in migrations.items():
        if column not in columns:
            cur.execute(statement)
    conn.commit()
    conn.close()
    sync_relay_authorized_keys()


def valid_ssh_public_key(value):
    return bool(value and SSH_KEY_RE.fullmatch(value.strip()))


def relay_authorized_key_line(machine):
    key = (machine["ssh_public_key"] or "").strip()
    port = machine["relay_port"]
    if not key or not port or not valid_ssh_public_key(key):
        return None
    options = f'restrict,port-forwarding,permitlisten="127.0.0.1:{port}"'
    key_parts = key.split()
    return f"{options} {key_parts[0]} {key_parts[1]} mytail-machine-{machine['id']}"


def sync_relay_authorized_keys():
    if not RELAY_AUTHORIZED_KEYS and not OPERATOR_KNOWN_HOSTS:
        return
    with relay_keys_lock:
        conn = db()
        machines = conn.execute("select id, ssh_public_key, local_ssh_host_key, relay_port from machines order by id").fetchall()
        conn.close()
        if RELAY_AUTHORIZED_KEYS:
            lines = [line for machine in machines if (line := relay_authorized_key_line(machine))]
            target = Path(RELAY_AUTHORIZED_KEYS)
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_suffix(".tmp")
            temporary.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            # OpenSSH reads this after dropping to the relay account. The file
            # contains public keys only; restrictions are part of every line.
            os.chmod(temporary, 0o644)
            os.replace(temporary, target)
        if OPERATOR_KNOWN_HOSTS:
            lines = []
            for machine in machines:
                key = (machine["local_ssh_host_key"] or "").strip()
                if valid_ssh_public_key(key):
                    parts = key.split()
                    lines.append(f"mytail-machine-{machine['id']} {parts[0]} {parts[1]}")
            target = Path(OPERATOR_KNOWN_HOSTS)
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_suffix(".tmp")
            temporary.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)


def audit(event_type, actor, machine_id=None, access_request_id=None, **details):
    conn = db()
    conn.execute(
        """
        insert into audit_events (
            machine_id, access_request_id, event_type, actor, details_json, created_at
        ) values (?, ?, ?, ?, ?, ?)
        """,
        (
            machine_id,
            access_request_id,
            event_type,
            actor,
            json.dumps(details, separators=(",", ":")),
            now_ts(),
        ),
    )
    conn.commit()
    conn.close()


def sign_session(payload):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{encoded}.{sig}"


def unsign_session(token):
    try:
        encoded, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = hmac.new(SESSION_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    padding = "=" * (-len(encoded) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(encoded + padding))
    except Exception:
        return None
    if data.get("exp", 0) < now_ts():
        return None
    return data


def parse_cookies(environ):
    jar = cookies.SimpleCookie()
    raw = environ.get("HTTP_COOKIE", "")
    if raw:
        jar.load(raw)
    return jar


def get_operator(environ):
    jar = parse_cookies(environ)
    morsel = jar.get(SESSION_COOKIE)
    if not morsel:
        return None
    return unsign_session(morsel.value)


def html_response(start_response, body, status="200 OK", headers=None):
    payload = body.encode("utf-8")
    response_headers = [
        ("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(payload))),
        ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
        ("Referrer-Policy", "no-referrer"), ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"), ("Cache-Control", "no-store"),
    ]
    if headers:
        response_headers.extend(headers)
    start_response(status, response_headers)
    return [payload]


def json_response(start_response, payload, status="200 OK", headers=None):
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    response_headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    if headers:
        response_headers.extend(headers)
    start_response(status, response_headers)
    return [body]


def redirect(start_response, location, headers=None):
    response_headers = [("Location", location)]
    if headers:
        response_headers.extend(headers)
    start_response("303 See Other", response_headers)
    return [b""]


def not_found(start_response):
    return html_response(start_response, render_page("Not Found", "<p>Route not found.</p>"), "404 Not Found")


def forbidden(start_response, message="Forbidden"):
    return html_response(start_response, render_page("Forbidden", f"<p>{html.escape(message)}</p>"), "403 Forbidden")


def read_body(environ):
    size = int(environ.get("CONTENT_LENGTH") or "0")
    return environ["wsgi.input"].read(size)


def parse_form(environ):
    body = read_body(environ)
    return {k: v[0] for k, v in parse_qs(body.decode("utf-8")).items()}


def operator_csrf_valid(operator, form):
    return bool(operator and hmac.compare_digest(str(operator.get("csrf", "")), str(form.get("csrf", ""))))


def request_ip(environ):
    forwarded = environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
    return forwarded or environ.get("REMOTE_ADDR", "")


def badge(status):
    cls = {
        "pending": "warn",
        "approved": "ok",
        "rejected": "bad",
        "expired": "muted",
    }.get(status, "muted")
    return f'<span class="badge {cls}">{html.escape(status)}</span>'


def render_page(title, body, operator=None):
    nav = ""
    if operator:
        nav = (
            '<nav class="topnav">'
            '<a href="/app">Machines</a>'
            '<a href="/app/audit">Audit</a>'
            '<a href="/logout">Logout</a>'
            "</nav>"
        )
    shell = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} • MyTail</title>
  <style>
    :root {{
      --bg: #f5efe3;
      --ink: #1d2a24;
      --panel: rgba(255,255,255,0.86);
      --line: rgba(29,42,36,0.14);
      --accent: #0f766e;
      --accent-2: #b45309;
      --ok: #166534;
      --warn: #b45309;
      --bad: #b91c1c;
      --muted: #5b665f;
      --shadow: 0 24px 60px rgba(44, 38, 24, 0.14);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(15,118,110,0.18), transparent 35%),
        radial-gradient(circle at top right, rgba(180,83,9,0.18), transparent 30%),
        linear-gradient(180deg, #f6f1e7 0%, #ece4d2 100%);
      min-height: 100vh;
    }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .wrap {{ max-width: 1120px; margin: 0 auto; padding: 32px 20px 48px; }}
    .hero {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 18px;
      margin-bottom: 24px;
    }}
    .brand {{ font-size: 13px; letter-spacing: 0.22em; text-transform: uppercase; color: var(--muted); }}
    h1 {{ margin: 8px 0 10px; font-size: clamp(2rem, 3vw, 3.2rem); line-height: 0.95; }}
    .lede {{ max-width: 760px; color: var(--muted); font-size: 1.02rem; line-height: 1.55; }}
    .topnav {{ display: flex; gap: 14px; flex-wrap: wrap; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
      border-radius: 24px;
      padding: 22px;
      backdrop-filter: blur(8px);
      margin-bottom: 18px;
    }}
    .grid {{ display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
    .stats {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin-top: 14px; }}
    .stat {{
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 14px;
      background: rgba(255,255,255,0.58);
    }}
    .stat strong {{ display: block; font-size: 1.45rem; margin-bottom: 4px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.96rem; }}
    th, td {{ text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: normal; font-size: 0.84rem; text-transform: uppercase; letter-spacing: 0.08em; }}
    form {{ display: grid; gap: 12px; }}
    label {{ display: grid; gap: 6px; font-size: 0.95rem; }}
    input, textarea, select, button {{
      font: inherit;
      border-radius: 14px;
      border: 1px solid var(--line);
      padding: 12px 14px;
      background: rgba(255,255,255,0.94);
      color: var(--ink);
    }}
    textarea {{ min-height: 96px; resize: vertical; }}
    button {{
      background: linear-gradient(135deg, var(--accent), #155e75);
      color: white;
      border: none;
      cursor: pointer;
    }}
    button.secondary {{
      background: transparent;
      color: var(--ink);
      border: 1px solid var(--line);
    }}
    .row {{ display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }}
    .badge {{
      display: inline-block;
      padding: 5px 10px;
      border-radius: 999px;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.09em;
      background: rgba(29,42,36,0.08);
    }}
    .badge.ok {{ background: rgba(22,101,52,0.12); color: var(--ok); }}
    .badge.warn {{ background: rgba(180,83,9,0.12); color: var(--warn); }}
    .badge.bad {{ background: rgba(185,28,28,0.12); color: var(--bad); }}
    .badge.muted {{ background: rgba(29,42,36,0.08); color: var(--muted); }}
    .flash {{
      margin-bottom: 16px;
      border-radius: 16px;
      padding: 12px 14px;
      background: rgba(15,118,110,0.1);
      color: var(--accent);
      border: 1px solid rgba(15,118,110,0.15);
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 9px 12px;
      background: rgba(255,255,255,0.72);
      margin: 6px 8px 0 0;
    }}
    .muted {{ color: var(--muted); }}
    .actions {{ display: flex; gap: 10px; flex-wrap: wrap; }}
    @media (max-width: 720px) {{
      .hero {{ display: block; }}
      .topnav {{ margin-top: 10px; }}
      .panel {{ padding: 18px; border-radius: 18px; }}
      th:nth-child(4), td:nth-child(4) {{ display: none; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <div class="brand">MyTail Consent Broker</div>
        <h1>{html.escape(title)}</h1>
        <p class="lede">Operator-initiated support access with explicit customer approval, selectable access windows, auditability, and a safe integration point for a visible Windows agent.</p>
      </div>
      {nav}
    </section>
    {body}
  </div>
</body>
</html>"""
    return shell


def fetch_machine(machine_id):
    conn = db()
    row = conn.execute("select * from machines where id = ?", (machine_id,)).fetchone()
    conn.close()
    return row


def fetch_request_by_token(token):
    conn = db()
    row = conn.execute(
        """
        select r.*, m.customer_name, m.machine_name, m.consent_code
        from access_requests r
        join machines m on m.id = r.machine_id
        where r.consent_token = ?
        """,
        (token,),
    ).fetchone()
    conn.close()
    return row


def issue_request(machine_id, operator_email, reason, requested_minutes, ip_addr):
    token = secrets.token_urlsafe(24)
    conn = db()
    cur = conn.execute(
        """
        insert into access_requests (
            machine_id, operator_email, reason, requested_minutes, status,
            consent_token, created_at, requested_by_ip
        ) values (?, ?, ?, ?, 'pending', ?, ?, ?)
        """,
        (machine_id, operator_email, reason, requested_minutes, token, now_ts(), ip_addr),
    )
    request_id = cur.lastrowid
    conn.commit()
    conn.close()
    audit(
        "request.created",
        operator_email,
        machine_id=machine_id,
        access_request_id=request_id,
        reason=reason,
        requested_minutes=requested_minutes,
        requested_by_ip=ip_addr,
    )
    return token, request_id


def expunge_expired_requests():
    conn = db()
    cur = conn.execute(
        """
        update access_requests
        set status = 'expired'
        where status = 'approved' and expires_at is not null and expires_at < ?
        """,
        (now_ts(),),
    )
    changed = cur.rowcount
    conn.commit()
    conn.close()
    return changed


def render_login(error=""):
    flash = f'<div class="flash">{html.escape(error)}</div>' if error else ""
    body = f"""
    <section class="panel" style="max-width: 460px;">
      {flash}
      <form method="post" action="/login">
        <label>Email
          <input type="email" name="email" value="{html.escape(OPERATOR_EMAIL)}" required>
        </label>
        <label>Password
          <input type="password" name="password" required>
        </label>
        <button type="submit">Login</button>
      </form>
    </section>
    """
    return render_page("Operator Login", body)


def app_dashboard(operator, flash=""):
    expunge_expired_requests()
    conn = db()
    stats = conn.execute(
        """
        select
          (select count(*) from machines) as machines,
          (select count(*) from access_requests where status = 'pending') as pending,
          (select count(*) from access_requests where status = 'approved' and expires_at >= ?) as active,
          (select count(*) from access_requests where status = 'rejected') as rejected
        """,
        (now_ts(),),
    ).fetchone()
    machines = conn.execute(
        """
        select
          m.*,
          (
            select status from access_requests r
            where r.machine_id = m.id
            order by r.created_at desc
            limit 1
          ) as latest_status,
          (
            select created_at from access_requests r
            where r.machine_id = m.id
            order by r.created_at desc
            limit 1
          ) as latest_request_at
        from machines m
        order by m.created_at desc
        """
    ).fetchall()
    requests = conn.execute(
        """
        select
          r.*, m.customer_name, m.machine_name, m.relay_port
        from access_requests r
        join machines m on m.id = r.machine_id
        order by r.created_at desc
        limit 20
        """
    ).fetchall()
    conn.close()

    flash_html = f'<div class="flash">{html.escape(flash)}</div>' if flash else ""
    machine_rows = []
    for machine in machines:
        machine_rows.append(
            "<tr>"
            f"<td><strong>{html.escape(machine['customer_name'])}</strong><br><span class='muted'>{html.escape(machine['machine_name'])}</span></td>"
            f"<td><code>{html.escape(machine['consent_code'])}</code></td>"
            f"<td>{badge(machine['latest_status'] or 'idle')}</td>"
            f"<td>{format_dt(machine['last_seen_at'])}</td>"
            f"<td>{format_dt(machine['latest_request_at'])}</td>"
            "<td>"
            f"<form method='post' action='/app/requests' style='display:grid;gap:8px;'>"
            f"<input type='hidden' name='csrf' value='{html.escape(operator['csrf'])}'>"
            f"<input type='hidden' name='machine_id' value='{machine['id']}'>"
            "<input type='text' name='reason' placeholder='Explain why access is needed' required>"
            f"<select name='requested_minutes'>{''.join(f'<option value=\"{d}\">{d} minutes</option>' for d in parse_duration_list(DEFAULT_DURATIONS))}</select>"
            "<button type='submit'>Request Access</button>"
            "</form>"
            "</td>"
            "</tr>"
        )
    request_rows = []
    for request in requests:
        consent_url = f"{APP_URL}/consent/{request['consent_token']}"
        active_note = ""
        if request["status"] == "approved":
            command = (
                "ssh -i /etc/mytail/operator/operator_ed25519 "
                f"-o HostKeyAlias=mytail-machine-{request['machine_id']} "
                "-o UserKnownHostsFile=/var/lib/mytail-operator/known_hosts "
                f"-p {request['relay_port']} mytail-admin@127.0.0.1"
            )
            active_note = (
                f"<br><span class='muted'>Expires {format_dt(request['expires_at'])}</span>"
                f"<br><code>{html.escape(command)}</code>"
            )
        request_rows.append(
            "<tr>"
            f"<td><strong>{html.escape(request['customer_name'])}</strong><br><span class='muted'>{html.escape(request['machine_name'])}</span></td>"
            f"<td>{badge(request['status'])}{active_note}</td>"
            f"<td>{html.escape(request['reason'])}</td>"
            f"<td>{request['requested_minutes']} min</td>"
            f"<td>{format_dt(request['created_at'])}</td>"
            f"<td><a href='{html.escape(consent_url)}'>{html.escape(consent_url)}</a></td>"
            "</tr>"
        )

    body = f"""
    {flash_html}
    <section class="panel">
      <div class="row" style="justify-content: space-between;">
        <div>
          <strong>Operator</strong><br>
          <span class="muted">{html.escape(operator['email'])}</span>
        </div>
        <div class="actions">
          <a class="pill" href="/app/audit">Open audit trail</a>
          <a class="pill" href="/health">Health endpoint</a>
        </div>
      </div>
      <div class="stats">
        <div class="stat"><strong>{stats['machines']}</strong>Machines</div>
        <div class="stat"><strong>{stats['pending']}</strong>Pending approvals</div>
        <div class="stat"><strong>{stats['active']}</strong>Active windows</div>
        <div class="stat"><strong>{stats['rejected']}</strong>Rejected requests</div>
      </div>
    </section>

    <div class="grid">
      <section class="panel">
        <h2>Enroll a machine</h2>
        <form method="post" action="/app/machines">
          <input type="hidden" name="csrf" value="{html.escape(operator['csrf'])}">
          <label>Customer name
            <input type="text" name="customer_name" required>
          </label>
          <label>Machine name
            <input type="text" name="machine_name" required>
          </label>
          <label>Notes
            <textarea name="notes" placeholder="Visible context for the operator and customer"></textarea>
          </label>
          <button type="submit">Create enrollment</button>
        </form>
      </section>

      <section class="panel">
        <h2>Agent security contract</h2>
        <div class="pill">Control outbound over HTTPS; relay outbound over SSH</div>
        <div class="pill">Customer-visible consent dialog every session</div>
        <div class="pill">Customer chooses duration at approval time</div>
        <div class="pill">Operator public key stays in memory only while approved</div>
        <div class="pill">Loopback-only privileged SSH endpoint</div>
        <div class="pill">Tunnel and authorization expire automatically</div>
      </section>
    </div>

    <section class="panel">
      <h2>Machines</h2>
      <table>
        <thead>
          <tr>
            <th>Machine</th>
            <th>Consent Code</th>
            <th>Status</th>
            <th>Last Seen</th>
            <th>Latest Request</th>
            <th>Request</th>
          </tr>
        </thead>
        <tbody>
          {''.join(machine_rows) or '<tr><td colspan="6">No machines enrolled yet.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Recent access requests</h2>
      <table>
        <thead>
          <tr>
            <th>Machine</th>
            <th>Status</th>
            <th>Reason</th>
            <th>Requested</th>
            <th>Created</th>
            <th>Consent Link</th>
          </tr>
        </thead>
        <tbody>
          {''.join(request_rows) or '<tr><td colspan="6">No requests yet.</td></tr>'}
        </tbody>
      </table>
    </section>
    """
    return render_page("Operator Console", body, operator=operator)


def audit_page(operator):
    conn = db()
    events = conn.execute(
        """
        select
          a.*,
          m.customer_name,
          m.machine_name
        from audit_events a
        left join machines m on m.id = a.machine_id
        order by a.created_at desc
        limit 100
        """
    ).fetchall()
    conn.close()
    rows = []
    for event in events:
        rows.append(
            "<tr>"
            f"<td>{format_dt(event['created_at'])}</td>"
            f"<td>{html.escape(event['event_type'])}</td>"
            f"<td>{html.escape(event['actor'])}</td>"
            f"<td>{html.escape((event['customer_name'] or '-') + ' / ' + (event['machine_name'] or '-'))}</td>"
            f"<td><code>{html.escape(event['details_json'])}</code></td>"
            "</tr>"
        )
    body = f"""
    <section class="panel">
      <h2>Audit Trail</h2>
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Event</th>
            <th>Actor</th>
            <th>Machine</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows) or '<tr><td colspan="5">No audit events yet.</td></tr>'}
        </tbody>
      </table>
    </section>
    """
    return render_page("Audit Trail", body, operator=operator)


def consent_page(request_row, error=""):
    durations = parse_duration_list(DEFAULT_DURATIONS)
    options = "".join(
        f"<option value='{d}'>{d} minutes</option>" for d in durations
    )
    flash = f'<div class="flash">{html.escape(error)}</div>' if error else ""
    body = f"""
    <section class="panel" style="max-width: 760px;">
      {flash}
      <p><strong>Customer</strong> {html.escape(request_row['customer_name'])}</p>
      <p><strong>Machine</strong> {html.escape(request_row['machine_name'])}</p>
      <p><strong>Operator</strong> {html.escape(request_row['operator_email'])}</p>
      <p><strong>Reason</strong> {html.escape(request_row['reason'])}</p>
      <p><strong>Requested window</strong> {request_row['requested_minutes']} minutes</p>
      <p><strong>Consent code</strong> <code>{html.escape(request_row['consent_code'])}</code></p>
      <p class="muted">The local agent shows this same code so the customer can verify the intended request. Approval temporarily authorizes an administrative SSH session and an outbound reverse tunnel.</p>
      <form method="post" action="/consent/{html.escape(request_row['consent_token'])}/approve">
        <label>Type the consent code shown by your local MyTail agent
          <input name="consent_code" autocomplete="off" required>
        </label>
        <label>How long should access remain active?
          <select name="approved_minutes">{options}</select>
        </label>
        <button type="submit">Allow access</button>
      </form>
      <form method="post" action="/consent/{html.escape(request_row['consent_token'])}/reject">
        <input type="hidden" name="consent_code" value="{html.escape(request_row['consent_code'])}">
        <button class="secondary" type="submit">Reject access</button>
      </form>
    </section>
    """
    return render_page("Approve Support Access", body)


def handle_login(environ, start_response):
    if environ["REQUEST_METHOD"] == "GET":
        return html_response(start_response, render_login())
    form = parse_form(environ)
    email = form.get("email", "")
    password = form.get("password", "")
    remote = request_ip(environ)
    with login_attempts_lock:
        recent = [stamp for stamp in login_attempts.get(remote, []) if stamp > now_ts() - 600]
        login_attempts[remote] = recent
    if len(recent) >= 5:
        return html_response(start_response, render_login("Too many attempts. Try again later."), "429 Too Many Requests")
    if email != OPERATOR_EMAIL or password != OPERATOR_PASSWORD:
        with login_attempts_lock:
            login_attempts.setdefault(remote, []).append(now_ts())
        return html_response(start_response, render_login("Invalid email or password"), "401 Unauthorized")
    with login_attempts_lock:
        login_attempts.pop(remote, None)
    payload = {"email": email, "csrf": secrets.token_urlsafe(24), "exp": now_ts() + 12 * 60 * 60}
    token = sign_session(payload)
    secure = "; Secure" if APP_URL.startswith("https://") else ""
    header = ("Set-Cookie", f"{SESSION_COOKIE}={token}; HttpOnly; Path=/; SameSite=Strict{secure}")
    audit("operator.login", email, remote_ip=request_ip(environ))
    return redirect(start_response, "/app", [header])


def require_operator(environ, start_response):
    operator = get_operator(environ)
    if not operator:
        redirect(start_response, "/login")
        return None
    return operator


def handle_logout(environ, start_response):
    operator = get_operator(environ)
    if operator:
        audit("operator.logout", operator["email"], remote_ip=request_ip(environ))
    header = ("Set-Cookie", f"{SESSION_COOKIE}=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
    return redirect(start_response, "/login", [header])


def handle_machine_create(environ, start_response, operator):
    form = parse_form(environ)
    if not operator_csrf_valid(operator, form):
        return forbidden(start_response, "Invalid or expired form token")
    customer_name = form.get("customer_name", "").strip()
    machine_name = form.get("machine_name", "").strip()
    notes = form.get("notes", "").strip()
    if not customer_name or not machine_name:
        return html_response(start_response, app_dashboard(operator, "Customer and machine name are required."))
    machine_token = secrets.token_urlsafe(24)
    consent_code = secrets.token_hex(3).upper()
    conn = db()
    cur = conn.execute(
        """
        insert into machines (
            customer_name, machine_name, machine_token, consent_code, notes, created_at
        ) values (?, ?, ?, ?, ?, ?)
        """,
        (customer_name, machine_name, machine_token, consent_code, notes, now_ts()),
    )
    machine_id = cur.lastrowid
    relay_port = RELAY_PORT_BASE + machine_id
    if relay_port > RELAY_PORT_MAX:
        conn.rollback()
        conn.close()
        return html_response(start_response, app_dashboard(operator, "Relay port pool is exhausted."), "503 Service Unavailable")
    conn.execute("update machines set relay_port = ? where id = ?", (relay_port, machine_id))
    conn.commit()
    conn.close()
    audit(
        "machine.created",
        operator["email"],
        machine_id=machine_id,
        customer_name=customer_name,
        machine_name=machine_name,
    )
    message = f"Enrollment created. Machine token: {machine_token}. Relay port: {relay_port}"
    return html_response(start_response, app_dashboard(operator, message))


def handle_request_create(environ, start_response, operator):
    form = parse_form(environ)
    if not operator_csrf_valid(operator, form):
        return forbidden(start_response, "Invalid or expired form token")
    machine_id = int(form.get("machine_id", "0") or "0")
    reason = form.get("reason", "").strip()
    requested_minutes = int(form.get("requested_minutes", "0") or "0")
    machine = fetch_machine(machine_id)
    if not machine or not reason or requested_minutes <= 0:
        return html_response(start_response, app_dashboard(operator, "Request payload is incomplete."))
    token, request_id = issue_request(machine_id, operator["email"], reason, requested_minutes, request_ip(environ))
    consent_url = f"{APP_URL}/consent/{token}"
    message = f"Request #{request_id} created. Share this approval URL: {consent_url}"
    return html_response(start_response, app_dashboard(operator, message))


def handle_consent_action(environ, start_response, token, action):
    request_row = fetch_request_by_token(token)
    if not request_row:
        return not_found(start_response)
    if request_row["status"] != "pending":
        return html_response(
            start_response,
            render_page("Request Finalized", f"<section class='panel'><p>This request is already {html.escape(request_row['status'])}.</p></section>"),
        )
    form = parse_form(environ)
    supplied_code = form.get("consent_code", "").strip().upper()
    if not hmac.compare_digest(supplied_code, request_row["consent_code"].upper()):
        return html_response(start_response, consent_page(request_row, "The consent code did not match the local agent."), "400 Bad Request")
    if action == "approve":
        approved_minutes = int(form.get("approved_minutes", "0") or "0")
        if approved_minutes not in parse_duration_list(DEFAULT_DURATIONS):
            return html_response(start_response, consent_page(request_row, "Choose one of the available durations."))
        expires_at = now_ts() + approved_minutes * 60
        conn = db()
        conn.execute(
            """
            update access_requests
            set status = 'approved', responded_at = ?, approved_minutes = ?, expires_at = ?
            where id = ?
            """,
            (now_ts(), approved_minutes, expires_at, request_row["id"]),
        )
        conn.commit()
        conn.close()
        audit(
            "request.approved",
            f"customer:{request_row['customer_name']}",
            machine_id=request_row["machine_id"],
            access_request_id=request_row["id"],
            approved_minutes=approved_minutes,
            expires_at=expires_at,
        )
        body = f"""
        <section class="panel">
          <h2>Access approved</h2>
          <p>The operator can proceed until <strong>{format_dt(expires_at)}</strong>.</p>
          <p class="muted">The local agent should activate only for this request window and should remove operator access automatically when the timer ends.</p>
        </section>
        """
        return html_response(start_response, render_page("Access Approved", body))
    conn = db()
    conn.execute(
        """
        update access_requests
        set status = 'rejected', responded_at = ?
        where id = ?
        """,
        (now_ts(), request_row["id"]),
    )
    conn.commit()
    conn.close()
    audit(
        "request.rejected",
        f"customer:{request_row['customer_name']}",
        machine_id=request_row["machine_id"],
        access_request_id=request_row["id"],
    )
    body = """
    <section class="panel">
      <h2>Access rejected</h2>
      <p>No remote access window has been opened.</p>
    </section>
    """
    return html_response(start_response, render_page("Access Rejected", body))


def api_machine_checkin(environ, start_response):
    if environ["REQUEST_METHOD"] != "POST":
        return json_response(start_response, {"error": "method_not_allowed"}, "405 Method Not Allowed")
    try:
        payload = json.loads(read_body(environ).decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return json_response(start_response, {"error": "invalid_json"}, "400 Bad Request")
    machine_token = payload.get("machine_token", "")
    hostname = payload.get("hostname", "")
    ssh_public_key = payload.get("ssh_public_key", "").strip()
    local_ssh_host_key = payload.get("local_ssh_host_key", "").strip()
    remote_user = payload.get("remote_user", "").strip()
    platform = payload.get("platform", "").strip()[:40]
    if ssh_public_key and not valid_ssh_public_key(ssh_public_key):
        return json_response(start_response, {"error": "invalid_ssh_public_key"}, "400 Bad Request")
    if local_ssh_host_key and not valid_ssh_public_key(local_ssh_host_key):
        return json_response(start_response, {"error": "invalid_local_ssh_host_key"}, "400 Bad Request")
    if remote_user and not REMOTE_USER_RE.fullmatch(remote_user):
        return json_response(start_response, {"error": "invalid_remote_user"}, "400 Bad Request")
    conn = db()
    machine = conn.execute("select * from machines where machine_token = ?", (machine_token,)).fetchone()
    if not machine:
        conn.close()
        return json_response(start_response, {"error": "unknown_machine"}, "403 Forbidden")
    key_changed = bool(
        (ssh_public_key and ssh_public_key != (machine["ssh_public_key"] or ""))
        or (local_ssh_host_key and local_ssh_host_key != (machine["local_ssh_host_key"] or ""))
    )
    conn.execute(
        """
        update machines set
          last_seen_at = ?, last_ip = ?, machine_name = coalesce(nullif(?, ''), machine_name),
          ssh_public_key = coalesce(nullif(?, ''), ssh_public_key),
          local_ssh_host_key = coalesce(nullif(?, ''), local_ssh_host_key),
          remote_user = coalesce(nullif(?, ''), remote_user),
          platform = coalesce(nullif(?, ''), platform),
          relay_key_updated_at = case when ? then ? else relay_key_updated_at end
        where id = ?
        """,
        (now_ts(), request_ip(environ), hostname, ssh_public_key, local_ssh_host_key, remote_user, platform, key_changed, now_ts(), machine["id"]),
    )
    active = conn.execute(
        """
        select id, operator_email, reason, created_at, approved_minutes, expires_at
        from access_requests
        where machine_id = ? and status = 'approved' and expires_at >= ?
        order by created_at desc
        limit 1
        """,
        (machine["id"], now_ts()),
    ).fetchone()
    conn.commit()
    conn.close()
    if key_changed:
        sync_relay_authorized_keys()
    if active:
        audit(
            "agent.checkin",
            f"machine:{machine['machine_name']}",
            machine_id=machine["id"],
            access_request_id=active["id"],
            hostname=hostname,
        )
    active_payload = dict(active) if active else None
    if active_payload:
        active_payload["operator_ssh_public_key"] = OPERATOR_SSH_PUBLIC_KEY
        active_payload["remote_user"] = remote_user or machine["remote_user"] or ""
        active_payload["relay"] = {
            "host": RELAY_HOST,
            "ssh_port": RELAY_SSH_PORT,
            "user": RELAY_USER,
            "transport": RELAY_TRANSPORT,
            "remote_port": machine["relay_port"],
            "known_hosts": RELAY_KNOWN_HOSTS,
        }
    return json_response(
        start_response,
        {
            "machine": {
                "customer_name": machine["customer_name"],
                "machine_name": machine["machine_name"],
                "consent_code": machine["consent_code"],
            },
            "active_request": active_payload,
            "server_time": now_ts(),
        },
    )


def api_agent_connectivity(environ, start_response):
    if environ["REQUEST_METHOD"] != "POST":
        return json_response(start_response, {"error": "method_not_allowed"}, "405 Method Not Allowed")
    try:
        payload = json.loads(read_body(environ).decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return json_response(start_response, {"error": "invalid_json"}, "400 Bad Request")
    machine_token = payload.get("machine_token", "")
    conn = db()
    machine = conn.execute(
        "select id, relay_port from machines where machine_token = ?", (machine_token,)
    ).fetchone()
    conn.close()
    if not machine:
        return json_response(start_response, {"error": "unknown_machine"}, "403 Forbidden")
    return json_response(start_response, {
        "control_plane": "ok",
        "relay": {
            "host": RELAY_HOST,
            "ssh_port": RELAY_SSH_PORT,
            "user": RELAY_USER,
            "transport": RELAY_TRANSPORT,
            "remote_port": machine["relay_port"],
            "known_hosts": RELAY_KNOWN_HOSTS,
        },
        "server_time": now_ts(),
    })


def api_agent_event(environ, start_response):
    if environ["REQUEST_METHOD"] != "POST":
        return json_response(start_response, {"error": "method_not_allowed"}, "405 Method Not Allowed")
    try:
        payload = json.loads(read_body(environ).decode("utf-8") or "{}")
    except json.JSONDecodeError:
        return json_response(start_response, {"error": "invalid_json"}, "400 Bad Request")
    machine_token = payload.get("machine_token", "")
    event_type = payload.get("event_type", "")
    allowed = {"connectivity.tested", "tunnel.started", "tunnel.stopped", "ssh.session.started", "ssh.session.ended"}
    if event_type not in allowed:
        return json_response(start_response, {"error": "invalid_event_type"}, "400 Bad Request")
    conn = db()
    machine = conn.execute("select id, machine_name from machines where machine_token = ?", (machine_token,)).fetchone()
    conn.close()
    if not machine:
        return json_response(start_response, {"error": "unknown_machine"}, "403 Forbidden")
    details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    safe_details = {str(key)[:60]: str(value)[:300] for key, value in details.items()}
    audit(event_type, f"machine:{machine['machine_name']}", machine_id=machine["id"], **safe_details)
    return json_response(start_response, {"status": "recorded"})


def api_machine_status(environ, start_response, token):
    conn = db()
    machine = conn.execute(
        "select id, customer_name, machine_name, consent_code, last_seen_at from machines where machine_token = ?",
        (token,),
    ).fetchone()
    conn.close()
    if not machine:
        return json_response(start_response, {"error": "unknown_machine"}, "404 Not Found")
    return json_response(start_response, dict(machine))


def application(environ, start_response):
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "GET")

    if path == "/health":
        expunge_expired_requests()
        return json_response(start_response, {"status": "ok", "ts": now_ts()})

    if path == "/":
        if get_operator(environ):
            return redirect(start_response, "/app")
        return redirect(start_response, "/login")

    if path == "/login":
        return handle_login(environ, start_response)

    if path == "/logout":
        return handle_logout(environ, start_response)

    if path == "/app":
        operator = require_operator(environ, start_response)
        if not operator:
            return [b""]
        return html_response(start_response, app_dashboard(operator))

    if path == "/app/audit":
        operator = require_operator(environ, start_response)
        if not operator:
            return [b""]
        return html_response(start_response, audit_page(operator))

    if path == "/app/machines" and method == "POST":
        operator = require_operator(environ, start_response)
        if not operator:
            return [b""]
        return handle_machine_create(environ, start_response, operator)

    if path == "/app/requests" and method == "POST":
        operator = require_operator(environ, start_response)
        if not operator:
            return [b""]
        return handle_request_create(environ, start_response, operator)

    if path.startswith("/consent/"):
        parts = [part for part in path.split("/") if part]
        if len(parts) == 2 and method == "GET":
            request_row = fetch_request_by_token(parts[1])
            if not request_row:
                return not_found(start_response)
            return html_response(start_response, consent_page(request_row))
        if len(parts) == 3 and method == "POST" and parts[2] in {"approve", "reject"}:
            return handle_consent_action(environ, start_response, parts[1], parts[2])

    if path == "/api/agent/checkin":
        return api_machine_checkin(environ, start_response)

    if path == "/api/agent/connectivity":
        return api_agent_connectivity(environ, start_response)

    if path == "/api/agent/event":
        return api_agent_event(environ, start_response)

    if path.startswith("/api/agent/status/"):
        return api_machine_status(environ, start_response, path.rsplit("/", 1)[-1])

    return not_found(start_response)


class Reaper(threading.Thread):
    daemon = True

    def run(self):
        while True:
            try:
                expunge_expired_requests()
            except Exception:
                pass
            time.sleep(30)


def main():
    init_db()
    Reaper().start()
    with make_server("0.0.0.0", PORT, application) as httpd:
        print(f"MyTail running on http://0.0.0.0:{PORT}", file=sys.stderr)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
