"""Link tracker: link corti con conteggio dei clic e pannello di statistiche.

Privacy: non viene salvato nessun indirizzo IP. Per ogni clic registriamo solo
data/ora, dominio di provenienza, tipo di dispositivo e browser.
"""
import csv
import hmac
import io
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo(os.environ.get("APP_TZ", "Europe/Rome"))
except Exception:  # tzdata mancante (es. Windows): si usa UTC
    TZ = timezone.utc

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "tracker.db"))
DATA_DIR = os.path.dirname(os.path.abspath(DB_PATH))

RESERVED_CODES = {"admin", "static", "favicon.ico", "robots.txt"}
CODE_RE = re.compile(r"^[A-Za-z0-9_-]{3,40}$")
BOT_RE = re.compile(
    r"bot|crawl|spider|slurp|preview|fetch|monitor|facebookexternalhit|whatsapp|"
    r"curl|wget|python-requests|httpclient|headless|lighthouse",
    re.I,
)


# --------------------------------------------------------------------------
# Configurazione (password e chiave di sessione)
# --------------------------------------------------------------------------
def load_or_create(env_name, filename, make_value):
    """Legge il valore dalla variabile d'ambiente; se manca lo genera una volta
    sola e lo salva in un file accanto al database (permessi 0600)."""
    value = os.environ.get(env_name)
    if value:
        return value
    path = os.path.join(DATA_DIR, filename)
    for _ in range(5):
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read().strip()
            if content:
                return content
            time.sleep(0.1)  # un altro worker lo sta ancora scrivendo
        except FileNotFoundError:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            value = make_value()
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(value)
            print(f"[link-tracker] {env_name} non impostata: generata e salvata in {path}")
            return value
    raise RuntimeError(f"Impossibile leggere {env_name} da {path}")


ADMIN_PASSWORD = load_or_create("ADMIN_PASSWORD", ".admin_password",
                                lambda: secrets.token_urlsafe(12))
SECRET_KEY = load_or_create("SECRET_KEY", ".secret_key",
                            lambda: secrets.token_hex(32))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)
if os.environ.get("TRUST_PROXY") == "1":  # dietro nginx / Render / ecc.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS links (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    code         TEXT NOT NULL UNIQUE,
    url          TEXT NOT NULL,
    title        TEXT NOT NULL DEFAULT '',
    utm_source   TEXT NOT NULL DEFAULT '',
    utm_medium   TEXT NOT NULL DEFAULT '',
    utm_campaign TEXT NOT NULL DEFAULT '',
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clicks (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id  INTEGER NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    ts       TEXT NOT NULL,
    day      TEXT NOT NULL,
    referrer TEXT NOT NULL,
    device   TEXT NOT NULL,
    browser  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clicks_link_day ON clicks (link_id, day);
"""


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode = WAL")
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


init_db()


# --------------------------------------------------------------------------
# Sicurezza: CSRF, login, rate limit
# --------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(24)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        expected = session.get("_csrf", "")
        sent = request.form.get("_csrf", "")
        if not expected or not hmac.compare_digest(expected, sent):
            abort(400, "Token CSRF non valido: ricarica la pagina e riprova.")


@app.after_request
def security_headers(resp):
    if request.path.startswith("/admin"):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


FAILS = {}  # ip -> (tentativi falliti, timestamp del primo)
MAX_FAILS, WINDOW = 5, 300


def is_locked(ip):
    count, first = FAILS.get(ip, (0, 0))
    if time.time() - first > WINDOW:
        FAILS.pop(ip, None)
        return False
    return count >= MAX_FAILS


def register_fail(ip):
    count, first = FAILS.get(ip, (0, time.time()))
    FAILS[ip] = (count + 1, first)


# --------------------------------------------------------------------------
# Utilità
# --------------------------------------------------------------------------
def normalize_url(raw):
    """Aggiunge https:// se manca e accetta solo http/https."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Inserisci un URL di destinazione.")
    if re.search(r"\s", raw):
        raise ValueError("L'URL non può contenere spazi.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("L'URL deve iniziare con http:// o https://.")
    try:
        parts.port  # solleva ValueError se la porta non è numerica (es. "javascript:alert(1)")
    except ValueError:
        raise ValueError("URL non valido.") from None
    if parts.hostname.lower() == (request.host.split(":")[0]).lower():
        raise ValueError("L'URL non può puntare a questo stesso sito.")
    return raw


def build_target(link):
    """URL finale: aggiunge i parametri UTM senza sovrascrivere quelli esistenti."""
    parts = urlsplit(link["url"])
    query = parse_qsl(parts.query, keep_blank_values=True)
    present = {k for k, _ in query}
    for key in ("utm_source", "utm_medium", "utm_campaign"):
        if link[key] and key not in present:
            query.append((key, link[key]))
    return urlunsplit(parts._replace(query=urlencode(query)))


def parse_ua(ua):
    low = ua.lower()
    if "ipad" in low or "tablet" in low or ("android" in low and "mobile" not in low):
        device = "Tablet"
    elif "mobi" in low or "iphone" in low or "android" in low:
        device = "Mobile"
    else:
        device = "Desktop"
    if "edg/" in low or "edga/" in low or "edgios/" in low:
        browser = "Edge"
    elif "opr/" in low or "opera" in low:
        browser = "Opera"
    elif "firefox" in low or "fxios" in low:
        browser = "Firefox"
    elif "chrome" in low or "crios" in low:
        browser = "Chrome"
    elif "safari" in low:
        browser = "Safari"
    else:
        browser = "Altro"
    return device, browser


def referrer_host():
    ref = request.referrer
    if not ref:
        return "Diretto"
    host = (urlsplit(ref).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host or "Diretto"


def log_click(db, link_id):
    ua = request.headers.get("User-Agent", "")
    purpose = (request.headers.get("Sec-Purpose", "") +
               request.headers.get("Purpose", "")).lower()
    if request.method == "HEAD" or not ua or BOT_RE.search(ua) or "prefetch" in purpose:
        return
    device, browser = parse_ua(ua)
    now = datetime.now(TZ)
    db.execute(
        "INSERT INTO clicks (link_id, ts, day, referrer, device, browser) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (link_id, now.isoformat(timespec="seconds"), now.date().isoformat(),
         referrer_host(), device, browser),
    )
    db.commit()


def breakdown(db, link_id, column, limit=8):
    assert column in ("referrer", "device", "browser")
    rows = db.execute(
        f"SELECT {column} AS label, COUNT(*) AS n FROM clicks "
        f"WHERE link_id = ? GROUP BY {column} ORDER BY n DESC LIMIT ?",
        (link_id, limit),
    ).fetchall()
    top = rows[0]["n"] if rows else 1
    return [{"label": r["label"], "n": r["n"], "pct": round(r["n"] * 100 / top)}
            for r in rows]


# --------------------------------------------------------------------------
# Redirect pubblico
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/<string:code>")
def go(code):
    if code in RESERVED_CODES:
        abort(404)
    db = get_db()
    link = db.execute("SELECT * FROM links WHERE code = ?", (code,)).fetchone()
    if link is None:
        abort(404)
    if not link["active"]:
        abort(410)
    try:
        log_click(db, link["id"])
    except sqlite3.Error:  # il redirect non deve mai fallire per colpa delle statistiche
        pass
    resp = redirect(build_target(link), code=302)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------
# Pannello di amministrazione
# --------------------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if is_locked(ip):
            flash("Troppi tentativi. Riprova tra qualche minuto.", "error")
            return render_template("login.html"), 429
        password = request.form.get("password", "")
        if hmac.compare_digest(password.encode(), ADMIN_PASSWORD.encode()):
            FAILS.pop(ip, None)
            session.clear()
            session["auth"] = True
            session.permanent = True
            return redirect(url_for("dashboard"))
        register_fail(ip)
        flash("Password errata.", "error")
    return render_template("login.html")


@app.post("/admin/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
@login_required
def dashboard():
    since = (datetime.now(TZ).date() - timedelta(days=6)).isoformat()
    links = get_db().execute(
        "SELECT l.*, COUNT(c.id) AS total, "
        "COALESCE(SUM(CASE WHEN c.day >= ? THEN 1 ELSE 0 END), 0) AS last7 "
        "FROM links l LEFT JOIN clicks c ON c.link_id = l.id "
        "GROUP BY l.id ORDER BY l.created_at DESC, l.id DESC",
        (since,),
    ).fetchall()
    return render_template("dashboard.html", links=links)


@app.post("/admin/links")
@login_required
def create_link():
    db = get_db()
    form = request.form
    try:
        url = normalize_url(form.get("url"))
    except ValueError as err:
        flash(str(err), "error")
        return redirect(url_for("dashboard"))

    code = (form.get("code") or "").strip()
    if code:
        if not CODE_RE.match(code):
            flash("Il codice può avere 3-40 caratteri: lettere, numeri, - e _.", "error")
            return redirect(url_for("dashboard"))
        if code.lower() in RESERVED_CODES:
            flash("Questo codice è riservato, scegline un altro.", "error")
            return redirect(url_for("dashboard"))
    else:
        code = secrets.token_urlsafe(5)
        while db.execute("SELECT 1 FROM links WHERE code = ?", (code,)).fetchone():
            code = secrets.token_urlsafe(5)

    title = (form.get("title") or "").strip()[:120] or urlsplit(url).hostname
    utm = {k: (form.get(k) or "").strip()[:100]
           for k in ("utm_source", "utm_medium", "utm_campaign")}
    try:
        db.execute(
            "INSERT INTO links (code, url, title, utm_source, utm_medium, utm_campaign, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (code, url, title, utm["utm_source"], utm["utm_medium"],
             utm["utm_campaign"], datetime.now(TZ).isoformat(timespec="seconds")),
        )
        db.commit()
    except sqlite3.IntegrityError:
        flash("Esiste già un link con questo codice.", "error")
        return redirect(url_for("dashboard"))

    flash("Link creato: " + url_for("go", code=code, _external=True), "ok")
    return redirect(url_for("dashboard"))


@app.route("/admin/links/<int:link_id>")
@login_required
def link_detail(link_id):
    db = get_db()
    link = db.execute("SELECT * FROM links WHERE id = ?", (link_id,)).fetchone()
    if link is None:
        abort(404)

    today = datetime.now(TZ).date()
    days = [(today - timedelta(days=i)).isoformat() for i in range(29, -1, -1)]
    counts = {r["day"]: r["n"] for r in db.execute(
        "SELECT day, COUNT(*) AS n FROM clicks WHERE link_id = ? AND day >= ? GROUP BY day",
        (link_id, days[0]))}
    peak = max(counts.values(), default=0)
    bars = [{"day": d, "n": counts.get(d, 0),
             "pct": max(4, round(counts[d] * 100 / peak)) if counts.get(d) else 0}
            for d in days]

    total = db.execute("SELECT COUNT(*) FROM clicks WHERE link_id = ?", (link_id,)).fetchone()[0]
    stats = {
        "total": total,
        "today": counts.get(today.isoformat(), 0),
        "last7": sum(b["n"] for b in bars[-7:]),
        "last30": sum(b["n"] for b in bars),
    }
    return render_template(
        "link.html", link=link, bars=bars, stats=stats,
        short_url=url_for("go", code=link["code"], _external=True),
        target=build_target(link),
        referrers=breakdown(db, link_id, "referrer"),
        devices=breakdown(db, link_id, "device"),
        browsers=breakdown(db, link_id, "browser"),
    )


@app.post("/admin/links/<int:link_id>/toggle")
@login_required
def toggle_link(link_id):
    db = get_db()
    db.execute("UPDATE links SET active = 1 - active WHERE id = ?", (link_id,))
    db.commit()
    return redirect(request.form.get("back") or url_for("dashboard"))


@app.post("/admin/links/<int:link_id>/delete")
@login_required
def delete_link(link_id):
    db = get_db()
    db.execute("DELETE FROM links WHERE id = ?", (link_id,))
    db.commit()
    flash("Link eliminato.", "ok")
    return redirect(url_for("dashboard"))


def csv_safe(value):
    """Evita che Excel interpreti una cella come formula."""
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


@app.route("/admin/links/<int:link_id>/export.csv")
@login_required
def export_csv(link_id):
    db = get_db()
    link = db.execute("SELECT code FROM links WHERE id = ?", (link_id,)).fetchone()
    if link is None:
        abort(404)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["data_ora", "provenienza", "dispositivo", "browser"])
    for r in db.execute(
            "SELECT ts, referrer, device, browser FROM clicks WHERE link_id = ? ORDER BY id",
            (link_id,)):
        writer.writerow([r["ts"], csv_safe(r["referrer"]), r["device"], r["browser"]])
    return Response(
        out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="clic-{link["code"]}.csv"'},
    )


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5000")), debug=False)
