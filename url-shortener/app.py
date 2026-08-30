"""Simple URL Shortener web app using Flask + SQLite."""

import random
import sqlite3
import string
from urllib.parse import urlparse

from flask import Flask, g, redirect, render_template, request, jsonify

app = Flask(__name__)

DATABASE = "database.db"
SHORT_CODE_LENGTH = 6
SHORT_CODE_CHARS = string.ascii_letters + string.digits


def get_db():
    """Get a SQLite connection for the current request."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the urls table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            short_code TEXT UNIQUE NOT NULL,
            original_url TEXT NOT NULL,
            clicks INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()
    conn.close()


def is_valid_url(url):
    """Basic URL validation: must have http/https scheme and a network location."""
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except ValueError:
        return False


def generate_short_code():
    """Generate a random short code, retrying until it's unique."""
    db = get_db()
    while True:
        code = "".join(random.choices(SHORT_CODE_CHARS, k=SHORT_CODE_LENGTH))
        existing = db.execute(
            "SELECT id FROM urls WHERE short_code = ?", (code,)
        ).fetchone()
        if not existing:
            return code


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/shorten", methods=["POST"])
def shorten():
    data = request.get_json(silent=True) or {}
    original_url = (data.get("url") or "").strip()

    if not original_url:
        return jsonify({"error": "Please enter a URL."}), 400

    if not is_valid_url(original_url):
        return jsonify({"error": "Please enter a valid URL starting with http:// or https://"}), 400

    db = get_db()
    short_code = generate_short_code()
    db.execute(
        "INSERT INTO urls (short_code, original_url) VALUES (?, ?)",
        (short_code, original_url),
    )
    db.commit()

    short_url = request.host_url + short_code
    return jsonify({"short_url": short_url, "short_code": short_code})


@app.route("/<short_code>")
def redirect_to_url(short_code):
    db = get_db()
    row = db.execute(
        "SELECT * FROM urls WHERE short_code = ?", (short_code,)
    ).fetchone()

    if row is None:
        return render_template("index.html", error="Short URL not found."), 404

    db.execute(
        "UPDATE urls SET clicks = clicks + 1 WHERE short_code = ?", (short_code,)
    )
    db.commit()

    return redirect(row["original_url"])


@app.route("/urls")
def list_urls():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM urls ORDER BY created_at DESC"
    ).fetchall()
    return render_template("urls.html", urls=rows)


@app.errorhandler(404)
def not_found(e):
    return render_template("index.html", error="Page not found."), 404


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
