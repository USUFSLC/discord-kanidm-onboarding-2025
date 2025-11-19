import sqlite3
from os import environ
from flask import Flask
from fslc_discord.auth import blueprint as auth_blueprint
from werkzeug.middleware.proxy_fix import ProxyFix


def create_app():
    with open("schema.sql") as f:
        script = f.read()
        with sqlite3.connect("export/db.sqlite") as con:
            cur = con.cursor()
            cur.executescript(script)

    app = Flask(__name__)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_port=1, x_host=1, x_prefix=1)

    app.secret_key = environ["SECRET_KEY"]

    app.register_blueprint(auth_blueprint, url_prefix="/api/discord")

    return app
