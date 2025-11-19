from datetime import timedelta
import json
import sqlite3
from flask import Blueprint, request, make_response, redirect, session, url_for
from os import environ
import requests
import secrets

blueprint = Blueprint('discord_oauth', __name__)

DISCORD_CLIENT_ID = environ["DISCORD_CLIENT_ID"]
DISCORD_CLIENT_SECRET = environ["DISCORD_CLIENT_SECRET"]

KANIDM_TOKEN = environ["KANIDM_TOKEN"]
KANIDM_DOMAIN = environ["KANIDM_DOMAIN"]

KANIDM_HEADERS = {
    "Authorization": f"Bearer {KANIDM_TOKEN}"
}

GUILD_ID = environ["DISCORD_GUILD_ID"]

class DiscordAuthError(Exception):
    message: str
    code: int

    def __init__(self, message, code):
        self.message = message
        self.code = code

    def into_response(self):
        return make_response({"error": "discord", "message": self.message}, self.code)


def get_discord_user(access_token):
    discord_headers = {
        "Authorization": f"Bearer {access_token}",
    }

    guild_result = requests.get(
        f"https://discord.com/api/users/@me/guilds/{GUILD_ID}/member",
        headers=discord_headers
    )

    if not guild_result.ok:
        raise 

    member = guild_result.json()

    return member


@blueprint.route("/login")
def login():
    state = secrets.token_urlsafe(30)

    after: str | None = request.args.get("after")
    if after is None:
        return make_response("No next link supplied.", 400)

    session["fslc_discord"] = {
        "state": state,
        "after": after,
    }

    return redirect(
        "https://discord.com/api/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={url_for('discord_oauth.callback', _external=True)}"
        f"&response_type=code"
        f"&scope=identify guilds guilds.members.read"
        f"&state={state}"
    )


@blueprint.route("/callback")
def callback():
    code: str | None = request.args.get("code")
    if code is None:
        return make_response("No authorization code supplied.", 400)
    state: str | None = request.args.get("state")
    if state is None:
        return make_response("No authorization state supplied.", 400)

    if "fslc_discord" not in session:
        return make_response("Browser has no cookie for FSLC discord.", 400)

    cookie = session["fslc_discord"]

    if cookie["state"] != state:
        return make_response("Browser's state does not match.", 400)

    token_request_result = requests.post(
        "https://discord.com/api/oauth2/token",
        data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "redirect_uri": url_for('discord_oauth.callback', _external=True),
            "scope": "identify guilds guilds.members.read",
            "code": code,
        }
    )

    token_json = token_request_result.json()

    if not token_request_result.ok:
        return make_response({"error": "discord", "content": token_json}, 400)

    access_token = token_json.get("access_token")

    if access_token is None:
        return make_response({"error": "fslc", "message": "Access token not found"}, 500)

    try:
        member = get_discord_user(access_token)
    except DiscordAuthError as e:
        return e.into_response()

    cookie["uid"] = member["user"]["id"]
    cookie["token"] = access_token

    session["fslc_discord"] = cookie

    return redirect(cookie["after"])


@blueprint.post("/signup")
def signup():
    body = request.json

    if not isinstance(body, dict):
        return make_response(
            {"error": "fslc", "message": "Malformed body"},
            400
        )

    name = body.get("name", None)
    displayname = body.get("displayname", None)

    if name is None or not isinstance(name, str) or len(name) == 0 or \
        displayname is None or not isinstance(displayname, str) or len(displayname) == 3:
        return make_response(
            {"error": "fslc", "message": "Name and displayname must both be specified as nonempty strings"},
            400
        )

    if "fslc_discord" not in session:
        return make_response("Browser has no cookie for FSLC discord.", 400)

    cookie = session["fslc_discord"]
    if "uid" not in cookie:
        return make_response("No discord user ID in session", 400)

    con = sqlite3.connect("export/db.sqlite")
    cur = con.cursor()
    cur.execute("SELECT * FROM accounts WHERE discord_id = ?", (cookie["uid"],))
    if cur.fetchone() is not None:
        return make_response({"error": "fslc", "message": "That discord account already has a user associated with it."}, 400)

    create_response = requests.post(
        f"https://{KANIDM_DOMAIN}/v1/person",
        json={"attrs": {"name": [name], "displayname": [displayname]}},
        headers=KANIDM_HEADERS
    )

    if not create_response.ok:
        return make_response({"error": "kanidm", "message": create_response.json()}, 500)

    user_response = requests.get(
        f"https://{KANIDM_DOMAIN}/v1/person/{name}",
        headers=KANIDM_HEADERS
    )

    user = user_response.json()
    uuid = user["attrs"]["uuid"][0]

    try:
        cur.execute(
            "INSERT INTO accounts (discord_id, kanidm_id) VALUES (?, ?)",
            (cookie["uid"], uuid)
        )
        con.commit()
    except sqlite3.IntegrityError:
        return make_response({"error": "fslc", "message": "username already exists"}, 400)

    update_intent_response = requests.get(
        f"https://{KANIDM_DOMAIN}/v1/person/{name}/_credential/_update_intent",
        headers=KANIDM_HEADERS
    )

    if not update_intent_response.ok:
        return make_response({"error": "kanidm", "message": update_intent_response.json()}, 500)

    update_intent = update_intent_response.json()
    token = update_intent["token"]

    return {
        "uuid": uuid,
        "token": token,
        "url": f"https://{KANIDM_DOMAIN}/ui/reset?token={token}"
    }
