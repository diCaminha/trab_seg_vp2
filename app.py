import json
import os
import sqlite3

from flask import Flask, redirect, request, url_for, make_response, jsonify
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

from db import init_db_command, set_cert_to_crl
from main import cert_gen
from user import User

GOOGLE_CLIENT_ID = os.environ.get("ENV_GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("ENV_GOOGLE_SECRET")
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)

try:
    init_db_command()
except sqlite3.OperationalError:
    pass

client = WebApplicationClient(GOOGLE_CLIENT_ID)


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/login")
def login():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    code = request.args.get("code")
    print(f"print code: {code}")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    client.parse_request_body_response(json.dumps(token_response.json()))

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )

    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    login_user(user)

    return make_response(jsonify({"message": "success"}), 200)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route('/cert', methods=['POST'])
def create_cert():
    if current_user.is_authenticated:
        data = request.get_json()
        print(data)
        cert, key = cert_gen(
            email=data['email'],
            name=data['name'],
            countryName=data['countryName'],
            stateName=data['stateName'],
            organizationName=data['organizationName']
        )

    return make_response(jsonify({"certificate": cert, "key": key}), 200)


@app.route('/tocrl/<serialnumber>', methods=['POST'])
def set_cert_crl(serialnumber):
    set_cert_to_crl(serialnumber)
    return make_response(jsonify({"message": f"cert with serialnumber: {serialnumber} set to CRL with success"}), 200)


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


if __name__ == "__main__":
    app.run(ssl_context="adhoc")
