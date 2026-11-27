"""Sample web app with the OAuth "return to" open redirect (test fixture, loopback only)."""
import sys

from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/auth/callback")
def callback():
    return_to = request.args.get("return_to") or "/"
    return redirect(return_to)


@app.route("/dashboard")
def dashboard():
    return "dashboard"


if __name__ == "__main__":
    app.run(port=int(sys.argv[1]))
