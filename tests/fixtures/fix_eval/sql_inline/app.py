import sqlite3
import sys
from flask import Flask, request

app = Flask(__name__)
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("CREATE TABLE users(name TEXT, email TEXT);"
                 "INSERT INTO users VALUES ('alice', 'alice@example.test'), ('bob', 'SECRET_BOB_MARKER');")


@app.route("/user")
def user():
    name = request.args.get("name", "")
    rows = DB.execute(f"SELECT name, email FROM users WHERE name = '{name}'").fetchall()
    return {"users": [list(r) for r in rows]}


if __name__ == "__main__":
    app.run(port=int(sys.argv[1]))
