import sqlite3
import sys
from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.executescript("CREATE TABLE items(id INTEGER, title TEXT, owner TEXT);"
                   "INSERT INTO items VALUES (1, 'pen', 'alice'), (2, 'HIDDEN_ITEM_MARKER', 'carol');")


@app.route("/items")
def items():
    owner = request.args.get("owner", "alice")
    query = "SELECT id, title FROM items WHERE owner = '" + owner + "'"
    cur = conn.cursor()
    cur.execute(query)
    return {"items": [list(r) for r in cur.fetchall()]}


if __name__ == "__main__":
    app.run(port=int(sys.argv[1]))
