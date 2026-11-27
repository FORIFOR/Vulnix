import sys
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return "<h1>Results for " + q + "</h1><p>No results.</p>"


if __name__ == "__main__":
    app.run(port=int(sys.argv[1]))
