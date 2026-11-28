import sys
from flask import Flask, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return f"<p>Hello, {name}!</p>"


if __name__ == "__main__":
    app.run(port=int(sys.argv[1]))
