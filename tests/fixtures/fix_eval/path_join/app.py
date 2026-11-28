import os
import sys
from flask import Flask, request

app = Flask(__name__)
BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name", "readme.txt")
    with open(os.path.join(BASE, name)) as f:
        return f.read()


if __name__ == "__main__":
    app.run(port=int(sys.argv[1]))
