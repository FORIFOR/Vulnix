import os
import sys
from flask import Flask, request, send_file

app = Flask(__name__)
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")


@app.route("/files/get")
def get_file():
    requested = request.args["file"]
    return send_file(os.path.join(ROOT, requested))


if __name__ == "__main__":
    app.run(port=int(sys.argv[1]))
