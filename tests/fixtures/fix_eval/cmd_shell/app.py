import subprocess
import sys
from flask import Flask, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    who = request.args.get("who", "world")
    out = subprocess.run(f"echo hello {who}", shell=True, capture_output=True, text=True)
    return out.stdout


if __name__ == "__main__":
    app.run(port=int(sys.argv[1]))
