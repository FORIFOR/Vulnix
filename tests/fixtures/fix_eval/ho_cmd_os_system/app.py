import os
import sys
import tempfile
from flask import Flask, request

app = Flask(__name__)
OUT = os.path.join(tempfile.gettempdir(), f"vulnix-fixeval-{os.getpid()}.txt")


@app.route("/archive")
def archive():
    label = request.args.get("label", "backup")
    os.system("echo archived " + label + " > " + OUT)
    with open(OUT) as f:
        return f.read()


if __name__ == "__main__":
    app.run(port=int(sys.argv[1]))
