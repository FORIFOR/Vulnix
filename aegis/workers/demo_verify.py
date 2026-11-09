"""Placeholder verification worker for the UI demo.

It performs NO attack and NO network access. It just runs long enough for the
pause / emergency-stop path to be exercised against a real process, and spawns a
child so process-group killing is observable.
"""
import json
import subprocess
import sys
import time

seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 20
child = subprocess.Popen(["/bin/sleep", str(int(seconds) + 30)])
time.sleep(seconds)
child.kill()
print(json.dumps({"outcome": "not_performed",
                  "note": "demo worker: reproduction test is not implemented"}))
