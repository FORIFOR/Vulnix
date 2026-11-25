"""Run paired synthetic observations using a reviewed Python adapter."""

import contextlib
import json
from pathlib import Path
import sys


def reject_side_effects(event, _args):
    if event.startswith(("socket.", "subprocess.", "ctypes.", "os.exec", "os.spawn", "os.fork", "os.posix_spawn", "os.system")):
        raise PermissionError("offline defence adapter")


def main():
    snapshot = Path(sys.argv[1])
    sys.addaudithook(reject_side_effects)
    sys.path.insert(0, str(snapshot / "source"))
    with contextlib.redirect_stdout(sys.stderr):
        from check import observe

        cases = json.loads((snapshot / "cases.json").read_bytes())
        result = {}
        for name, pair in cases.items():
            result[name] = {}
            for mode, values in pair.items():
                try:
                    value = observe(name, values)
                except Exception:
                    value = None
                result[name][mode] = value if type(value) is bool else None
    print(json.dumps(result))


if __name__ == "__main__":
    main()
