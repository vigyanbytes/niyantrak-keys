"""Throwaway Niyantrak join listener for the compatibility test (needs NIYANTRAK_SRC on sys.path).

Starts the real panel join listener (TLS, self-signed, pinned) on 127.0.0.1:<free port> with a temp state dir and
join store, issues one single-use token, prints {"port", "fingerprint", "token", "store"} as one JSON line, then
serves until stdin closes. Nothing outside the temp dir is touched.
"""
import json
import sys
import tempfile
import threading

from niyantrak import join as joinmod
from niyantrak import panel

state = tempfile.mkdtemp(prefix="nyk-compat-")
store = f"{state}/join.json"
admin, js = panel.make_servers("127.0.0.1", 0, "127.0.0.1", 0, state_dir=state, store=store)
threading.Thread(target=js.serve_forever, daemon=True).start()
token = joinmod.issue_token(store)
print(json.dumps({"port": js.server_address[1], "fingerprint": js.fingerprint, "token": token, "store": store}), flush=True)
sys.stdin.read()
js.shutdown()
