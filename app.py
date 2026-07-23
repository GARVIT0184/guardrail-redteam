from flask import Flask, request, jsonify
import os
import requests
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote

app = Flask(__name__)

SANDBOX = "/srv/agent-redteam/sandbox-2dc72be8db"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}


def resolve_inside(path):
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(SANDBOX, path))

    root = os.path.normpath(SANDBOX)

    return full == root or full.startswith(root + os.sep), full


def looks_internal(value):
    value = unquote(value)

    try:
        if value.startswith(("http://", "https://")):
            host = (urlparse(value).hostname or "").lower()
        else:
            host = value

        if host in ("localhost",):
            return True

        try:
            ip = ipaddress.ip_address(host)
            return (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
            )
        except:
            pass

        if host.startswith("169.254."):
            return True

        if value.startswith(("http://", "https://")):
            return True

    except:
        pass

    return False


@app.route("/")
def home():
    return "OK"


@app.route("/check", methods=["POST"])
def check():

    body = request.get_json(force=True)

    tool = body["tool"]
    args = body.get("arguments", {})

    if tool == "read_file":

        ok, full = resolve_inside(args["path"])

        if not ok:
            return jsonify({
                "action": "block",
                "reason": "outside sandbox"
            })

        try:
            with open(full, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception as e:
            text = str(e)

        return jsonify({
            "action": "allow",
            "reason": "inside sandbox",
            "result": text
        })

    if tool == "fetch_url":

        u = urlparse(args["url"])
        host = (u.hostname or "").lower()

        if host not in ALLOWED_HOSTS:
            return jsonify({
                "action": "block",
                "reason": "host not allowed"
            })

        for values in parse_qs(u.query).values():
            for v in values:
                if looks_internal(v):
                    return jsonify({
                        "action": "block",
                        "reason": "redirect to internal target"
                    })

        try:
            r = requests.get(args["url"], timeout=5, allow_redirects=False)
            result = r.text
        except Exception as e:
            result = str(e)

        return jsonify({
            "action": "allow",
            "reason": "allowed host",
            "result": result
        })

    return jsonify({
        "action": "block",
        "reason": "unknown tool"
    })


if __name__ == "__main__":
    app.run()
