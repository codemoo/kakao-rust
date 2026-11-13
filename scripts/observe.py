#!/usr/bin/env python3
"""Record allowlisted API health fields; never log payloads or credentials."""
import argparse
import datetime
import json
import os
from pathlib import Path
import stat
import time
import urllib.error
import urllib.parse
import urllib.request


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_size > 65536:
            raise ValueError("credential file must be a private regular file")
        value = json.load(stream)
    token = value.get("token")
    if not isinstance(token, str) or not token or len(token) > 16384:
        raise ValueError("invalid credential file")
    return token


def count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def health(value):
    collector = value.get("collector") or {}
    return {
        "live_connected": value.get("live_connected") is True,
        "connections": count(collector.get("connections")),
        "messages_received": count(collector.get("messages_received")),
        "pending_rooms": count(collector.get("pending_rooms")),
        "pending_packets": count(collector.get("pending_packets")),
        "maintenance_failures": {
            row["job"]: count(row.get("failures"))
            for row in value.get("maintenance", [])
            if isinstance(row, dict) and row.get("job") in {"settings", "less_settings", "friends", "contacts"}
        },
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8787")
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=259200)
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--append", action="store_true", help="resume an existing private observation log")
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.url)
    if url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
        parser.error("URL must contain only scheme, host and optional port")
    if url.scheme != "https" and not (url.scheme == "http" and url.hostname in {"127.0.0.1", "::1", "localhost"}):
        parser.error("HTTPS required except on loopback")
    if args.seconds < 1 or args.interval < 1:
        parser.error("duration and interval must be positive")
    token = private_read(args.token_file)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    flags = os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | (os.O_APPEND if args.append else os.O_EXCL)
    output_fd = os.open(args.output, flags, 0o600)
    meta = os.fstat(output_fd)
    if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077:
        os.close(output_fd)
        parser.error("output must be a private regular file")
    until = time.monotonic() + args.seconds
    with os.fdopen(output_fd, "w", buffering=1) as output:
        while True:
            row = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
            request = urllib.request.Request(args.url.rstrip("/") + "/v1/status", headers={"Authorization": "Bearer " + token})
            try:
                with opener.open(request, timeout=15) as response:
                    body = response.read(1024 * 1024 + 1)
                    if len(body) > 1024 * 1024:
                        raise ValueError("oversize")
                    row["http_status"] = response.status
                    row.update(health(json.loads(body)))
            except urllib.error.HTTPError as error:
                row["http_status"] = error.code
            except Exception:
                row["error"] = "observation_failed"
            output.write(json.dumps(row, ensure_ascii=True) + "\n")
            output.flush()
            os.fsync(output.fileno())
            remaining = until - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(args.interval, remaining))


if __name__ == "__main__":
    main()
