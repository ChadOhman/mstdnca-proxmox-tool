import base64
import json
import logging
import re
import shlex
from datetime import datetime, timezone

from clients.proxmox_api import ProxmoxClient
from clients.ssh_client import SSHClient
from models import Guest, GuestService, ScanResult, UpdatePackage, db

logger = logging.getLogger(__name__)

# Valid systemd unit names: alphanumeric, hyphens, underscores, dots, @, *
_VALID_UNIT_RE = re.compile(r'^[\w.\-@*]+$')

# Pure-Python3 Redis client script for Sidekiq stats.
# Uses only stdlib socket + urllib — no redis-cli required.
# \\r\\n in this bytes literal → \r\n in the inner Python source → CR+LF at runtime.
_SIDEKIQ_REDIS_SCRIPT = b"""\
import socket, urllib.parse as up, json, time

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    print("---queues---")
    rc(s, "SMEMBERS", "queues")
    qs = rr(s, bf) or []
    _lat_dbg = ''
    def _parse_ea(ea):
        try:
            ts = float(ea)
            if ts > 1e11: ts /= 1000.0
            return ts
        except (TypeError, ValueError): pass
        try:
            from datetime import datetime as _dt
            return _dt.fromisoformat(str(ea).replace('Z', '+00:00')).timestamp()
        except Exception: return None
    for q in qs:
        rc(s, "LLEN", "queue:"+q)
        size = rr(s, bf) or 0
        lat = 0.0
        if size > 0:
            rc(s, "LINDEX", "queue:"+q, "-1")
            rc(s, "LINDEX", "queue:"+q, "0")
            for _item in [rr(s, bf), rr(s, bf)]:
                if _item:
                    try:
                        _job = json.loads(_item)
                        _ea = _job.get("enqueued_at") or _job.get("created_at")
                        if _ea is not None:
                            _ts = _parse_ea(_ea)
                            if _ts is not None:
                                _l = time.time() - _ts
                                if _l > lat: lat = _l
                            if not _lat_dbg:
                                _lat_dbg = '{}|{}|{}'.format(q, type(_ea).__name__, str(_ea)[:30])
                        elif not _lat_dbg:
                            _lat_dbg = '{}|no_ea|keys:{}'.format(q, ','.join(list(_job.keys())[:5]))
                    except Exception as _ex:
                        if not _lat_dbg: _lat_dbg = '{}|ex|{}'.format(q, str(_ex)[:60])
        print("{}={}|{:.2f}".format(q, size, lat))
    print("---stats---")
    for k, c in [("processed", ("GET", "stat:processed")), ("failed", ("GET", "stat:failed")),
                 ("retry", ("ZCARD", "retry")), ("dead", ("ZCARD", "dead")),
                 ("scheduled", ("ZCARD", "schedule"))]:
        rc(s, *c)
        print("{}={}".format(k, rr(s, bf) or 0))
    print("---workers---")
    rc(s, "SMEMBERS", "processes")
    procs = rr(s, bf) or []
    for pid_key in procs:
        rc(s, "HGETALL", pid_key)
        fields = rr(s, bf) or []
        h = {}
        it = iter(fields)
        for fk in it:
            try:
                fv = next(it)
            except StopIteration:
                break
            h[fk] = fv
        print("worker={}|{}|{}|{}|{}|{}".format(
            h.get("hostname", ""),
            h.get("pid", ""),
            h.get("concurrency", "0"),
            h.get("busy", "0"),
            h.get("beat", ""),
            h.get("queues", "[]"),
        ))
    print("---paused---")
    rc(s, "SMEMBERS", "paused")
    paused_set = rr(s, bf) or []
    for pq in paused_set:
        print(pq)
    s.close()
    print("---debug---")
    print("host={}".format(host))
    print("port={}".format(port))
    print("db={}".format(db))
    print("auth_set={}".format("yes" if pw else "no"))
    print("redis_cli=python3-ok")
    print("lat_dbg={}".format(_lat_dbg or 'none'))
except Exception as e:
    print("---debug---")
    print("host={}".format(host))
    print("port={}".format(port))
    print("db={}".format(db))
    print("auth_set={}".format("yes" if pw else "no"))
    print("redis_cli=python3-err")
    print("errmsg={}".format(str(e)[:120]))
"""


# Pure-Python3 Redis script to clear the Sidekiq dead queue.
# Shares the same connection discovery logic as _SIDEKIQ_REDIS_SCRIPT.
_SIDEKIQ_CLEAR_DEAD_SCRIPT = b"""\
import socket, urllib.parse as up

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    rc(s, "DEL", "dead")
    n = rr(s, bf)
    s.close()
    print("ok={}".format(n or 0))
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_clear_dead(guest, service):
    """Clear the Sidekiq dead queue by deleting the 'dead' sorted set from Redis.

    Returns (ok: bool, message: str).
    """
    _py_b64 = base64.b64encode(_SIDEKIQ_CLEAR_DEAD_SCRIPT).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            count = line.split("=", 1)[1]
            return True, f"Cleared {count} job(s) from the dead queue"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


# Pure-Python3 Redis script to retry all jobs in the Sidekiq dead queue.
# Reads each job from the 'dead' sorted set, LPUSHes it back onto its queue,
# then deletes the dead set. Shares connection discovery with the other scripts.
_SIDEKIQ_RETRY_DEAD_SCRIPT = b"""\
import socket, urllib.parse as up, json

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    rc(s, "ZRANGE", "dead", "0", "-1")
    jobs = rr(s, bf) or []
    count = 0
    for job_str in jobs:
        try:
            queue = json.loads(job_str).get("queue", "default")
            rc(s, "LPUSH", "queue:" + queue, job_str)
            rr(s, bf)
            count += 1
        except: pass
    rc(s, "DEL", "dead")
    rr(s, bf)
    s.close()
    print("ok={}".format(count))
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_retry_dead(guest, service):
    """Retry all jobs in the Sidekiq dead queue by requeueing them.

    Returns (ok: bool, message: str).
    """
    _py_b64 = base64.b64encode(_SIDEKIQ_RETRY_DEAD_SCRIPT).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            count = line.split("=", 1)[1]
            return True, f"Retried {count} job(s) from the dead queue"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


# Pure-Python3 Redis script to clear the Sidekiq retry queue.
_SIDEKIQ_CLEAR_RETRY_SCRIPT = b"""\
import socket, urllib.parse as up

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    rc(s, "DEL", "retry")
    n = rr(s, bf)
    s.close()
    print("ok={}".format(n or 0))
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_clear_retry(guest, service):
    """Clear the Sidekiq retry queue by deleting the 'retry' sorted set from Redis.

    Returns (ok: bool, message: str).
    """
    _py_b64 = base64.b64encode(_SIDEKIQ_CLEAR_RETRY_SCRIPT).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            count = line.split("=", 1)[1]
            return True, f"Cleared {count} job(s) from the retry queue"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


# Pure-Python3 Redis script to immediately re-enqueue all jobs in the Sidekiq retry queue.
_SIDEKIQ_RETRY_RETRY_SCRIPT = b"""\
import socket, urllib.parse as up, json

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    rc(s, "ZRANGE", "retry", "0", "-1")
    jobs = rr(s, bf) or []
    count = 0
    for job_str in jobs:
        try:
            queue = json.loads(job_str).get("queue", "default")
            rc(s, "LPUSH", "queue:" + queue, job_str)
            rr(s, bf)
            count += 1
        except: pass
    rc(s, "DEL", "retry")
    rr(s, bf)
    s.close()
    print("ok={}".format(count))
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_retry_retry(guest, service):
    """Immediately re-enqueue all jobs in the Sidekiq retry queue.

    Returns (ok: bool, message: str).
    """
    _py_b64 = base64.b64encode(_SIDEKIQ_RETRY_RETRY_SCRIPT).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            count = line.split("=", 1)[1]
            return True, f"Retried {count} job(s) from the retry queue"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


_SIDEKIQ_JID_RE = re.compile(r'^[0-9a-f]{16,32}$')


def _format_elapsed(secs):
    """Format seconds as a human-readable elapsed time string for queue latency."""
    try:
        secs = float(secs)
    except (TypeError, ValueError):
        return "—"
    if secs < 1:
        return "< 1s"
    elif secs < 60:
        return f"{secs:.0f}s"
    elif secs < 3600:
        m, s = int(secs // 60), int(secs % 60)
        return f"{m}m {s}s"
    else:
        h = int(secs // 3600)
        m = int((secs % 3600) // 60)
        return f"{h}h {m}m"


# Pure-Python3 Redis script template to list jobs from a Sidekiq sorted-set queue.
# Placeholders __QUEUEKEY__, __OFFSET__, __ENDIDX__ are replaced at call time via bytes.replace().
_SIDEKIQ_LIST_JOBS_TEMPLATE = b"""\
import socket, urllib.parse as up, json

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(8)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    q_key = __QUEUEKEY__
    offset = __OFFSET__
    end = __ENDIDX__
    rc(s, "ZCARD", q_key)
    total = rr(s, bf) or 0
    if q_key == "dead":
        rc(s, "ZREVRANGE", q_key, str(offset), str(end), "WITHSCORES")
    else:
        rc(s, "ZRANGE", q_key, str(offset), str(end), "WITHSCORES")
    items = rr(s, bf) or []
    jobs = []
    for i in range(0, len(items), 2):
        try:
            job = json.loads(items[i])
            score = float(items[i+1]) if i+1 < len(items) else 0.0
            jobs.append({"jid": job.get("jid",""), "class": job.get("class",""), "queue": job.get("queue",""), "args": str(job.get("args",[]))[:80], "enqueued_at": job.get("enqueued_at",0), "failed_at": job.get("failed_at",0), "error_message": (job.get("error_message","") or "")[:100], "score": score})
        except: pass
    s.close()
    print(json.dumps({"total": total, "jobs": jobs}))
except Exception as e:
    print(json.dumps({"error": str(e)[:120]}))
"""


def sidekiq_list_jobs(guest, service, queue_type, offset=0, limit=25):
    """Fetch a page of jobs from a Sidekiq sorted-set queue (dead/retry/schedule).

    Returns (jobs: list, total: int, error: str|None).
    """
    if queue_type not in ("dead", "retry", "schedule"):
        return [], 0, "Invalid queue type"
    script = _SIDEKIQ_LIST_JOBS_TEMPLATE
    script = script.replace(b"__QUEUEKEY__", repr(str(queue_type)).encode())
    script = script.replace(b"__OFFSET__", str(int(offset)).encode())
    script = script.replace(b"__ENDIDX__", str(int(offset) + int(limit) - 1).encode())
    _py_b64 = base64.b64encode(script).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return [], 0, err
    try:
        data = json.loads((out or "").strip())
        if "error" in data:
            return [], 0, data["error"]
        return data.get("jobs", []), int(data.get("total", 0)), None
    except Exception:
        return [], 0, f"Could not parse response: {(out or '')[:80]}"


# Pure-Python3 Redis script template to delete a single Sidekiq job by JID.
# Iterates the sorted set via ZSCAN to find and ZREM the matching member.
# Placeholders __QUEUEKEY__ and __JID__ are replaced at call time.
_SIDEKIQ_DELETE_JOB_TEMPLATE = b"""\
import socket, urllib.parse as up, json

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(8)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    q_key = __QUEUEKEY__
    target_jid = __JID__
    cursor = "0"
    found = None
    while True:
        rc(s, "ZSCAN", q_key, cursor, "COUNT", "200")
        result = rr(s, bf) or ["0", []]
        cursor = result[0] if result[0] else "0"
        items = result[1] or []
        for i in range(0, len(items), 2):
            try:
                if json.loads(items[i]).get("jid") == target_jid:
                    found = items[i]
                    break
            except: pass
        if found is not None or cursor == "0":
            break
    if found is not None:
        rc(s, "ZREM", q_key, found)
        n = rr(s, bf) or 0
        print("ok={}".format(n))
    else:
        print("error=job not found")
    s.close()
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_delete_job(guest, service, queue_type, jid):
    """Remove a single job from a Sidekiq sorted-set queue by JID.

    Returns (ok: bool, message: str).
    """
    if queue_type not in ("dead", "retry", "schedule"):
        return False, "Invalid queue type"
    if not _SIDEKIQ_JID_RE.match(jid):
        return False, "Invalid JID"
    script = _SIDEKIQ_DELETE_JOB_TEMPLATE
    script = script.replace(b"__QUEUEKEY__", repr(str(queue_type)).encode())
    script = script.replace(b"__JID__", repr(str(jid)).encode())
    _py_b64 = base64.b64encode(script).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            return True, "Job deleted"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


# Pure-Python3 Redis script template to retry (re-enqueue) a single Sidekiq job by JID.
# Finds the job via ZSCAN, LPUSHes it back to its queue, then ZREMs it from the set.
# Placeholders __QUEUEKEY__ and __JID__ are replaced at call time.
_SIDEKIQ_RETRY_JOB_TEMPLATE = b"""\
import socket, urllib.parse as up, json

def rc(s, *args):
    p = ["*{}\\r\\n".format(len(args))]
    for a in args:
        a = str(a)
        p.append("${}\\r\\n{}\\r\\n".format(len(a.encode()), a))
    s.sendall("".join(p).encode())

def rr(s, bf):
    while b"\\r\\n" not in bf[0]:
        d = s.recv(65536)
        if not d: break
        bf[0] += d
    if not bf[0]: return None
    i = bf[0].index(b"\\r\\n")
    ln = bf[0][:i].decode("utf-8", "replace")
    bf[0] = bf[0][i+2:]
    t, rest = ln[0], ln[1:]
    if t == "+": return rest
    if t == "-": return None
    if t == ":": return int(rest) if rest.lstrip("-").isdigit() else 0
    if t == "$":
        n = int(rest)
        if n < 0: return None
        while len(bf[0]) < n + 2:
            d = s.recv(65536)
            if not d: break
            bf[0] += d
        v = bf[0][:n].decode("utf-8", "replace")
        bf[0] = bf[0][n+2:]
        return v
    if t == "*":
        n = int(rest)
        return [rr(s, bf) for _ in range(max(n, 0))]
    return None

env = {}
for f in ["/home/mastodon/live/.env.production", "/var/www/mastodon/.env.production", "/opt/mastodon/.env.production"]:
    try:
        for line in open(f):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip(chr(34)+chr(39))
        break
    except: pass

url = env.get("REDIS_URL", "")
if url:
    u = up.urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 6379
    pw = u.password or env.get("REDIS_PASSWORD", "")
    db = int((u.path or "/0").lstrip("/") or "0")
else:
    host = env.get("REDIS_HOST", "127.0.0.1")
    port = int(env.get("REDIS_PORT", "6379") or "6379")
    pw = env.get("REDIS_PASSWORD", "")
    db = int(env.get("REDIS_DB", "0") or "0")

try:
    s = socket.socket()
    s.settimeout(8)
    s.connect((host, port))
    bf = [b""]
    if pw:
        rc(s, "AUTH", pw)
        rr(s, bf)
    rc(s, "SELECT", str(db))
    rr(s, bf)
    q_key = __QUEUEKEY__
    target_jid = __JID__
    cursor = "0"
    found_member = None
    found_job = None
    while True:
        rc(s, "ZSCAN", q_key, cursor, "COUNT", "200")
        result = rr(s, bf) or ["0", []]
        cursor = result[0] if result[0] else "0"
        items = result[1] or []
        for i in range(0, len(items), 2):
            try:
                job = json.loads(items[i])
                if job.get("jid") == target_jid:
                    found_member = items[i]
                    found_job = job
                    break
            except: pass
        if found_member is not None or cursor == "0":
            break
    if found_member is not None:
        queue = found_job.get("queue", "default")
        rc(s, "LPUSH", "queue:" + queue, found_member)
        rr(s, bf)
        rc(s, "ZREM", q_key, found_member)
        rr(s, bf)
        s.close()
        print("ok=1")
    else:
        s.close()
        print("error=job not found")
except Exception as e:
    print("error={}".format(str(e)[:120]))
"""


def sidekiq_retry_job(guest, service, queue_type, jid):
    """Re-enqueue a single job from a Sidekiq sorted-set queue for immediate processing.

    Returns (ok: bool, message: str).
    """
    if queue_type not in ("dead", "retry", "schedule"):
        return False, "Invalid queue type"
    if not _SIDEKIQ_JID_RE.match(jid):
        return False, "Invalid JID"
    script = _SIDEKIQ_RETRY_JOB_TEMPLATE
    script = script.replace(b"__QUEUEKEY__", repr(str(queue_type)).encode())
    script = script.replace(b"__JID__", repr(str(jid)).encode())
    _py_b64 = base64.b64encode(script).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"
    out, err = _execute_command(guest, cmd, timeout=30)
    if err and not out:
        return False, err
    for line in (out or "").split("\n"):
        line = line.strip()
        if line.startswith("ok="):
            return True, "Job re-queued for immediate processing"
        if line.startswith("error="):
            return False, line.split("=", 1)[1]
    return False, "No response from Redis"


def _safe_unit_name(name):
    """Validate a systemd unit name to prevent shell injection."""
    if not name or not _VALID_UNIT_RE.match(name):
        raise ValueError(f"Invalid systemd unit name: {name!r}")
    return name

def _has_valid_ip(guest):
    """Check if a guest has a usable IP address (not dhcp/auto placeholders)."""
    ip = guest.ip_address
    return bool(ip) and ip.lower() not in ("dhcp", "dhcp6", "auto")


APT_CHECK_CMD = "apt-get update -qq 2>/dev/null && apt-get -s upgrade 2>/dev/null"
APT_LIST_CMD = "apt list --upgradable 2>/dev/null"
APT_SECURITY_CMD = "apt-get -s upgrade 2>/dev/null | grep -i security"


def parse_upgradable(output):
    """Parse 'apt list --upgradable' output into package dicts."""
    packages = []
    for line in output.strip().split("\n"):
        if "/" not in line or "Listing..." in line:
            continue
        try:
            # Format: package/source version arch [upgradable from: old_version]
            name_part, rest = line.split("/", 1)
            parts = rest.split()
            available_version = parts[1] if len(parts) > 1 else "unknown"
            current_version = "unknown"
            if "upgradable from:" in line:
                current_version = line.split("upgradable from: ")[-1].rstrip("]").strip()
            packages.append({
                "name": name_part.strip(),
                "current_version": current_version,
                "available_version": available_version,
            })
        except (IndexError, ValueError) as e:
            logger.debug(f"Could not parse line: {line} ({e})")
    return packages


def determine_severity(package_name, security_output):
    """Check if a package appears in security upgrade output."""
    if security_output and package_name in security_output:
        return "critical"
    return "normal"


def _execute_on_guest(guest):
    """Execute APT commands on a guest and return (upgradable_output, security_output, error)."""
    # Try SSH first if configured
    if guest.connection_method in ("ssh", "auto") and _has_valid_ip(guest):
        credential = guest.credential
        if not credential:
            # Try default credential
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential and _has_valid_ip(guest):
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    # Update package lists (needs root)
                    ssh.execute_sudo("apt-get update -qq 2>/dev/null", timeout=120)
                    # Get upgradable list
                    stdout, stderr, code = ssh.execute(APT_LIST_CMD, timeout=60)
                    if code == 0:
                        # Check for security updates
                        sec_out, _, _ = ssh.execute_sudo(APT_SECURITY_CMD, timeout=60)
                        return stdout, sec_out, None
                    if guest.connection_method == "ssh":
                        return None, None, f"SSH apt list failed: {stderr}"
            except Exception as e:
                if guest.connection_method == "ssh":
                    return None, None, f"SSH failed: {e}"
                logger.debug(f"SSH failed for {guest.name}, trying agent: {e}")

    # Try QEMU guest agent
    if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            # Find the node this VM is on
            all_guests = client.get_all_guests()
            node = None
            for g in all_guests:
                if g.get("vmid") == guest.vmid:
                    node = g.get("node")
                    break

            if node:
                # Update apt
                client.exec_guest_agent(node, guest.vmid, "apt-get update -qq")
                # Get upgradable — no shell redirection needed; agent separates stdout/stderr
                stdout, err = client.exec_guest_agent(node, guest.vmid, "apt list --upgradable")
                if err is None:
                    # Pipe requires a shell; wrap in sh -c
                    sec_cmd = "apt-get -s upgrade 2>/dev/null | grep -i security"
                    sec_out, _ = client.exec_guest_agent(node, guest.vmid, f"sh -c {shlex.quote(sec_cmd)}")
                    return stdout, sec_out, None
                return None, None, f"Agent exec failed: {err}"
            return None, None, f"Could not find VM {guest.vmid} on any node"
        except Exception as e:
            return None, None, f"Agent failed: {e}"

    return None, None, "No viable connection method available"


def _execute_command(guest, command, timeout=60, sudo=False):
    """Execute a single command on a guest via SSH or agent. Returns (stdout, error).

    If sudo=True, wraps the command with sudo when connected as a non-root user.
    """
    if guest.connection_method in ("ssh", "auto") and _has_valid_ip(guest):
        credential = guest.credential
        if not credential:
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential and _has_valid_ip(guest):
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    if sudo:
                        stdout, stderr, code = ssh.execute_sudo(command, timeout=timeout)
                    else:
                        stdout, stderr, code = ssh.execute(command, timeout=timeout)
                    if code == 0:
                        return stdout, None
                    if guest.connection_method == "ssh":
                        return stdout, stderr or f"Exit code {code}"
            except Exception as e:
                if guest.connection_method == "ssh":
                    return None, f"SSH failed: {e}"
                logger.debug(f"SSH failed for {guest.name}, trying agent: {e}")

    if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            node = client.find_guest_node(guest.vmid)
            if node:
                # Wrap in sh -c so shell features (redirects, pipes, ||) work via guest agent
                stdout, err = client.exec_guest_agent(node, guest.vmid, f"sh -c {shlex.quote(command)}")
                return stdout, err
            return None, f"Could not find VM {guest.vmid} on any node"
        except Exception as e:
            return None, f"Agent failed: {e}"

    return None, "No viable connection method available"


def _map_systemctl_status(status_str):
    """Map systemctl is-active output to our status strings."""
    if status_str == "active":
        return "running"
    elif status_str == "inactive":
        return "stopped"
    elif status_str == "failed":
        return "failed"
    return "unknown"


def detect_services(guest):
    """Detect known services on a guest via systemctl. Called during scan."""
    now = datetime.now(timezone.utc)

    # Split services into fixed and glob patterns
    fixed_services = {}
    glob_services = {}
    for key, (display_name, unit_name, default_port) in GuestService.KNOWN_SERVICES.items():
        if "*" in unit_name:
            glob_services[key] = (display_name, unit_name, default_port)
        else:
            fixed_services[key] = (display_name, unit_name, default_port)

    # Check fixed services with a single systemctl call
    if fixed_services:
        unit_names = [info[1] for info in fixed_services.values()]
        cmd = "systemctl is-active " + " ".join(unit_names) + " 2>/dev/null"
        stdout, error = _execute_command(guest, cmd)

        if stdout or not error:
            lines = (stdout or "").strip().split("\n")
            for i, (key, (_display_name, unit_name, default_port)) in enumerate(fixed_services.items()):
                status_str = lines[i].strip() if i < len(lines) else "unknown"
                status = _map_systemctl_status(status_str)
                _upsert_service(guest, key, unit_name, default_port, status, now)

    # Discover glob-pattern services (e.g., mastodon-sidekiq*.service)
    for key, (_display_name, unit_pattern, default_port) in glob_services.items():
        cmd = f"systemctl list-units '{unit_pattern}' --no-legend --plain 2>/dev/null"
        stdout, error = _execute_command(guest, cmd)
        if not stdout:
            continue
        for line in stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) < 3:
                continue
            discovered_unit = parts[0]  # e.g. mastodon-sidekiq1.service
            active_state = parts[2]     # active/inactive/failed
            status = _map_systemctl_status(active_state)
            _upsert_service(guest, key, discovered_unit, default_port, status, now)

    db.session.commit()


def _upsert_service(guest, service_key, unit_name, default_port, status, now):
    """Create or update a GuestService record."""
    try:
        _safe_unit_name(unit_name)
    except ValueError:
        logger.warning(f"Skipping service with invalid unit name: {unit_name!r}")
        return
    existing = GuestService.query.filter_by(guest_id=guest.id, unit_name=unit_name).first()
    if status in ("running", "failed"):
        if existing:
            old_status = existing.status
            existing.status = status
            existing.last_checked = now
            # Notifications on state transitions
            if status == "failed" and old_status != "failed":
                try:
                    from core.notifier import guest_matches_notify_tags, send_service_failed_notification
                    if guest_matches_notify_tags(guest):
                        send_service_failed_notification(guest.name, service_key)
                except Exception:
                    pass
                try:
                    from core.push_notifier import dispatch_push_alerts
                    dispatch_push_alerts(guest, "service_failed", {"service": service_key, "unit": unit_name})
                except Exception:
                    pass
            elif status == "running" and old_status == "failed":
                try:
                    from core.notifier import guest_matches_notify_tags, send_service_recovery_notification
                    if guest_matches_notify_tags(guest):
                        send_service_recovery_notification(guest.name, service_key)
                except Exception:
                    pass
                try:
                    from core.push_notifier import dispatch_push_alerts
                    dispatch_push_alerts(guest, "service_recovered", {"service": service_key, "unit": unit_name})
                except Exception:
                    pass
        else:
            svc = GuestService(
                guest_id=guest.id,
                service_name=service_key,
                unit_name=unit_name,
                port=default_port,
                status=status,
                last_checked=now,
                auto_detected=True,
            )
            db.session.add(svc)
            if status == "failed":
                try:
                    from core.notifier import guest_matches_notify_tags, send_service_failed_notification
                    if guest_matches_notify_tags(guest):
                        send_service_failed_notification(guest.name, service_key)
                except Exception:
                    pass
                try:
                    from core.push_notifier import dispatch_push_alerts
                    dispatch_push_alerts(guest, "service_failed", {"service": service_key, "unit": unit_name})
                except Exception:
                    pass
    elif status == "stopped" and existing:
        existing.status = status
        existing.last_checked = now


def check_service_statuses(guest):
    """Lightweight status refresh for all services on a guest."""
    if not guest.services:
        return

    unit_names = [_safe_unit_name(svc.unit_name) for svc in guest.services]
    cmd = "systemctl is-active " + " ".join(unit_names) + " 2>/dev/null"
    stdout, error = _execute_command(guest, cmd)

    if error and not stdout:
        logger.debug(f"Service status check failed for {guest.name}: {error}")
        return

    lines = (stdout or "").strip().split("\n")
    now = datetime.now(timezone.utc)

    for i, svc in enumerate(guest.services):
        status_str = lines[i].strip() if i < len(lines) else "unknown"
        if status_str == "active":
            svc.status = "running"
        elif status_str == "inactive":
            svc.status = "stopped"
        elif status_str == "failed":
            svc.status = "failed"
        else:
            svc.status = "unknown"
        svc.last_checked = now

    db.session.commit()


def service_action(guest, service, action):
    """Execute start/stop/restart on a service. Returns (success, output)."""
    if action not in ("start", "stop", "restart"):
        return False, "Invalid action"

    try:
        unit = _safe_unit_name(service.unit_name)
    except ValueError as e:
        return False, str(e)

    cmd = f"systemctl {action} {unit}"
    stdout, error = _execute_command(guest, cmd, timeout=30, sudo=True)

    if error:
        return False, error

    # Refresh status after action
    status_out, _ = _execute_command(guest, f"systemctl is-active {unit} 2>/dev/null")
    now = datetime.now(timezone.utc)
    status_str = (status_out or "").strip()
    if status_str == "active":
        service.status = "running"
    elif status_str == "inactive":
        service.status = "stopped"
    elif status_str == "failed":
        service.status = "failed"
    else:
        service.status = "unknown"
    service.last_checked = now
    db.session.commit()

    return True, stdout or f"{action.capitalize()} command sent"


def get_service_logs(guest, service, lines=50):
    """Fetch recent journal logs for a service. Returns log text."""
    try:
        unit = _safe_unit_name(service.unit_name)
    except ValueError as e:
        return f"Error: {e}"
    lines = int(lines)
    cmd = f"journalctl -u {unit} -n {lines} --no-pager 2>/dev/null"
    stdout, error = _execute_command(guest, cmd, timeout=30)
    if error:
        return f"Error fetching logs: {error}"

    # postgresql.service is a meta/target unit on Debian/Ubuntu; its journal has
    # very few entries.  Fall back to the real cluster unit for useful log output.
    if service.service_name == "postgresql" and (
        not stdout or "No entries" in stdout or not stdout.strip()
    ):
        cluster_out, _ = _execute_command(
            guest,
            "systemctl list-units 'postgresql@*.service' --no-legend --plain 2>/dev/null",
            timeout=10,
        )
        if cluster_out:
            first_line = cluster_out.strip().split("\n")[0].strip()
            cluster_unit = first_line.split()[0] if first_line else ""
            if cluster_unit and _VALID_UNIT_RE.match(cluster_unit):
                cmd2 = f"journalctl -u {cluster_unit} -n {lines} --no-pager 2>/dev/null"
                stdout2, _ = _execute_command(guest, cmd2, timeout=30)
                if stdout2 and stdout2.strip():
                    return stdout2

    return stdout or "No log output"


def _parse_systemd_props(output):
    """Parse systemctl show output into a dict."""
    props = {}
    for line in (output or "").strip().split("\n"):
        if "=" in line:
            key, _, val = line.partition("=")
            props[key.strip()] = val.strip()
    return props


def _human_bytes(n):
    """Convert bytes to human-readable string."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _parse_redis_info(output):
    """Parse redis-cli info output into a dict."""
    info = {}
    for line in (output or "").strip().split("\n"):
        line = line.strip()
        if ":" in line and not line.startswith("#"):
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    return info


def get_service_stats(guest, service):
    """Fetch service-specific stats via SSH. Returns a dict with stats and a 'type' key."""

    stype = service.service_name
    stats = {"type": stype, "error": None}

    # Common: get systemd resource usage
    unit = _safe_unit_name(service.unit_name)
    props_cmd = f"systemctl show {unit} --property=MemoryCurrent,CPUUsageNSec,MainPID,ActiveState,ActiveEnterTimestamp 2>/dev/null"
    props_out, _ = _execute_command(guest, props_cmd, timeout=15)
    props = _parse_systemd_props(props_out)

    mem_current = props.get("MemoryCurrent", "")
    if mem_current and mem_current not in ("[not set]", "infinity", ""):
        try:
            stats["memory_bytes"] = int(mem_current)
            stats["memory_human"] = _human_bytes(int(mem_current))
        except ValueError:
            pass

    cpu_ns = props.get("CPUUsageNSec", "")
    if cpu_ns and cpu_ns not in ("[not set]", ""):
        try:
            secs = int(cpu_ns) / 1_000_000_000
            if secs >= 3600:
                stats["cpu_time"] = f"{secs / 3600:.1f}h"
            elif secs >= 60:
                stats["cpu_time"] = f"{secs / 60:.1f}m"
            else:
                stats["cpu_time"] = f"{secs:.1f}s"
        except ValueError:
            pass

    main_pid = props.get("MainPID", "")
    stats["pid"] = main_pid if main_pid and main_pid != "0" else ""
    stats["active_state"] = props.get("ActiveState", "")
    active_enter = props.get("ActiveEnterTimestamp", "")
    if active_enter and active_enter not in ("n/a", ""):
        stats["started_at"] = active_enter

    # Service-specific stats
    try:
        if stype == "elasticsearch":
            stats.update(_stats_elasticsearch(guest, service))
        elif stype == "redis":
            stats.update(_stats_redis(guest, service))
        elif stype == "postgresql":
            stats.update(_stats_postgresql(guest))
        elif stype == "puma":
            stats.update(_stats_puma(guest, service))
        elif stype == "sidekiq":
            stats.update(_stats_sidekiq(guest, service))
        elif stype == "libretranslate":
            stats.update(_stats_libretranslate(guest, service))
        elif stype == "jitsi-videobridge2":
            stats.update(_stats_jitsi_videobridge(guest, service))
        elif stype == "prometheus":
            stats.update(_stats_prometheus(guest, service))
    except Exception as e:
        logger.error(f"Error collecting {stype} stats for {guest.name}: {e}")
        stats["error"] = str(e)

    return stats


def _stats_elasticsearch(guest, service):
    """Collect Elasticsearch stats."""
    import json as _json
    port = service.port or 9200
    stats = {}

    # Version from root endpoint
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/ 2>/dev/null", timeout=10)
    if out:
        try:
            root = _json.loads(out)
            stats["es_version"] = root.get("version", {}).get("number", "")
        except _json.JSONDecodeError:
            pass

    # Cluster health
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/_cluster/health 2>/dev/null", timeout=15)
    if out:
        try:
            health = _json.loads(out)
            stats["cluster_status"] = health.get("status", "unknown")
            stats["cluster_name"] = health.get("cluster_name", "")
            stats["node_count"] = health.get("number_of_nodes", 0)
            stats["active_shards"] = health.get("active_shards", 0)
            stats["relocating_shards"] = health.get("relocating_shards", 0)
            stats["unassigned_shards"] = health.get("unassigned_shards", 0)
        except _json.JSONDecodeError:
            pass

    # Cluster stats (doc count, store size)
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/_cluster/stats 2>/dev/null", timeout=15)
    if out:
        try:
            cstats = _json.loads(out)
            indices = cstats.get("indices", {})
            stats["index_count"] = indices.get("count", 0)
            docs = indices.get("docs", {})
            stats["doc_count"] = docs.get("count", 0)
            store = indices.get("store", {})
            stats["store_size_bytes"] = store.get("size_in_bytes", 0)
            stats["store_size"] = _human_bytes(store.get("size_in_bytes", 0))
        except _json.JSONDecodeError:
            pass

    # JVM heap + OS CPU + disk FS (combined call)
    out, _ = _execute_command(guest, f"curl -s localhost:{port}/_nodes/stats/jvm,os,fs 2>/dev/null", timeout=15)
    if out:
        try:
            jvm_data = _json.loads(out)
            nodes = jvm_data.get("nodes", {})
            total_heap_used = 0
            total_heap_max = 0
            total_cpu = 0
            node_count_for_avg = 0
            total_disk_free = 0
            total_disk_total = 0
            for node_info in nodes.values():
                jvm = node_info.get("jvm", {}).get("mem", {})
                total_heap_used += jvm.get("heap_used_in_bytes", 0)
                total_heap_max += jvm.get("heap_max_in_bytes", 0)
                cpu_pct = node_info.get("os", {}).get("cpu", {}).get("percent", None)
                if cpu_pct is not None:
                    total_cpu += cpu_pct
                    node_count_for_avg += 1
                fs = node_info.get("fs", {}).get("total", {})
                total_disk_free += fs.get("free_in_bytes", 0)
                total_disk_total += fs.get("total_in_bytes", 0)
            stats["jvm_heap_used"] = _human_bytes(total_heap_used)
            stats["jvm_heap_max"] = _human_bytes(total_heap_max)
            if total_heap_max > 0:
                stats["jvm_heap_percent"] = round(total_heap_used / total_heap_max * 100, 1)
            if node_count_for_avg > 0:
                stats["cpu_percent"] = round(total_cpu / node_count_for_avg, 1)
            if total_disk_total > 0:
                disk_used = total_disk_total - total_disk_free
                stats["disk_total"] = _human_bytes(total_disk_total)
                stats["disk_used"] = _human_bytes(disk_used)
                stats["disk_percent"] = round(disk_used / total_disk_total * 100, 1)
        except _json.JSONDecodeError:
            pass

    # Per-node stats
    out, _ = _execute_command(
        guest,
        f"curl -s 'localhost:{port}/_cat/nodes?format=json&h=name,ip,heap.percent,cpu,load_1m,node.role' 2>/dev/null",
        timeout=15,
    )
    if out:
        try:
            stats["nodes"] = _json.loads(out)
        except _json.JSONDecodeError:
            pass

    # Per-index stats
    out, _ = _execute_command(guest, f"curl -s 'localhost:{port}/_cat/indices?format=json&h=index,health,status,docs.count,store.size,pri,rep' 2>/dev/null", timeout=15)
    if out:
        try:
            stats["indices"] = _json.loads(out)
        except _json.JSONDecodeError:
            pass

    return stats


def _stats_redis(guest, service):
    """Collect Redis stats."""
    stats = {}
    port = service.port or 6379

    # Single SSH call: detect password, then run redis-cli info all.
    #
    # Password detection order:
    #   1. requirepass in Redis server config files
    #   2. REDIS_PASSWORD in Mastodon .env.production (multiple common paths)
    #
    # REDISCLI_AUTH env var is used so the password never appears in the
    # process list via -a.  || true forces exit 0 so _execute_command in
    # auto connection mode (LXC containers) returns stdout rather than
    # discarding it and falling through to the QEMU guest agent.
    redis_script = (
        "_RP=\"\";"
        " for _F in /etc/redis/redis.conf /etc/redis/redis-server.conf /etc/redis.conf; do"
        "   _RP=$(grep -i \"^requirepass\" \"$_F\" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\"');"
        "   [ -n \"$_RP\" ] && break;"
        " done;"
        " [ -z \"$_RP\" ] && _RP=$(grep \"^REDIS_PASSWORD=\""
        " /home/mastodon/live/.env.production"
        " /var/www/mastodon/.env.production"
        " /opt/mastodon/.env.production"
        " 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\"');"
        f" REDISCLI_AUTH=\"$_RP\" redis-cli -p {port} info all 2>/dev/null || true"
    )

    out, _ = _execute_command(guest, redis_script, timeout=30, sudo=True)
    info = _parse_redis_info(out)

    if info:
        # Server
        stats["redis_version"] = info.get("redis_version", "")
        uptime_s = int(info.get("uptime_in_seconds", 0) or 0)
        _days, _rem = divmod(uptime_s, 86400)
        _hours, _rem = divmod(_rem, 3600)
        _mins = _rem // 60
        _parts = []
        if _days:
            _parts.append(f"{_days}d")
        if _hours:
            _parts.append(f"{_hours}h")
        if not _days:
            _parts.append(f"{_mins}m")
        stats["uptime_human"] = " ".join(_parts) or "0m"

        # Memory
        stats["used_memory"] = info.get("used_memory_human", "")
        stats["used_memory_rss"] = info.get("used_memory_rss_human", "")
        stats["used_memory_peak"] = info.get("used_memory_peak_human", "")
        stats["used_memory_bytes"] = info.get("used_memory", "0")
        _maxmem_raw = info.get("maxmemory", "0")
        stats["maxmemory"] = "No limit" if _maxmem_raw in ("0", "") else info.get("maxmemory_human", "No limit")
        stats["maxmemory_policy"] = info.get("maxmemory_policy", "")
        _frag = info.get("mem_fragmentation_ratio", "")
        stats["mem_fragmentation_ratio"] = _frag

        # Clients
        stats["connected_clients"] = info.get("connected_clients", "0")
        stats["blocked_clients"] = info.get("blocked_clients", "0")
        stats["total_connections"] = info.get("total_connections_received", "0")

        # Stats / evictions
        stats["ops_per_sec"] = info.get("instantaneous_ops_per_sec", "0")
        hits = int(info.get("keyspace_hits", 0) or 0)
        misses = int(info.get("keyspace_misses", 0) or 0)
        total = hits + misses
        stats["keyspace_hits"] = hits
        stats["keyspace_misses"] = misses
        stats["hit_ratio"] = f"{(hits / total * 100):.1f}%" if total > 0 else "N/A"
        stats["total_commands"] = info.get("total_commands_processed", "0")
        stats["evicted_keys"] = int(info.get("evicted_keys", 0) or 0)
        stats["expired_keys"] = int(info.get("expired_keys", 0) or 0)

        # Network I/O
        stats["net_input_kbps"] = info.get("instantaneous_input_kbps", "0")
        stats["net_output_kbps"] = info.get("instantaneous_output_kbps", "0")
        stats["net_input_bytes"] = _human_bytes(int(info.get("total_net_input_bytes", 0) or 0))
        stats["net_output_bytes"] = _human_bytes(int(info.get("total_net_output_bytes", 0) or 0))

        # Persistence
        stats["rdb_changes"] = int(info.get("rdb_changes_since_last_save", 0) or 0)
        stats["rdb_last_save_ts"] = int(info.get("rdb_last_save_time", 0) or 0)
        stats["rdb_bgsave_status"] = info.get("rdb_last_bgsave_status", "")
        stats["aof_enabled"] = info.get("aof_enabled", "0") == "1"
        stats["aof_rewrite_status"] = info.get("aof_last_bgrewrite_status", "")

        # Replication
        stats["role"] = info.get("role", "")
        stats["connected_slaves"] = int(info.get("connected_slaves", 0) or 0)
        stats["repl_backlog_size"] = _human_bytes(int(info.get("repl_backlog_size", 0) or 0))
        stats["master_host"] = info.get("master_host", "")
        stats["master_port"] = info.get("master_port", "")
        stats["master_link_status"] = info.get("master_link_status", "")
        stats["master_sync_in_progress"] = info.get("master_sync_in_progress", "0") == "1"

    # Keyspace (always set, may be empty) — parsed into structured dicts
    keyspace = {}
    for key, val in info.items():
        if key.startswith("db"):
            entry = {}
            for part in val.split(","):
                k, _, v = part.partition("=")
                try:
                    entry[k.strip()] = int(v.strip())
                except ValueError:
                    entry[k.strip()] = v.strip()
            keyspace[key] = entry
    stats["keyspace"] = keyspace

    return stats


def _stats_postgresql(guest):
    """Collect PostgreSQL stats."""
    stats = {}

    # Server version
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SHOW server_version\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["pg_version"] = out.strip()

    # Database sizes + per-db commits/rollbacks/temp files
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT datname, pg_database_size(datname), xact_commit, xact_rollback, temp_files, temp_bytes "
        "FROM pg_stat_database JOIN pg_database USING (datname) "
        "WHERE datistemplate = false ORDER BY pg_database_size(datname) DESC"
        "\" 2>/dev/null",
        timeout=15, sudo=True)
    if out:
        databases = []
        for line in out.strip().split("\n"):
            parts = line.strip().split("|")
            if len(parts) == 6:
                size_bytes = int(parts[1]) if parts[1].isdigit() else 0
                temp_bytes = int(parts[5]) if parts[5].isdigit() else 0
                databases.append({
                    "name": parts[0],
                    "size_bytes": size_bytes,
                    "size": _human_bytes(size_bytes),
                    "commits": int(parts[2]) if parts[2].isdigit() else 0,
                    "rollbacks": int(parts[3]) if parts[3].isdigit() else 0,
                    "temp_files": int(parts[4]) if parts[4].isdigit() else 0,
                    "temp_bytes": _human_bytes(temp_bytes),
                })
        stats["databases"] = databases

    # Active query count
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT count(*) FROM pg_stat_activity WHERE state = 'active'\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["active_queries"] = out.strip()

    # Active/non-idle query list with durations and pid (for kill action)
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT pid, datname, usename, state, "
        "round(extract(epoch from (now() - query_start))::numeric, 1), "
        "replace(replace(left(query, 4096), chr(10), ' '), chr(13), ' ') "
        "FROM pg_stat_activity WHERE pid != pg_backend_pid() "
        "AND state IS NOT NULL AND state != 'idle' "
        "ORDER BY (now() - query_start) DESC NULLS LAST"
        "\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        query_list = []
        for line in out.strip().split("\n"):
            parts = line.strip().split("|", 5)
            if len(parts) == 6:
                try:
                    secs = float(parts[4])
                except ValueError:
                    secs = 0.0
                if secs >= 3600:
                    duration = f"{int(secs // 3600)}h {int((secs % 3600) // 60)}m"
                elif secs >= 60:
                    duration = f"{int(secs // 60)}m {int(secs % 60)}s"
                else:
                    duration = f"{secs:.1f}s"
                query_list.append({
                    "pid": parts[0],
                    "datname": parts[1] or "—",
                    "usename": parts[2] or "—",
                    "state": parts[3],
                    "duration": duration,
                    "duration_secs": secs,
                    "query": parts[5],
                })
        stats["active_query_list"] = query_list

    # Total connections
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT sum(numbackends) FROM pg_stat_database\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["total_connections"] = out.strip()

    # Max connections
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SHOW max_connections\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        stats["max_connections"] = out.strip()

    # Cache hit ratio
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT round(sum(blks_hit)::numeric / nullif(sum(blks_hit) + sum(blks_read), 0) * 100, 2) FROM pg_stat_database\" 2>/dev/null",
        timeout=10, sudo=True)
    if out and out.strip():
        stats["cache_hit_ratio"] = f"{out.strip()}%"

    # Transactions
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \"SELECT sum(xact_commit), sum(xact_rollback) FROM pg_stat_database\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        parts = out.strip().split("|")
        if len(parts) == 2:
            stats["total_commits"] = parts[0].strip()
            stats["total_rollbacks"] = parts[1].strip()

    # postgresql.service is a meta/target unit on Debian/Ubuntu with no MainPID.
    # Discover the real cluster unit (e.g. postgresql@16-main.service) to get
    # accurate memory, CPU, and PID stats.
    cluster_out, _ = _execute_command(
        guest,
        "systemctl list-units 'postgresql@*.service' --no-legend --plain 2>/dev/null",
        timeout=10,
    )
    if cluster_out:
        first_line = cluster_out.strip().split("\n")[0].strip()
        cluster_unit = first_line.split()[0] if first_line else ""
        if cluster_unit and _VALID_UNIT_RE.match(cluster_unit):
            cprops_out, _ = _execute_command(
                guest,
                f"systemctl show {cluster_unit} --property=MemoryCurrent,CPUUsageNSec,MainPID 2>/dev/null",
                timeout=10,
            )
            cprops = _parse_systemd_props(cprops_out)

            mem = cprops.get("MemoryCurrent", "")
            if mem and mem not in ("[not set]", "infinity", ""):
                try:
                    stats["memory_bytes"] = int(mem)
                    stats["memory_human"] = _human_bytes(int(mem))
                except ValueError:
                    pass

            cpu_ns = cprops.get("CPUUsageNSec", "")
            if cpu_ns and cpu_ns not in ("[not set]", ""):
                try:
                    secs = int(cpu_ns) / 1_000_000_000
                    if secs >= 3600:
                        stats["cpu_time"] = f"{secs / 3600:.1f}h"
                    elif secs >= 60:
                        stats["cpu_time"] = f"{secs / 60:.1f}m"
                    else:
                        stats["cpu_time"] = f"{secs:.1f}s"
                except ValueError:
                    pass

            main_pid = cprops.get("MainPID", "")
            if main_pid and main_pid != "0":
                stats["pid"] = main_pid

    # Connection state breakdown
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT coalesce(state, 'unknown'), count(*) FROM pg_stat_activity "
        "WHERE pid != pg_backend_pid() GROUP BY state"
        "\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        conn_states = {}
        for line in out.strip().split("\n"):
            parts = line.strip().split("|")
            if len(parts) == 2:
                try:
                    conn_states[parts[0]] = int(parts[1])
                except ValueError:
                    pass
        stats["connection_states"] = conn_states

    # Lock wait count
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'"
        "\" 2>/dev/null",
        timeout=10, sudo=True)
    if out and out.strip().isdigit():
        stats["lock_waits"] = int(out.strip())

    # Temp file stats (aggregate across all databases)
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT coalesce(sum(temp_files),0), coalesce(sum(temp_bytes),0) FROM pg_stat_database"
        "\" 2>/dev/null",
        timeout=10, sudo=True)
    if out:
        parts = out.strip().split("|")
        if len(parts) == 2:
            try:
                stats["temp_files_total"] = int(parts[0])
                stats["temp_bytes_total"] = _human_bytes(int(parts[1]))
            except ValueError:
                pass

    # Unused indexes count
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT count(*) FROM pg_stat_user_indexes WHERE idx_scan = 0"
        "\" 2>/dev/null",
        timeout=10, sudo=True)
    if out and out.strip().isdigit():
        stats["unused_indexes"] = int(out.strip())

    # Replication replica count
    out, _ = _execute_command(guest,
        "sudo -u postgres psql -t -A -c \""
        "SELECT count(*) FROM pg_stat_replication"
        "\" 2>/dev/null",
        timeout=10, sudo=True)
    if out and out.strip().isdigit():
        stats["replication_replicas"] = int(out.strip())

    # Table stats — pg_stat_user_tables is per-database, so target the largest
    # non-system database (most likely to have application tables).
    _system_dbs = {"postgres", "template0", "template1"}
    _table_target_db = next(
        (db["name"] for db in stats.get("databases", []) if db["name"] not in _system_dbs),
        None,
    )
    if _table_target_db:
        out, _ = _execute_command(guest,
            f"sudo -u postgres psql -d {_table_target_db} -t -A -c \""  # noqa: S608 — db name sourced from pg_database, not user input
            "SELECT schemaname, relname, "
            "coalesce(n_live_tup,0), coalesce(n_dead_tup,0), "
            "coalesce(to_char(greatest(last_vacuum, last_autovacuum), 'YYYY-MM-DD HH24:MI'), '-'), "
            "coalesce(to_char(greatest(last_analyze, last_autoanalyze), 'YYYY-MM-DD HH24:MI'), '-'), "
            "pg_relation_size(relid) "
            "FROM pg_stat_user_tables "
            "ORDER BY n_dead_tup DESC NULLS LAST LIMIT 25"
            "\" 2>/dev/null",
            timeout=15, sudo=True)
        if out:
            tables = []
            for line in out.strip().split("\n"):
                parts = line.strip().split("|")
                if len(parts) == 7:
                    try:
                        rel_size = int(parts[6]) if parts[6].isdigit() else 0
                        tables.append({
                            "schema": parts[0],
                            "table": parts[1],
                            "live_tup": int(parts[2]),
                            "dead_tup": int(parts[3]),
                            "last_vacuum": parts[4],
                            "last_analyze": parts[5],
                            "size": _human_bytes(rel_size),
                            "size_bytes": rel_size,
                        })
                    except (ValueError, IndexError):
                        pass
            if tables:
                stats["tables"] = tables
                stats["tables_database"] = _table_target_db

    # Historical slow queries from pg_stat_statements (graceful if extension absent).
    # pg_stat_statements must be queried from the database where the extension is
    # installed — typically the application DB, not the default "postgres" DB.
    # Use the largest non-template DB we already collected; fall back to "postgres".
    _ss_db = "postgres"
    for _db in stats.get("databases", []):
        _db_name = _db.get("name", "")
        if _db_name and _db_name not in ("postgres", "template0", "template1"):
            _ss_db = _db_name
            break
    out, _ = _execute_command(guest,
        f"sudo -u postgres psql -d {_ss_db} -t -A -c \""  # noqa: S608
        "SELECT round(mean_exec_time::numeric,2), calls, "
        "round(total_exec_time::numeric,2), rows, "
        "replace(replace(left(query,4096),chr(10),' '),chr(13),' ') "
        "FROM pg_stat_statements "
        "WHERE mean_exec_time IS NOT NULL "
        "ORDER BY mean_exec_time DESC LIMIT 15"
        "\" 2>/dev/null",
        timeout=15, sudo=True)
    if out and out.strip():
        slow = []
        for line in out.strip().split("\n"):
            parts = line.strip().split("|", 4)
            if len(parts) == 5:
                try:
                    slow.append({
                        "mean_ms": float(parts[0]),
                        "calls": int(parts[1]),
                        "total_ms": float(parts[2]),
                        "rows": int(parts[3]),
                        "query": parts[4],
                    })
                except (ValueError, IndexError):
                    pass
        if slow:
            stats["slow_query_stats"] = slow

    return stats


def _stats_puma(guest, service):
    """Collect Puma/mastodon-web stats."""
    stats = {}
    port = service.port or 3000

    # ── 1. Health endpoint ────────────────────────────────────────────────────
    out, _ = _execute_command(
        guest,
        f"curl -s -o /dev/null -w '%{{http_code}}' localhost:{port}/health 2>/dev/null",
        timeout=10,
    )
    if out:
        stats["health_status"] = "OK" if out.strip() == "200" else f"HTTP {out.strip()}"

    # ── 2. Puma version — read from running process name ─────────────────────
    # The puma master process title always contains the version string:
    #   "puma 6.4.0 (tcp://0.0.0.0:3000) [mastodon]"
    # This works regardless of file permissions or install path.
    out, _ = _execute_command(
        guest,
        "ps aux 2>/dev/null | grep '[p]uma' | grep -v worker"
        r" | grep -oP 'puma \K[0-9]+\.[0-9]+\.[0-9]+' | head -1",
        timeout=10,
    )
    v = (out or "").strip()
    if v:
        stats["puma_version"] = v

    # ── 3. MainPID — parsed robustly for all systemd versions ────────────────
    # --value is not available on all systemd versions; grep -oP '\d+' handles
    # both "1744132" and "MainPID=1744132" output formats.
    # head -1 ensures exit code 0 even if grep finds nothing.
    out, _ = _execute_command(
        guest,
        "systemctl show mastodon-web.service --property=MainPID 2>/dev/null"
        " | grep -oP '\\d+' | head -1",
        timeout=10,
    )
    pid = (out or "").strip()

    if pid and pid.isdigit() and pid != "0":
        # ── 4a. Thread + worker config from process environment ───────────────
        for env_var, stat_key in [
            ("WEB_CONCURRENCY", "workers"),
            ("RAILS_MAX_THREADS", "max_threads"),
            ("RAILS_MIN_THREADS", "min_threads"),
        ]:
            out, _ = _execute_command(
                guest,
                f"tr '\\0' '\\n' < /proc/{pid}/environ 2>/dev/null"
                f" | grep '^{env_var}=' | head -1",
                timeout=10,
            )
            line = (out or "").strip()
            if "=" in line:
                val = line.split("=", 1)[1].strip()
                try:
                    stats[stat_key] = int(val)
                except ValueError:
                    pass

    # Mastodon's compiled-in default is 5 threads when RAILS_MAX_THREADS is unset
    if "max_threads" not in stats:
        stats["max_threads"] = 5
    if "min_threads" not in stats:
        stats["min_threads"] = stats["max_threads"]

    # ── 5. Worker process listing — grep+head replaces awk ───────────────────
    # grep '[p]uma' | grep worker | head avoids awk (which may exit non-zero on
    # some implementations) and always produces exit 0 via head.
    out, _ = _execute_command(
        guest,
        "ps aux 2>/dev/null | grep '[p]uma' | grep worker | head -200",
        timeout=10,
    )
    if out and out.strip():
        procs = []
        for line in out.strip().split("\n"):
            # ps aux columns (0-indexed): USER PID %CPU %MEM VSZ RSS ...
            parts = line.split()
            if len(parts) >= 6:
                try:
                    rss_kb = int(parts[5])
                    procs.append({
                        "pid": parts[1],
                        "cpu_pct": parts[2],
                        "mem_human": _human_bytes(rss_kb * 1024),
                    })
                except (ValueError, IndexError):
                    pass
        if procs:
            stats["worker_processes"] = procs
            if "workers" not in stats:
                stats["workers"] = len(procs)

    return stats


def _stats_sidekiq(guest, service):
    """Collect Sidekiq stats — per-instance systemd info plus aggregate queue stats from Redis."""
    stats = {}

    # Sidekiq version from process title (e.g. "sidekiq 7.3.2 app [0 of 10 busy]")
    out, _ = _execute_command(
        guest,
        r"ps aux 2>/dev/null | grep '[s]idekiq' | grep -oP 'sidekiq \K[0-9]+\.[0-9]+\.[0-9]+' | head -1",
        timeout=10,
    )
    v = (out or "").strip()
    if v:
        stats["sidekiq_version"] = v

    # Use a pure-Python3 Redis client (no redis-cli needed) — Sidekiq servers
    # connect to Redis via the Ruby gem so redis-cli is often absent.
    # The script is base64-encoded to avoid any shell quoting issues.
    _py_b64 = base64.b64encode(_SIDEKIQ_REDIS_SCRIPT).decode()
    redis_script = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null || true"

    out, _ = _execute_command(guest, redis_script, timeout=30)

    queues = []
    kv = {}
    debug_kv = {}
    workers_list = []
    paused_queues = []
    section = None
    for line in (out or "").split("\n"):
        line = line.strip()
        if line == "---queues---":
            section = "queues"
        elif line == "---stats---":
            section = "stats"
        elif line == "---workers---":
            section = "workers"
        elif line == "---paused---":
            section = "paused"
        elif line == "---debug---":
            section = "debug"
        elif section == "queues" and "=" in line:
            name, _, rest = line.partition("=")
            size_str, _, lat_str = rest.strip().partition("|")
            size = int(size_str) if size_str.isdigit() else 0
            try:
                lat_secs = float(lat_str) if lat_str else 0.0
            except ValueError:
                lat_secs = 0.0
            queues.append({
                "name": name.strip(),
                "size": size,
                "latency_secs": lat_secs,
                "latency": _format_elapsed(lat_secs) if lat_secs > 0 else ("< 1s" if size > 0 else "—"),
            })
        elif section == "stats" and "=" in line:
            key, _, val = line.partition("=")
            kv[key.strip()] = val.strip()
        elif section == "debug" and "=" in line:
            key, _, val = line.partition("=")
            debug_kv[key.strip()] = val.strip()
        elif section == "workers" and line.startswith("worker="):
            raw = line[len("worker="):]
            parts = raw.split("|", 5)
            if len(parts) == 6:
                hostname, pid, concurrency_s, busy_s, beat_raw, queues_json = parts
                beat_age = None
                try:
                    beat_ts = float(beat_raw)
                    if beat_ts > 0:
                        now_ts = datetime.now(timezone.utc).timestamp()
                        beat_age = int(now_ts - beat_ts)
                except (ValueError, TypeError):
                    pass
                try:
                    queues_l = json.loads(queues_json)
                    queues_csv = ", ".join(str(q) for q in queues_l)
                except Exception:
                    queues_csv = queues_json.strip("[]").replace('"', "")
                workers_list.append({
                    "hostname": hostname,
                    "pid": pid,
                    "concurrency": int(concurrency_s) if concurrency_s.isdigit() else 0,
                    "busy": int(busy_s) if busy_s.isdigit() else 0,
                    "beat_age_secs": beat_age,
                    "queues_csv": queues_csv,
                })
        elif section == "paused" and line:
            paused_queues.append(line)

    stats["queues"] = queues
    stats["workers"] = workers_list
    stats["paused_queues"] = paused_queues
    stats["_debug"] = debug_kv  # connection params for troubleshooting (host/port/db/auth_set)
    stats["processed"] = kv.get("processed", "0") if kv.get("processed", "") not in ("(nil)", "", None) else "0"
    stats["failed"] = kv.get("failed", "0") if kv.get("failed", "") not in ("(nil)", "", None) else "0"
    stats["retry_size"] = kv.get("retry", "0") if (kv.get("retry", "") or "").isdigit() else "0"
    stats["dead_size"] = kv.get("dead", "0") if (kv.get("dead", "") or "").isdigit() else "0"
    stats["scheduled_size"] = kv.get("scheduled", "0") if (kv.get("scheduled", "") or "").isdigit() else "0"

    # Per-instance systemd stats — batched into a single SSH call
    sibling_services = GuestService.query.filter_by(guest_id=guest.id, service_name="sidekiq").all()
    instances = []
    if sibling_services:
        unit_names = []
        valid_svcs = []
        for svc in sibling_services:
            try:
                unit_names.append(_safe_unit_name(svc.unit_name))
                valid_svcs.append(svc)
            except ValueError:
                continue

        if unit_names:
            units_str = " ".join(unit_names)
            batch_cmd = (
                f"for _U in {units_str}; do"
                " echo \"---unit:$_U---\";"
                " systemctl show \"$_U\" --property=MemoryCurrent,CPUUsageNSec,ActiveState,MainPID 2>/dev/null || true;"
                " done"
            )
            batch_out, _ = _execute_command(guest, batch_cmd, timeout=20)
            # Split output by unit markers
            current_unit = None
            unit_props = {}
            for line in (batch_out or "").split("\n"):
                line = line.strip()
                if line.startswith("---unit:") and line.endswith("---"):
                    current_unit = line[8:-3]
                    unit_props[current_unit] = {}
                elif current_unit and "=" in line:
                    k, _, v = line.partition("=")
                    unit_props[current_unit][k.strip()] = v.strip()

            for svc, unit in zip(valid_svcs, unit_names, strict=False):
                p = unit_props.get(unit, {})
                mem = p.get("MemoryCurrent", "")
                mem_human = ""
                if mem and mem not in ("[not set]", "infinity", ""):
                    try:
                        mem_human = _human_bytes(int(mem))
                    except ValueError:
                        pass
                instances.append({
                    "unit_name": svc.unit_name,
                    "status": _map_systemctl_status(p.get("ActiveState", "unknown")),
                    "pid": p.get("MainPID", ""),
                    "memory": mem_human,
                })

    stats["instances"] = instances
    return stats


# Pure-Python3 script to health-check LibreTranslate.  Tries four candidate
# URLs in order (localhost + configured port, localhost:80, guest-IP + configured
# port, guest-IP:80) so it works regardless of whether a reverse proxy is in
# front, and without requiring curl on the target host.
# Placeholders __HOST__ and __PORT__ are replaced at call time.
_LT_FETCH_SCRIPT_TPL = b"""\
import urllib.request as _ur, sys as _sys
_h = '__HOST__'
_p = __PORT__
_seen = set()
for _url in [
    'http://localhost:{}/languages'.format(_p),
    'http://localhost:80/languages',
    'http://{}:{}/languages'.format(_h, _p),
    'http://{}:80/languages'.format(_h),
]:
    if _url in _seen:
        continue
    _seen.add(_url)
    try:
        _r = _ur.urlopen(_url, timeout=3)
        print(str(_r.status))
        print(_r.read().decode('utf-8', 'replace')[:16384])
        _sys.exit(0)
    except Exception:
        pass
print('0')
print('')
"""


def _stats_libretranslate(guest, service):
    """Collect LibreTranslate stats.

    Uses a base64-encoded Python3 script (no curl dependency) that tries
    localhost and the guest's own IP on both the configured port and port 80.
    """
    import json as _json
    stats = {}
    port = service.port or 5000
    host = guest.ip_address or "127.0.0.1"

    script = _LT_FETCH_SCRIPT_TPL
    script = script.replace(b"__HOST__", host.encode())
    script = script.replace(b"__PORT__", str(port).encode())
    _py_b64 = base64.b64encode(script).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null"

    out, _ = _execute_command(guest, cmd, timeout=20)
    if out:
        status_line, _, body = out.strip().partition('\n')
        status = status_line.strip()
        body = body.strip()

        stats["health_status"] = "OK" if status == "200" else f"HTTP {status}" if status not in ("", "0") else "unreachable"

        if body:
            try:
                langs = _json.loads(body)
                if isinstance(langs, list):
                    stats["languages_count"] = len(langs)
                    stats["languages"] = [
                        lang.get("name", lang.get("code", ""))
                        for lang in langs[:20]
                        if isinstance(lang, dict)
                    ]
            except Exception:
                pass
    else:
        stats["health_status"] = "unreachable"

    # Package version from dist-info (works for venv, pipx, and system installs)
    ver_out, _ = _execute_command(
        guest,
        "find /home /opt /root /srv /var /usr/local /usr/lib -maxdepth 10"
        " -name 'METADATA' -path '*/libretranslate-*.dist-info/*' 2>/dev/null"
        " | head -1 | xargs -r grep '^Version:' 2>/dev/null | awk '{print $2}'",
        timeout=10,
    )
    if ver_out and ver_out.strip():
        stats["lt_version"] = ver_out.strip()

    return stats


def _stats_jitsi_videobridge(guest, service):
    """Collect Jitsi Videobridge stats via REST API.

    JVB 2.3+ moved endpoints:
      - Health:  /about/health  (was /colibri/rest/healthcheck)
      - Stats:   /metrics (Prometheus format) or /colibri/stats (JSON)
      - Version: /about/version (was embedded in /colibri/stats)

    We try new endpoints first, falling back to legacy colibri paths.
    """
    import json as _json
    stats = {}
    port = service.port or 8080

    # ---- Health check (also detects whether the REST API is enabled) ----
    # Try new endpoint first (/about/health), fall back to legacy
    hc_out, _ = _execute_command(
        guest,
        f"curl -sf -o /dev/null -w '%{{http_code}}' http://localhost:{port}/about/health 2>/dev/null || echo 000",
        timeout=10,
    )
    http_code = (hc_out or "").strip()

    if http_code == "404" or http_code == "000":
        # New endpoint not available — try legacy colibri path
        hc_out, _ = _execute_command(
            guest,
            f"curl -sf -o /dev/null -w '%{{http_code}}' http://localhost:{port}/colibri/rest/healthcheck 2>/dev/null || echo 000",
            timeout=10,
        )
        http_code = (hc_out or "").strip()

    if http_code == "000":
        stats["rest_api_disabled"] = True
        return stats

    stats["jvb_healthy"] = http_code == "200"

    # ---- Try Prometheus /metrics endpoint (JVB 2.3+) ----
    metrics_out, _ = _execute_command(
        guest,
        f"curl -sf http://localhost:{port}/metrics 2>/dev/null",
        timeout=15,
    )

    if metrics_out and "jitsi_jvb_" in metrics_out:
        _parse_jvb_prometheus_metrics(stats, metrics_out)
        # Get version from /about/version
        ver_out, _ = _execute_command(
            guest,
            f"curl -sf http://localhost:{port}/about/version 2>/dev/null",
            timeout=10,
        )
        if ver_out:
            try:
                ver_data = _json.loads(ver_out)
                if "version" in ver_data:
                    stats["jvb_version"] = ver_data["version"]
            except _json.JSONDecodeError:
                pass
        return stats

    # ---- Fallback: legacy /colibri/stats JSON endpoint ----
    out, _ = _execute_command(
        guest,
        f"curl -sf http://localhost:{port}/colibri/stats 2>/dev/null",
        timeout=15,
    )
    if not out:
        return stats

    try:
        data = _json.loads(out)
    except _json.JSONDecodeError:
        return stats

    # Activity
    for key in (
        "conferences", "participants", "largest_conference",
        "endpoints_sending_audio", "endpoints_sending_video",
        "p2p_conferences", "inactive_conferences",
    ):
        if key in data:
            stats[key] = data[key]

    # Load
    for key in (
        "stress_level", "bit_rate_download", "bit_rate_upload",
        "packet_rate_download", "packet_rate_upload",
        "rtt_aggregate", "threads",
    ):
        if key in data:
            stats[key] = data[key]

    # Cumulative
    for key in (
        "total_conferences_created", "total_conferences_completed",
        "total_participants", "total_conference_seconds",
        "total_bytes_received", "total_bytes_sent",
        "total_ice_succeeded", "total_ice_failed", "total_ice_succeeded_relayed",
    ):
        if key in data:
            stats[key] = data[key]

    # Version
    if "version" in data:
        stats["jvb_version"] = data["version"]

    return stats


def _parse_jvb_prometheus_metrics(stats, metrics_text):
    """Parse Prometheus-format /metrics output into the stats dict.

    Maps jitsi_jvb_* metric names to the keys expected by the template.
    Lines are in the format: metric_name{labels} value
    """
    # Map from Prometheus metric name → stats dict key
    _gauge_map = {
        "jitsi_jvb_conferences": "conferences",
        "jitsi_jvb_participants": "participants",
        "jitsi_jvb_largest_conference": "largest_conference",
        "jitsi_jvb_endpoints_sending_audio": "endpoints_sending_audio",
        "jitsi_jvb_endpoints_sending_video": "endpoints_sending_video",
        "jitsi_jvb_p2p_conferences": "p2p_conferences",
        "jitsi_jvb_inactive_conferences": "inactive_conferences",
        "jitsi_jvb_stress_level": "stress_level",
        "jitsi_jvb_bit_rate_download": "bit_rate_download",
        "jitsi_jvb_bit_rate_upload": "bit_rate_upload",
        "jitsi_jvb_packet_rate_download": "packet_rate_download",
        "jitsi_jvb_packet_rate_upload": "packet_rate_upload",
        "jitsi_jvb_rtt_aggregate": "rtt_aggregate",
        "jitsi_jvb_threads": "threads",
        "jitsi_jvb_healthy": "_jvb_healthy",
    }
    _counter_map = {
        "jitsi_jvb_conferences_created_total": "total_conferences_created",
        "jitsi_jvb_conferences_completed_total": "total_conferences_completed",
        "jitsi_jvb_participants_total": "total_participants",
        "jitsi_jvb_conference_seconds_total": "total_conference_seconds",
        "jitsi_jvb_bytes_received_total": "total_bytes_received",
        "jitsi_jvb_bytes_sent_total": "total_bytes_sent",
        "jitsi_jvb_ice_succeeded_total": "total_ice_succeeded",
        "jitsi_jvb_ice_failed_total": "total_ice_failed",
        "jitsi_jvb_ice_succeeded_relayed_total": "total_ice_succeeded_relayed",
    }

    # Also accept the short names (without jitsi_ prefix) that some JVB builds emit
    _all_maps = {}
    _all_maps.update(_gauge_map)
    _all_maps.update(_counter_map)

    for line in metrics_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Strip labels: "metric{label=val} 123" → "metric", "123"
        metric_name = line.split("{")[0].split()[0] if "{" in line else line.split()[0]
        parts = line.rsplit(None, 1)
        if len(parts) != 2:
            continue
        raw_value = parts[1]

        stat_key = _all_maps.get(metric_name)
        if not stat_key:
            continue

        try:
            value = float(raw_value)
        except ValueError:
            continue

        if stat_key == "_jvb_healthy":
            stats["jvb_healthy"] = value == 1.0
        elif stat_key in ("stress_level",):
            stats[stat_key] = value
        elif stat_key in ("bit_rate_download", "bit_rate_upload",
                          "packet_rate_download", "packet_rate_upload",
                          "rtt_aggregate"):
            stats[stat_key] = value
        else:
            # Integer metrics (conferences, participants, totals, threads)
            stats[stat_key] = int(value)


def _stats_prometheus(guest, service):
    """Collect Prometheus server stats from its HTTP API."""
    import json as _json
    stats = {}
    port = service.port or 9090

    # Helper: fetch a URL using curl or wget (guest may not have curl)
    def _prom_fetch(url, timeout=10):
        cmd = (
            f"(curl -sf '{url}' 2>/dev/null "
            f"|| wget -qO- '{url}' 2>/dev/null)"
        )
        out, _ = _execute_command(guest, cmd, timeout=timeout)
        return (out or "").strip()

    # Health check
    hc_out = _prom_fetch(f"http://localhost:{port}/-/healthy")
    if not hc_out:
        stats["prom_api_disabled"] = True
        return stats

    stats["prom_healthy"] = "Healthy" in hc_out or "OK" in hc_out

    # Runtime info — version, retention, start time
    out = _prom_fetch(f"http://localhost:{port}/api/v1/status/runtimeinfo")
    if out:
        try:
            data = _json.loads(out)
            info = data.get("data", {})
            stats["prom_version"] = info.get("CWD", "")  # fallback
            if info.get("storageRetention"):
                stats["prom_retention"] = info["storageRetention"]
            if info.get("startTime"):
                stats["prom_start_time"] = info["startTime"]
        except _json.JSONDecodeError:
            pass

    # Get version from build info (more reliable)
    out = _prom_fetch(f"http://localhost:{port}/api/v1/status/buildinfo")
    if out:
        try:
            data = _json.loads(out)
            info = data.get("data", {})
            if info.get("version"):
                stats["prom_version"] = info["version"]
        except _json.JSONDecodeError:
            pass

    # Runtime flags — detect lifecycle / admin API availability
    out = _prom_fetch(f"http://localhost:{port}/api/v1/status/flags")
    if out:
        try:
            data = _json.loads(out)
            flags = data.get("data", {})
            stats["prom_lifecycle_enabled"] = flags.get("web.enable-lifecycle", "false") == "true"
            stats["prom_admin_api_enabled"] = flags.get("web.enable-admin-api", "false") == "true"
        except _json.JSONDecodeError:
            pass

    # TSDB stats — series, chunks, storage size
    out = _prom_fetch(f"http://localhost:{port}/api/v1/status/tsdb")
    if out:
        try:
            data = _json.loads(out)
            tsdb = data.get("data", {})
            if "headStats" in tsdb:
                head = tsdb["headStats"]
                stats["head_series"] = head.get("numSeries", 0)
                stats["head_chunks"] = head.get("numChunks", 0)
                stats["min_time"] = head.get("minTime", 0)
                stats["max_time"] = head.get("maxTime", 0)
        except _json.JSONDecodeError:
            pass

    # Storage size via promtool or filesystem
    out, _ = _execute_command(
        guest,
        "du -sb /var/lib/prometheus/ 2>/dev/null | cut -f1",
        timeout=10,
    )
    if out and out.strip().isdigit():
        storage_bytes = int(out.strip())
        stats["storage_bytes"] = storage_bytes
        stats["storage_human"] = _human_bytes(storage_bytes)

    # WAL size
    out, _ = _execute_command(
        guest,
        "du -sb /var/lib/prometheus/wal 2>/dev/null | cut -f1",
        timeout=10,
    )
    if out and out.strip().isdigit():
        wal_bytes = int(out.strip())
        stats["wal_bytes"] = wal_bytes
        stats["wal_human"] = _human_bytes(wal_bytes)

    # Scrape targets
    out = _prom_fetch(f"http://localhost:{port}/api/v1/targets", timeout=15)
    if out:
        try:
            data = _json.loads(out)
            active = data.get("data", {}).get("activeTargets", [])
            targets = []
            targets_up = 0
            targets_down = 0
            for t in active:
                health = t.get("health", "unknown")
                if health == "up":
                    targets_up += 1
                else:
                    targets_down += 1
                targets.append({
                    "job": t.get("labels", {}).get("job", ""),
                    "endpoint": t.get("scrapeUrl", ""),
                    "health": health,
                    "lastScrape": t.get("lastScrape", ""),
                    "scrapeDuration": round(float(t.get("lastScrapeDuration", 0)), 4),
                    "lastError": t.get("lastError", ""),
                })
            stats["targets"] = targets
            stats["active_targets_count"] = len(active)
            stats["targets_up"] = targets_up
            stats["targets_down"] = targets_down
        except (_json.JSONDecodeError, ValueError):
            pass

    return stats


# --- LibreTranslate package management scripts ---
# _LT_PATH_SETUP is prepended to every script. It uses two strategies to add
# the argostranslate site-packages to sys.path regardless of where the
# LibreTranslate virtualenv lives:
#   1. Broad glob covering all common installation patterns
#   2. subprocess `find` fallback — only runs if the glob still can't locate
#      argostranslate, so there's no overhead in the normal case.
_LT_PATH_SETUP = b"""\
import sys, os, glob, json
for _pat in [
    '/home/*/venv/lib/python*/site-packages',
    '/home/*/.venv/lib/python*/site-packages',
    '/home/*/.local/lib/python*/site-packages',
    '/opt/*/venv/lib/python*/site-packages',
    '/opt/*/lib/python*/site-packages',
    '/root/.local/lib/python*/site-packages',
    '/root/.local/pipx/venvs/*/lib/python*/site-packages',
    '/srv/*/venv/lib/python*/site-packages',
    '/var/*/venv/lib/python*/site-packages',
    '/usr/local/lib/python*/dist-packages',
    '/usr/local/lib/python*/site-packages',
    '/usr/lib/python3/dist-packages',
]:
    for _p in glob.glob(_pat):
        if _p not in sys.path: sys.path.insert(0, _p)
try:
    import argostranslate as _at_probe
    del _at_probe
except ImportError:
    import subprocess as _sp
    try:
        _r = _sp.run(
            'find /home /opt /root /var /usr/local /usr/lib /srv -maxdepth 10 '
            '-name "argostranslate" -type d 2>/dev/null | head -1',
            shell=True, capture_output=True, text=True, timeout=15)
        _d = _r.stdout.strip()
        if _d and os.path.isfile(os.path.join(_d, '__init__.py')):
            _site = os.path.dirname(_d)
            if _site not in sys.path: sys.path.insert(0, _site)
    except Exception:
        pass
"""

_LT_LIST_INSTALLED_SCRIPT = _LT_PATH_SETUP + b"""\
try:
    from argostranslate import package as _pkg
    def _norm(v): return str(v).replace('_', '.').strip().lower() if v else ''
    # Compare against locally-cached available packages (no network call) to
    # detect outdated versions. If no local cache exists, outdated stays False.
    _avail_ver = {}
    try:
        _avail_ver = {(p.from_code, p.to_code): p.package_version
                      for p in _pkg.get_available_packages()}
    except Exception:
        pass
    # Deduplicate by language pair: argostranslate leaves old package directories
    # in place after installing a new version, so get_installed_packages() may
    # return multiple entries for the same pair.  Prefer the entry whose version
    # matches the available index (i.e. the current version).
    _pairs = {}  # (from, to) -> (InstalledPackage, version_str)
    for _p in _pkg.get_installed_packages():
        _key = (_p.from_code, _p.to_code)
        _pver = getattr(_p, 'package_version', None)
        _avail = _avail_ver.get(_key)
        if _key not in _pairs:
            _pairs[_key] = (_p, _pver)
        elif _avail and _norm(_pver) == _norm(_avail):
            # This entry matches the current index - prefer it over the stale one.
            _pairs[_key] = (_p, _pver)
    _pkgs = []
    for _key, (_p, _ver) in _pairs.items():
        _avail = _avail_ver.get(_key)
        _pkgs.append({
            'from_code': _p.from_code, 'to_code': _p.to_code,
            'from_name': _p.from_name, 'to_name': _p.to_name,
            'version': _ver,
            'available_version': _avail,
            'outdated': bool(_avail and _ver and _norm(_avail) != _norm(_ver)),
        })
    print(json.dumps({'packages': _pkgs}))
except Exception as _e:
    print(json.dumps({'error': str(_e)}))
"""

_LT_LIST_AVAILABLE_SCRIPT = _LT_PATH_SETUP + b"""\
try:
    from argostranslate import package as _pkg
    _pkg.update_package_index()
    _installed = {(p.from_code, p.to_code) for p in _pkg.get_installed_packages()}
    print(json.dumps({'packages': [
        {'from_code': p.from_code, 'to_code': p.to_code,
         'from_name': p.from_name, 'to_name': p.to_name,
         'version': getattr(p, 'package_version', None),
         'installed': (p.from_code, p.to_code) in _installed}
        for p in _pkg.get_available_packages()
    ]}))
except Exception as _e:
    print(json.dumps({'error': str(_e)}))
"""

# Placeholders __FROM__ and __TO__ replaced at call time (validated as lang codes).
_LT_INSTALL_PACKAGE_SCRIPT_TPL = _LT_PATH_SETUP + b"""\
try:
    from argostranslate import package as _pkg
    _pkg.update_package_index()
    _from, _to = '__FROM__', '__TO__'
    for _p in _pkg.get_available_packages():
        if _p.from_code == _from and _p.to_code == _to:
            _p.install()
            print(json.dumps({'ok': True, 'message': 'Installed {}->{}'.format(_from, _to)}))
            raise SystemExit
    print(json.dumps({'ok': False, 'message': 'Package not found: {}->{}'.format(_from, _to)}))
except SystemExit:
    pass
except Exception as _e:
    print(json.dumps({'ok': False, 'message': str(_e)}))
"""

_LT_UPDATE_ALL_SCRIPT = _LT_PATH_SETUP + b"""\
try:
    from argostranslate import package as _pkg
    def _norm(v): return str(v).replace('_', '.').strip().lower() if v else ''
    _pkg.update_package_index()
    _avail = {(p.from_code, p.to_code): p for p in _pkg.get_available_packages()}
    _n = 0
    _errors = []
    _seen = set()  # deduplicate language pairs across multiple installed versions
    for _inst in _pkg.get_installed_packages():
        _key = (_inst.from_code, _inst.to_code)
        if _key in _seen:
            continue
        _avail_pkg = _avail.get(_key)
        if _avail_pkg is None:
            continue
        _inst_ver = getattr(_inst, 'package_version', None)
        _avail_ver = getattr(_avail_pkg, 'package_version', None)
        if _inst_ver and _avail_ver and _norm(_inst_ver) == _norm(_avail_ver):
            _seen.add(_key)
            continue
        _seen.add(_key)
        try:
            _avail_pkg.install()
            _n += 1
        except Exception as _ie:
            _errors.append('{}->{}: {}'.format(_key[0], _key[1], str(_ie)))
    _msg = 'Updated {} package(s)'.format(_n)
    if _errors:
        _msg += '; {} error(s): {}'.format(len(_errors), '; '.join(_errors))
    print(json.dumps({'ok': True, 'updated': _n, 'message': _msg}))
except Exception as _e:
    print(json.dumps({'ok': False, 'updated': 0, 'message': str(_e)}))
"""

# Streaming variant of the update script.  Emits one JSON object per line so
# the caller can report per-package progress to the user in real time.
_LT_UPDATE_STREAMING_SCRIPT = _LT_PATH_SETUP + b"""\
import sys
try:
    from argostranslate import package as _pkg
    def _norm(v): return str(v).replace('_', '.').strip().lower() if v else ''
    print(json.dumps({'type': 'status', 'message': 'Updating package index\u2026'}), flush=True)
    _pkg.update_package_index()
    _avail = {(p.from_code, p.to_code): p for p in _pkg.get_available_packages()}
    _to_update = []
    _seen = set()  # deduplicate language pairs across multiple installed versions
    for _inst in _pkg.get_installed_packages():
        _key = (_inst.from_code, _inst.to_code)
        if _key in _seen:
            continue
        _avail_pkg = _avail.get(_key)
        if _avail_pkg is None:
            continue
        _inst_ver = getattr(_inst, 'package_version', None)
        _avail_ver = getattr(_avail_pkg, 'package_version', None)
        if _inst_ver and _avail_ver and _norm(_inst_ver) == _norm(_avail_ver):
            _seen.add(_key)
            continue
        _seen.add(_key)
        _to_update.append((_key, _avail_pkg, _avail_ver))
    print(json.dumps({'type': 'start', 'total': len(_to_update)}), flush=True)
    _n = 0
    _errors = []
    for _i, (_key, _avail_pkg, _avail_ver) in enumerate(_to_update):
        _from, _to = _key
        print(json.dumps({'type': 'installing', 'from_code': _from, 'to_code': _to,
                          'version': _avail_ver, 'index': _i + 1, 'total': len(_to_update)}), flush=True)
        try:
            _avail_pkg.install()
            _n += 1
            print(json.dumps({'type': 'installed', 'from_code': _from, 'to_code': _to}), flush=True)
        except Exception as _ie:
            _errors.append('{}->{}: {}'.format(_from, _to, str(_ie)))
            print(json.dumps({'type': 'error', 'from_code': _from, 'to_code': _to,
                              'message': str(_ie)}), flush=True)
    _msg = 'Updated {} package(s)'.format(_n)
    if _errors:
        _msg += '; {} error(s): {}'.format(len(_errors), '; '.join(_errors))
    print(json.dumps({'ok': True, 'updated': _n, 'message': _msg, 'type': 'result'}), flush=True)
except Exception as _e:
    print(json.dumps({'ok': False, 'updated': 0, 'message': str(_e), 'type': 'result'}), flush=True)
"""

_LANG_CODE_RE = re.compile(r'^[a-z]{2,8}$')


def _lt_run(guest, script_bytes, timeout=60):
    """Base64-encode a script and run it via SSH using system python3.

    argostranslate discovery is handled inside the script itself via
    _LT_PATH_SETUP (broad glob + find fallback).
    """
    _py_b64 = base64.b64encode(script_bytes).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null"
    out, err = _execute_command(guest, cmd, timeout=timeout)
    if err and not out:
        raise RuntimeError(err)
    # Parse the last JSON object line — guards against any progress text printed
    # to stdout by argostranslate during package installs.
    lines = [line for line in (out or "").strip().splitlines() if line.strip().startswith("{")]
    if not lines:
        raise RuntimeError(f"No JSON output from script; stdout={out!r}")
    return json.loads(lines[-1])


def lt_list_installed(guest, service):
    """List installed LibreTranslate language packages. Returns (packages, error)."""
    try:
        data = _lt_run(guest, _LT_LIST_INSTALLED_SCRIPT, timeout=30)
        if "error" in data:
            return [], data["error"]
        return data.get("packages", []), None
    except Exception as e:
        return [], str(e)


def lt_list_available(guest, service):
    """Fetch available LibreTranslate packages from the Argos index. Returns (packages, error)."""
    try:
        data = _lt_run(guest, _LT_LIST_AVAILABLE_SCRIPT, timeout=60)
        if "error" in data:
            return [], data["error"]
        return data.get("packages", []), None
    except Exception as e:
        return [], str(e)


def lt_install_package(guest, service, from_code, to_code):
    """Install a single LibreTranslate language pair. Returns (ok, message)."""
    if not _LANG_CODE_RE.match(from_code) or not _LANG_CODE_RE.match(to_code):
        return False, "Invalid language code"
    script = _LT_INSTALL_PACKAGE_SCRIPT_TPL
    script = script.replace(b"__FROM__", from_code.encode())
    script = script.replace(b"__TO__", to_code.encode())
    try:
        data = _lt_run(guest, script, timeout=300)
        return data.get("ok", False), data.get("message", "Unknown error")
    except Exception as e:
        return False, str(e)


def lt_update_all_packages(guest, service):
    """Re-install the latest version of every installed language package. Returns (ok, message, count)."""
    try:
        data = _lt_run(guest, _LT_UPDATE_ALL_SCRIPT, timeout=600)
        return data.get("ok", False), data.get("message", "Unknown error"), data.get("updated", 0)
    except Exception as e:
        return False, str(e), 0


def lt_update_packages_stream(guest, service, line_callback):
    """Stream LibreTranslate package updates via SSH, calling line_callback for each JSON progress line.

    Only supports SSH connections (streaming requires channel-level access).
    line_callback receives a raw JSON string for each progress event.
    """
    _py_b64 = base64.b64encode(_LT_UPDATE_STREAMING_SCRIPT).decode()
    cmd = f"python3 -c 'import base64;exec(base64.b64decode(\"{_py_b64}\").decode())' 2>/dev/null"

    credential = guest.credential
    if not credential:
        from models import Credential
        credential = Credential.query.filter_by(is_default=True).first()

    if not credential or not _has_valid_ip(guest):
        line_callback(json.dumps({"type": "result", "ok": False, "updated": 0,
                                  "message": "No SSH credential or IP address available"}))
        return

    buf = ""

    def _on_chunk(chunk):
        nonlocal buf
        buf += chunk
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.strip()
            if line.startswith("{"):
                line_callback(line)

    try:
        with SSHClient.from_credential(guest.ip_address, credential) as ssh:
            ssh.execute_streaming(cmd, _on_chunk, timeout=600)
        # flush any remaining buffered line
        if buf.strip().startswith("{"):
            line_callback(buf.strip())
    except Exception as e:
        line_callback(json.dumps({"type": "result", "ok": False, "updated": 0,
                                  "message": f"SSH error: {e}"}))


def check_reboot_required(guest):
    """Check if a guest needs a reboot (Debian/Ubuntu: /var/run/reboot-required)."""
    stdout, error = _execute_command(guest, "[ -f /var/run/reboot-required ] && echo yes || echo no")
    if not error and stdout:
        guest.reboot_required = stdout.strip() == "yes"
        db.session.commit()


def scan_guest(guest):
    """Scan a single guest for updates. Returns ScanResult."""
    logger.info(f"Scanning {guest.name} ({guest.guest_type})...")

    upgradable_output, security_output, error = _execute_on_guest(guest)

    now = datetime.now(timezone.utc)

    if error:
        logger.error(f"Scan failed for {guest.name}: {error}")
        result = ScanResult(
            guest_id=guest.id,
            scanned_at=now,
            total_updates=0,
            security_updates=0,
            status="error",
            error_message=error,
        )
        guest.status = "error"
        guest.last_scan = now
        db.session.add(result)
        db.session.commit()
        return result

    # Parse packages
    packages = parse_upgradable(upgradable_output or "")

    # Clear old pending updates for this guest
    UpdatePackage.query.filter_by(guest_id=guest.id, status="pending").delete()

    security_count = 0
    for pkg in packages:
        severity = determine_severity(pkg["name"], security_output)
        if severity == "critical":
            security_count += 1

        update = UpdatePackage(
            guest_id=guest.id,
            package_name=pkg["name"],
            current_version=pkg["current_version"],
            available_version=pkg["available_version"],
            severity=severity,
            discovered_at=now,
            status="pending",
        )
        db.session.add(update)

    result = ScanResult(
        guest_id=guest.id,
        scanned_at=now,
        total_updates=len(packages),
        security_updates=security_count,
        status="success",
    )

    guest.status = "updates-available" if packages else "up-to-date"
    guest.last_scan = now

    db.session.add(result)
    db.session.commit()

    logger.info(f"Scan complete for {guest.name}: {len(packages)} updates ({security_count} security)")

    # Auto-detect services during scan
    try:
        detect_services(guest)
    except Exception as e:
        logger.debug(f"Service detection failed for {guest.name}: {e}")

    # Check if guest needs a reboot
    try:
        check_reboot_required(guest)
    except Exception as e:
        logger.debug(f"Reboot check failed for {guest.name}: {e}")

    # Push notifications for mobile app
    try:
        from core.push_notifier import dispatch_push_alerts
        if security_count > 0:
            dispatch_push_alerts(guest, "security_update", {"count": security_count})
        if guest.reboot_required:
            dispatch_push_alerts(guest, "reboot_required")
        if guest.status == "error":
            dispatch_push_alerts(guest, "guest_error", {"error": error or "scan failed"})
    except Exception as e:
        logger.debug(f"Push notification dispatch failed for {guest.name}: {e}")

    return result


def scan_all_guests():
    """Scan all enabled, running guests."""
    guests = Guest.query.filter_by(enabled=True, power_state="running").all()
    results = []
    for guest in guests:
        try:
            result = scan_guest(guest)
            results.append(result)
        except Exception as e:
            logger.error(f"Unexpected error scanning {guest.name}: {e}")
    return results


def apply_updates(guest, dist_upgrade=False):
    """Apply pending updates to a guest."""
    cmd = "DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y" if dist_upgrade else "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"

    logger.info(f"Applying updates to {guest.name} (dist_upgrade={dist_upgrade})...")

    if guest.connection_method in ("ssh", "auto") and _has_valid_ip(guest):
        credential = guest.credential
        if not credential:
            from models import Credential
            credential = Credential.query.filter_by(is_default=True).first()

        if credential:
            try:
                with SSHClient.from_credential(guest.ip_address, credential) as ssh:
                    ssh.execute_sudo("apt-get update -qq", timeout=120)
                    stdout, stderr, code = ssh.execute_sudo(cmd, timeout=600)
                    if code == 0:
                        # Mark all pending as applied
                        now = datetime.now(timezone.utc)
                        for pkg in guest.pending_updates():
                            pkg.status = "applied"
                            pkg.applied_at = now
                        guest.status = "up-to-date"
                        db.session.commit()
                        try:
                            check_reboot_required(guest)
                        except Exception:
                            pass
                        return True, stdout
                    return False, stderr
            except Exception as e:
                return False, str(e)

    if guest.connection_method in ("agent", "auto") and guest.proxmox_host and guest.guest_type == "vm":
        try:
            client = ProxmoxClient(guest.proxmox_host)
            all_guests = client.get_all_guests()
            node = None
            for g in all_guests:
                if g.get("vmid") == guest.vmid:
                    node = g.get("node")
                    break
            if node:
                client.exec_guest_agent(node, guest.vmid, "apt-get update -qq")
                stdout, err = client.exec_guest_agent(node, guest.vmid, cmd)
                if err is None:
                    now = datetime.now(timezone.utc)
                    for pkg in guest.pending_updates():
                        pkg.status = "applied"
                        pkg.applied_at = now
                    guest.status = "up-to-date"
                    db.session.commit()
                    try:
                        check_reboot_required(guest)
                    except Exception:
                        pass
                    return True, stdout
                return False, err
        except Exception as e:
            return False, str(e)

    return False, "No viable connection method"

