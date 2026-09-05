#!/usr/bin/env python3
"""
Vault -> AWS credential demo - static-key rotation (Phase 1) and JIT dynamic credentials (Phase 2).

Deliberately stdlib-only: no pip install at pod start, no image to build or push.
AWS calls are signed inline with SigV4 so the demo shows real API traffic.
"""
import base64, datetime, hashlib, hmac, json, os, ssl, threading, time, urllib.error, urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

VAULT_ADDR = os.environ.get("VAULT_ADDR", "https://vault.example.com")
VAULT_NS = os.environ.get("VAULT_NAMESPACE", "apps")
AUTH_MOUNT = os.environ.get("VAULT_AUTH_MOUNT", "kubernetes")
VAULT_ROLE = os.environ.get("VAULT_ROLE", "demo-app")
AWS_MOUNT = os.environ.get("VAULT_AWS_MOUNT", "aws-demo")
STATIC_ROLE = os.environ.get("VAULT_STATIC_ROLE", "demo-app")
DYNAMIC_ROLE = os.environ.get("VAULT_DYNAMIC_ROLE", "dynamic-sts")
DYNAMIC_USER_ROLE = os.environ.get("VAULT_DYNAMIC_USER_ROLE", "dynamic-iam-user")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "5"))

_ssl = ssl.create_default_context()
_ssl.check_hostname = False
_ssl.verify_mode = ssl.CERT_NONE

STATE = {
    "auth": {"status": "not authenticated"},
    "connection": {"method": "loading", "title": "reading config/root..."},
    "phase1": {"history": []},
    "phase2": {"current": None, "issued": []},
    "log": [],
    "config": {
        "vault_addr": VAULT_ADDR, "vault_namespace": VAULT_NS,
        "auth_mount": AUTH_MOUNT, "vault_role": VAULT_ROLE,
        "aws_mount": AWS_MOUNT, "static_role": STATIC_ROLE,
        "dynamic_role": DYNAMIC_ROLE, "dynamic_user_role": DYNAMIC_USER_ROLE,
        "region": AWS_REGION,
        "pod": os.environ.get("POD_NAME", "?"), "k8s_ns": os.environ.get("POD_NAMESPACE", "demo-apps"),
    },
}
LOCK = threading.Lock()
SEQ = [0]


def log(actor, action, target, detail="", status="ok", ms=None):
    with LOCK:
        SEQ[0] += 1
        STATE["log"].insert(0, {
            "n": SEQ[0], "ts": datetime.datetime.now().strftime("%H:%M:%S"),
            "actor": actor, "action": action, "target": target,
            "detail": detail, "status": status, "ms": ms,
        })
        del STATE["log"][400:]


def mask(secret, keep=4):
    if not secret:
        return ""
    return secret[:keep] + "•" * 8 + secret[-2:] if len(secret) > keep + 2 else "•" * 8


# --------------------------------------------------------------------------- Vault

def vault_call(method, path, body=None, token=None):
    url = f"{VAULT_ADDR}/v1/{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-Vault-Namespace", VAULT_NS)
    if token:
        req.add_header("X-Vault-Token", token)
    if data:
        req.add_header("Content-Type", "application/json")
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=20, context=_ssl) as r:
        payload = json.loads(r.read() or b"{}")
    return payload, int((time.time() - t0) * 1000)


def vault_login():
    """Exchange the pod's ServiceAccount JWT for a Vault token. No secret is stored in the pod."""
    try:
        with open(SA_TOKEN_PATH) as f:
            jwt = f.read().strip()
    except OSError as e:
        log("app", "read ServiceAccount JWT", SA_TOKEN_PATH, str(e), "error")
        STATE["auth"] = {"status": "error", "error": str(e)}
        return None
    claims = {}
    try:
        seg = jwt.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        pass
    log("app", "read ServiceAccount JWT", "projected volume",
        f"sub={claims.get('sub', '?')}", "ok")
    try:
        res, ms = vault_call("POST", f"auth/{AUTH_MOUNT}/login",
                             {"role": VAULT_ROLE, "jwt": jwt})
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:200]
        log("app → vault", f"POST auth/{AUTH_MOUNT}/login", f"role={VAULT_ROLE}", detail, "error")
        STATE["auth"] = {"status": "error", "error": detail}
        return None
    a = res["auth"]
    STATE["auth"] = {
        "status": "authenticated", "accessor": a["accessor"],
        "policies": a["token_policies"], "lease_duration": a["lease_duration"],
        "obtained_at": time.time(), "sa": claims.get("sub", "?"),
        "token_preview": mask(a["client_token"], 8),
    }
    STATE["_token"] = a["client_token"]
    log("app → vault", f"POST auth/{AUTH_MOUNT}/login", f"role={VAULT_ROLE}",
        f"policies={','.join(a['token_policies'])} ttl={a['lease_duration']}s", "ok", ms)
    return a["client_token"]


def token():
    tok = STATE.get("_token")
    if not tok:
        tok = vault_login()
    return tok


def vault_authed(method, path, body=None, retry=True):
    tok = token()
    if not tok:
        raise RuntimeError("no vault token")
    try:
        return vault_call(method, path, body, tok)
    except urllib.error.HTTPError as e:
        if e.code in (403, 401) and retry:
            STATE["_token"] = None
            log("app", "vault token rejected", path, "re-authenticating", "warn")
            return vault_authed(method, path, body, retry=False)
        raise


# --------------------------------------------------------------------------- SigV4

def sigv4(method, url, service, akid, skey, stoken=None, body=b"", extra=None):
    p = urlparse(url)
    host, uri, qs = p.netloc, (p.path or "/"), (p.query or "")
    now = datetime.datetime.now(datetime.timezone.utc)
    amzdate, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    h = {"host": host, "x-amz-date": amzdate, "x-amz-content-sha256": payload_hash}
    if stoken:
        h["x-amz-security-token"] = stoken
    for k, v in (extra or {}).items():
        h[k.lower()] = v
    signed = ";".join(sorted(h))
    canon_headers = "".join(f"{k}:{h[k].strip()}\n" for k in sorted(h))
    canon_req = "\n".join([method, uri, qs, canon_headers, signed, payload_hash])
    scope = f"{datestamp}/{AWS_REGION}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                     hashlib.sha256(canon_req.encode()).hexdigest()])

    def _s(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k = _s(("AWS4" + skey).encode(), datestamp)
    for part in (AWS_REGION, service, "aws4_request"):
        k = _s(k, part)
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    h["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, "
                          f"SignedHeaders={signed}, Signature={sig}")
    req = urllib.request.Request(url, data=body or None, method=method)
    for key, val in h.items():
        req.add_header(key, val)
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode(), int((time.time() - t0) * 1000)


def aws_whoami(creds, label, retries=0):
    """sts:GetCallerIdentity - proves WHICH identity the credential maps to."""
    body = b"Action=GetCallerIdentity&Version=2011-06-15"
    try:
        xml, ms = sigv4("POST", f"https://sts.{AWS_REGION}.amazonaws.com/", "sts",
                        creds["access_key"], creds["secret_key"], creds.get("session_token"),
                        body, {"content-type": "application/x-www-form-urlencoded"})
        root = ET.fromstring(xml)
        ns = "{https://sts.amazonaws.com/doc/2011-06-15/}"
        arn = root.find(f".//{ns}Arn").text
        log("app → aws", "sts:GetCallerIdentity", label, arn, "ok", ms)
        return {"ok": True, "arn": arn, "ms": ms}
    except urllib.error.HTTPError as e:
        msg = e.read().decode()[:200]
        if retries > 0 and ("InvalidClientTokenId" in msg or "AccessDenied" in msg):
            # documented AWS eventual consistency for new IAM credentials
            log("app → aws", "sts:GetCallerIdentity", label,
                f"not valid yet, AWS propagation - retrying ({retries} left)", "warn")
            time.sleep(4)
            return aws_whoami(creds, label, retries - 1)
        log("app → aws", "sts:GetCallerIdentity", label, msg, "error")
        return {"ok": False, "error": msg}
    except Exception as e:
        log("app → aws", "sts:GetCallerIdentity", label, str(e), "error")
        return {"ok": False, "error": str(e)}


def aws_list_buckets(creds, label):
    """s3:ListAllMyBuckets - proves the credential is actually AUTHORIZED, not just valid."""
    try:
        xml, ms = sigv4("GET", f"https://s3.{AWS_REGION}.amazonaws.com/", "s3",
                        creds["access_key"], creds["secret_key"], creds.get("session_token"))
        root = ET.fromstring(xml)
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        names = [b.find(f"{ns}Name").text for b in root.iter(f"{ns}Bucket")]
        log("app → aws", "s3:ListAllMyBuckets", label, f"{len(names)} bucket(s)", "ok", ms)
        return {"ok": True, "buckets": names, "ms": ms}
    except urllib.error.HTTPError as e:
        msg = e.read().decode()[:200]
        log("app → aws", "s3:ListAllMyBuckets", label, msg, "error")
        return {"ok": False, "error": msg}
    except Exception as e:
        log("app → aws", "s3:ListAllMyBuckets", label, str(e), "error")
        return {"ok": False, "error": str(e)}


# --------------------------------------------------------------------------- Phase 1

def phase1_read(call_aws=True):
    """Read the current Vault-rotated static credential and note whether it changed."""
    try:
        res, ms = vault_authed("GET", f"{AWS_MOUNT}/static-creds/{STATIC_ROLE}")
    except Exception as e:
        log("app → vault", f"GET {AWS_MOUNT}/static-creds/{STATIC_ROLE}", "static credential",
            str(e), "error")
        return
    d = res["data"]
    p1 = STATE["phase1"]
    previous = p1.get("access_key")
    rotated = previous is not None and previous != d["access_key"]
    # AWS static-creds returns an RFC3339 "expiration", not a ttl integer.
    expires_at = None
    if d.get("expiration"):
        try:
            expires_at = datetime.datetime.fromisoformat(
                d["expiration"].replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    left = f"{int(expires_at - time.time())}s" if expires_at else "?"
    log("app → vault", f"GET {AWS_MOUNT}/static-creds/{STATIC_ROLE}", "static credential",
        f"access_key={d['access_key']} rotates in {left}", "ok", ms)
    if rotated:
        log("vault → aws", "iam:CreateAccessKey + iam:DeleteAccessKey",
            f"user/{STATIC_ROLE}", f"{previous} → {d['access_key']}", "rotate")
        p1["history"].insert(0, {
            "ts": datetime.datetime.now().strftime("%H:%M:%S"),
            "old": previous, "new": d["access_key"],
        })
        del p1["history"][20:]
    p1.update({
        "access_key": d["access_key"], "secret_preview": mask(d["secret_key"]),
        "expires_at": expires_at, "read_at": time.time(), "rotated_just_now": rotated,
    })
    STATE["_p1_creds"] = {"access_key": d["access_key"], "secret_key": d["secret_key"]}
    if call_aws:
        label = f"static key {d['access_key']}"
        p1["whoami"] = aws_whoami(STATE["_p1_creds"], label)
        p1["s3"] = aws_list_buckets(STATE["_p1_creds"], label)


def phase1_meta():
    try:
        res, ms = vault_authed("GET", f"{AWS_MOUNT}/static-roles/{STATIC_ROLE}")
        STATE["phase1"]["rotation_period"] = res["data"].get("rotation_period")
        STATE["phase1"]["username"] = res["data"].get("username")
    except Exception:
        pass


# ------------------------------------------------------- how Vault reaches AWS

def vault_conn():
    """Report how Vault itself authenticates to AWS.

    Reads config/root, which never contains secret material - Vault does not return
    secret_key to anyone, including root. Which of the three shapes is in effect is
    the first thing to explain to a customer, so the UI shows it permanently.
    """
    try:
        res, ms = vault_authed("GET", f"{AWS_MOUNT}/config/root")
    except Exception as e:
        STATE["connection"] = {"method": "unknown", "title": "could not read config/root",
                               "detail": str(e)[:120], "secret": "-", "note": ""}
        return
    d = res["data"]
    access_key = d.get("access_key")
    role_arn = d.get("role_arn")
    audience = d.get("identity_token_audience")

    if role_arn and audience:
        conn = {
            "method": "wif",
            "title": "Plugin workload identity federation",
            "detail": f"assumes {role_arn.split('/')[-1]} · audience {audience}",
            "secret": "none — Vault stores no AWS credential",
            "note": "Vault signs its own identity token and trades it with AWS STS for "
                    "short-lived credentials. Nothing to leak, nothing to rotate.",
        }
    elif access_key:
        conn = {
            "method": "static",
            "title": "Static credential, rotated by Vault",
            "detail": f"{access_key} · IAM user vault-root",
            "secret": "write-only — Vault never returns secret_key",
            "note": "Generated by config/rotate-root, so the secret was created inside Vault "
                    "and no human has ever seen it. One credential, not thousands.",
        }
    else:
        conn = {
            "method": "ambient",
            "title": "Ambient platform identity (AWS SDK chain)",
            "detail": "resolved from the runtime — IRSA / instance profile",
            "secret": "none — Vault stores no AWS credential",
            "note": "Vault uses the identity its platform already gives it, so there is "
                    "no credential in Vault's configuration at all.",
        }
    conn["region"] = d.get("region")
    STATE["connection"] = conn
    log("app → vault", f"GET {AWS_MOUNT}/config/root", "how Vault authenticates to AWS",
        conn["title"], "ok", ms)


# --------------------------------------------------------------------------- Phase 2

def phase2_issue(mode="sts"):
    """Mint a just-in-time credential. Every call returns a brand new, short-lived identity."""
    role = DYNAMIC_ROLE if mode == "sts" else DYNAMIC_USER_ROLE
    kind = "assumed_role (STS)" if mode == "sts" else "iam_user"
    try:
        res, ms = vault_authed("GET", f"{AWS_MOUNT}/creds/{role}")
    except Exception as e:
        log("app → vault", f"GET {AWS_MOUNT}/creds/{role}", "dynamic credential", str(e), "error")
        return
    d = res["data"]
    log("app → vault", f"GET {AWS_MOUNT}/creds/{role}", f"dynamic credential ({kind})",
        f"lease={res['lease_id'].split('/')[-1]} ttl={res['lease_duration']}s", "ok", ms)
    if mode == "sts":
        log("vault → aws", "sts:AssumeRole", "role/dynamic-role",
            f"minted {d['access_key']}", "mint")
    else:
        log("vault → aws", "iam:CreateUser + iam:CreateAccessKey", "user/vault-dynamic/*",
            f"created a throwaway IAM user, key {d['access_key']}", "mint")
    creds = {"access_key": d["access_key"], "secret_key": d["secret_key"],
             "session_token": d.get("session_token")}
    label = f"JIT key {d['access_key']}"
    cur = {
        "mode": mode, "kind": kind,
        "lease_id": res["lease_id"], "lease_duration": res["lease_duration"],
        "issued_at": time.time(), "access_key": d["access_key"],
        "secret_preview": mask(d["secret_key"]),
        "session_preview": mask(d["session_token"], 6) if d.get("session_token") else "(none - iam_user)",
        "revoked": False,
    }
    # iam_user credentials are eventually consistent; STS credentials are immediate
    cur["whoami"] = aws_whoami(creds, label, retries=0 if mode == "sts" else 4)
    cur["s3"] = aws_list_buckets(creds, label)
    STATE["_p2_creds"] = creds
    STATE["phase2"]["current"] = cur
    STATE["phase2"]["verify"] = None
    STATE["phase2"]["issued"].insert(0, {
        "ts": datetime.datetime.now().strftime("%H:%M:%S"), "mode": mode,
        "access_key": d["access_key"], "arn": cur["whoami"].get("arn", ""),
    })
    del STATE["phase2"]["issued"][20:]


def phase2_revoke():
    cur = STATE["phase2"].get("current")
    if not cur or cur.get("revoked"):
        return
    try:
        _, ms = vault_authed("PUT", "sys/leases/revoke", {"lease_id": cur["lease_id"]})
        cur["revoked"] = True
        if cur["mode"] == "sts":
            log("app → vault", "PUT sys/leases/revoke", cur["lease_id"].split("/")[-1],
                "Vault lease destroyed - but AWS cannot recall an STS credential", "warn", ms)
        else:
            log("app → vault", "PUT sys/leases/revoke", cur["lease_id"].split("/")[-1],
                "Vault lease destroyed", "ok", ms)
            log("vault → aws", "iam:DeleteUser", "user/vault-dynamic/*",
                "throwaway IAM user deleted - credential is gone for good", "mint")
    except Exception as e:
        log("app → vault", "PUT sys/leases/revoke", "lease", str(e), "error")


def phase2_verify():
    """Re-test the same credential after revocation. The result differs by credential type."""
    creds = STATE.get("_p2_creds")
    cur = STATE["phase2"].get("current")
    if not creds or not cur:
        return
    if cur["mode"] != "sts":
        time.sleep(5)  # let the IAM deletion propagate
    r = aws_whoami(creds, "re-test after revoke")
    r["mode"] = cur["mode"]
    r["revoked"] = cur.get("revoked", False)
    STATE["phase2"]["verify"] = r


# --------------------------------------------------------------------------- poller

def poller():
    time.sleep(2)
    vault_login()
    phase1_meta()
    vault_conn()
    while True:
        try:
            phase1_read(call_aws=STATE["phase1"].get("access_key") is None)
        except Exception as e:
            log("app", "poll error", "phase1", str(e), "error")
        time.sleep(POLL_SECONDS)


# --------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if self.path == "/healthz":
            return self._send(200, "ok", "text/plain")
        if self.path == "/api/state":
            pub = {k: v for k, v in STATE.items() if not k.startswith("_")}
            pub["now"] = time.time()
            return self._send(200, json.dumps(pub))
        return self._send(404, "{}")

    def do_POST(self):
        actions = {
            "/api/login": lambda: (STATE.update({"_token": None}), vault_login(), phase1_meta(), vault_conn()),
            "/api/conn/refresh": vault_conn,
            "/api/phase1/refresh": lambda: phase1_read(True),
            "/api/phase2/issue": lambda: phase2_issue("sts"),
            "/api/phase2/issue-user": lambda: phase2_issue("user"),
            "/api/phase2/revoke": phase2_revoke,
            "/api/phase2/verify": phase2_verify,
        }
        fn = actions.get(self.path)
        if not fn:
            return self._send(404, "{}")
        try:
            fn()
            return self._send(200, json.dumps({"ok": True}))
        except Exception as e:
            log("app", "action failed", self.path, str(e), "error")
            return self._send(500, json.dumps({"ok": False, "error": str(e)}))


PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<title>Vault to AWS Credential Demo</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#e6edf3;font:13px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
header{padding:14px 20px;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
h1{font-size:15px;margin:0;font-weight:600}
.sub{color:#7d8590;font-size:12px}
.pill{padding:2px 8px;border-radius:20px;font-size:11px;border:1px solid #30363d}
.pill.ok{background:#0f2f1a;border-color:#238636;color:#3fb950}
.pill.err{background:#3d1418;border-color:#da3633;color:#f85149}
.wrap{display:grid;grid-template-columns:1fr 1fr 420px;gap:14px;padding:14px;align-items:start}
@media(max-width:1500px){.wrap{grid-template-columns:1fr 1fr}.logcol{grid-column:1/-1}}
@media(max-width:1000px){.wrap{grid-template-columns:1fr}}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px}
.card h2{font-size:13px;margin:0 0 3px;display:flex;align-items:center;gap:8px}
.card .why{color:#7d8590;font-size:11.5px;margin:0 0 12px;line-height:1.45}
.tag{font-size:10px;padding:1px 7px;border-radius:4px;background:#1f6feb33;color:#79c0ff;border:1px solid #1f6feb55}
.tag.p2{background:#a371f733;color:#d2a8ff;border-color:#a371f755}
.kv{display:grid;grid-template-columns:120px 1fr;gap:4px 10px;font-size:12px;margin:8px 0}
.kv div:nth-child(odd){color:#7d8590}
.key{font-size:17px;letter-spacing:.4px;padding:9px 11px;background:#0d1117;border:1px solid #30363d;
     border-radius:6px;word-break:break-all;transition:all .5s}
.key.flash{background:#1a3a1f;border-color:#3fb950;box-shadow:0 0 0 3px #3fb95022}
.arn{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px 10px;
     word-break:break-all;font-size:11.5px;color:#79c0ff}
.bar{height:5px;background:#21262d;border-radius:3px;overflow:hidden;margin:8px 0 2px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,#1f6feb,#3fb950);transition:width 1s linear}
.bar.p2 i{background:linear-gradient(90deg,#a371f7,#f85149)}
button{background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:7px 12px;
       font-size:12px;cursor:pointer;font-weight:500}
button:hover{background:#30363d}
button.primary{background:#1f6feb;border-color:#1f6feb}button.primary:hover{background:#388bfd}
button.p2{background:#8957e5;border-color:#8957e5}button.p2:hover{background:#a371f7}
button.danger{background:#8b2c2c;border-color:#b33}button.danger:hover{background:#b33}
button:disabled{opacity:.4;cursor:not-allowed}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
table{width:100%;border-collapse:collapse;font-size:11px;margin-top:8px}
th{text-align:left;color:#7d8590;font-weight:500;padding:4px 6px;border-bottom:1px solid #21262d}
td{padding:4px 6px;border-bottom:1px solid #21262d20}
.log{max-height:74vh;overflow:auto}
.ev{display:grid;grid-template-columns:52px 96px 1fr;gap:8px;padding:5px 6px;border-bottom:1px solid #21262d40;font-size:11px}
.ev:hover{background:#1c2128}
.ev .t{color:#6e7681}
.ev .a{font-size:9.5px;padding:1px 5px;border-radius:3px;text-align:center;height:16px;line-height:14px;border:1px solid}
.a-appvault{background:#1f6feb22;color:#79c0ff;border-color:#1f6feb44}
.a-appaws{background:#3fb95022;color:#3fb950;border-color:#3fb95044}
.a-vaultaws{background:#f8514922;color:#ff7b72;border-color:#f8514944}
.a-app{background:#30363d;color:#8b949e;border-color:#484f58}
.ev .d{color:#8b949e;word-break:break-all}
.ev .d b{color:#e6edf3;font-weight:500}
.ev.error .d b{color:#f85149}
.flow{width:100%;height:118px;margin:2px 0 10px}
.flow text{font:10px ui-monospace,monospace;fill:#8b949e}
.flow .box{fill:#0d1117;stroke:#30363d}
.flow .lbl{fill:#e6edf3;font-size:10.5px}
.note{font-size:11px;color:#7d8590;border-left:2px solid #30363d;padding-left:9px;margin-top:10px;line-height:1.5}
.stale{opacity:.45}
.conn{display:grid;grid-template-columns:270px 1fr 1fr;gap:20px;align-items:start;
      margin:14px 14px 0;padding:12px 15px;background:#161b22;border:1px solid #21262d;
      border-left:3px solid #6e7681;border-radius:8px}
.conn.wif,.conn.ambient{border-left-color:#3fb950}
.conn.static{border-left-color:#d29922}
.conn.unknown{border-left-color:#f85149}
.conn-lbl{font-size:9.5px;letter-spacing:.09em;text-transform:uppercase;color:#7d8590}
.conn-title{font-size:13.5px;font-weight:600;margin-top:4px;line-height:1.3}
.conn-kv{display:grid;grid-template-columns:115px 1fr;gap:4px 10px;font-size:11.5px}
.conn-kv div:nth-child(odd){color:#7d8590}
.conn-note{font-size:11px;color:#8b949e;line-height:1.55;border-left:2px solid #30363d;padding-left:10px}
@media(max-width:1000px){.conn{grid-template-columns:1fr}}
</style></head><body>
<header>
  <h1>Vault &rarr; AWS Credential Demo</h1>
  <span class="pill" id="authpill">connecting...</span>
  <span class="sub mono" id="cfg"></span>
</header>

<section class="conn" id="conn">
  <div>
    <div class="conn-lbl">Vault &rarr; AWS authentication</div>
    <div class="conn-title" id="conntitle">reading&hellip;</div>
  </div>
  <div class="conn-kv">
    <div>identity</div><div class="mono" id="conndetail">-</div>
    <div>secret material</div><div class="mono" id="connsecret">-</div>
    <div>region</div><div class="mono" id="connregion">-</div>
  </div>
  <div class="conn-note" id="connnote"></div>
</section>

<svg class="flow" viewBox="0 0 1200 118">
  <rect class="box" x="10"  y="34" width="176" height="50" rx="6"/>
  <text class="lbl" x="98" y="55" text-anchor="middle">demo app (pod)</text>
  <text x="98" y="70" text-anchor="middle">ns/demo-apps &middot; sa/demo-app</text>

  <rect class="box" x="300" y="34" width="200" height="50" rx="6"/>
  <text class="lbl" x="400" y="55" text-anchor="middle">Vault Enterprise</text>
  <text x="400" y="70" text-anchor="middle">ns apps</text>

  <rect class="box" x="640" y="10" width="240" height="44" rx="6"/>
  <text class="lbl" x="760" y="30" text-anchor="middle">AWS IAM &middot; 111122223333</text>
  <text x="760" y="45" text-anchor="middle">user/demo-app (Phase 1)</text>

  <rect class="box" x="640" y="66" width="240" height="44" rx="6"/>
  <text class="lbl" x="760" y="86" text-anchor="middle">AWS STS &middot; 111122223333</text>
  <text x="760" y="101" text-anchor="middle">role/dynamic-role (Phase 2)</text>

  <rect class="box" x="990" y="34" width="196" height="50" rx="6"/>
  <text class="lbl" x="1088" y="55" text-anchor="middle">s3 / sts calls</text>
  <text x="1088" y="70" text-anchor="middle">proves cred works</text>

  <path d="M186 59 L296 59" stroke="#1f6feb" stroke-width="1.5" marker-end="url(#a)"/>
  <text x="241" y="52" text-anchor="middle">1. k8s auth</text>
  <path d="M500 50 L636 34" stroke="#f85149" stroke-width="1.5" marker-end="url(#a)"/>
  <text x="568" y="34" text-anchor="middle">2. rotate</text>
  <path d="M500 68 L636 84" stroke="#a371f7" stroke-width="1.5" marker-end="url(#a)"/>
  <text x="568" y="95" text-anchor="middle">2. AssumeRole</text>
  <path d="M880 59 L986 59" stroke="#3fb950" stroke-width="1.5" marker-end="url(#a)"/>
  <text x="933" y="52" text-anchor="middle">3. use</text>
  <defs><marker id="a" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
    <path d="M0 0 L7 3.5 L0 7 z" fill="#484f58"/></marker></defs>
</svg>

<div class="wrap">
  <div class="card">
    <h2><span class="tag">PHASE 1</span> Static key, rotated by Vault</h2>
    <p class="why">The IAM user never changes &mdash; its ARN, policies and CloudTrail history all stay intact.
       Only the key material rotates, on Vault's schedule, with no human involved.</p>
    <div class="kv">
      <div>IAM user</div><div class="mono" id="p1user">-</div>
      <div>rotation</div><div class="mono" id="p1rot">-</div>
      <div>next in</div><div class="mono" id="p1ttl">-</div>
    </div>
    <div class="bar"><i id="p1bar" style="width:0%"></i></div>
    <div style="color:#7d8590;font-size:11px;margin:10px 0 4px">current access key id</div>
    <div class="key mono" id="p1key">-</div>
    <div class="kv"><div>secret</div><div class="mono" id="p1sec">-</div></div>
    <div style="color:#7d8590;font-size:11px;margin:10px 0 4px">identity when app calls AWS</div>
    <div class="arn mono" id="p1arn">-</div>
    <div class="kv"><div>s3 buckets</div><div class="mono" id="p1s3">-</div></div>
    <div class="row">
      <button class="primary" onclick="post('/api/phase1/refresh')">Re-read &amp; call AWS</button>
    </div>
    <table><thead><tr><th>rotated at</th><th>old key</th><th>new key</th></tr></thead>
      <tbody id="p1hist"><tr><td colspan="3" style="color:#6e7681">watching for rotation...</td></tr></tbody></table>
    <p class="note">The ARN above stays identical across every rotation. That is the whole point:
       the workload's AWS identity is stable, only the credential is disposable.</p>
  </div>

  <div class="card">
    <h2><span class="tag p2">PHASE 2</span> Dynamic JIT credential</h2>
    <p class="why">No standing credential at all. Vault mints one on demand and it expires by itself.
       Two flavours, with genuinely different revocation behaviour &mdash; see the note below.</p>
    <div class="kv">
      <div>type</div><div class="mono" id="p2kind">-</div>
      <div>lease id</div><div class="mono" id="p2lease">-</div>
      <div>expires in</div><div class="mono" id="p2ttl">-</div>
    </div>
    <div class="bar p2"><i id="p2bar" style="width:0%"></i></div>
    <div style="color:#7d8590;font-size:11px;margin:10px 0 4px">issued access key id</div>
    <div class="key mono" id="p2key">-</div>
    <div class="kv">
      <div>secret</div><div class="mono" id="p2sec">-</div>
      <div>session token</div><div class="mono" id="p2tok">-</div>
    </div>
    <div style="color:#7d8590;font-size:11px;margin:10px 0 4px">identity when app calls AWS</div>
    <div class="arn mono" id="p2arn">-</div>
    <div class="kv"><div>s3 buckets</div><div class="mono" id="p2s3">-</div></div>
    <div class="row">
      <button class="p2" onclick="post('/api/phase2/issue')">Request JIT cred &middot; assumed_role</button>
      <button class="p2" onclick="post('/api/phase2/issue-user')">Request JIT cred &middot; iam_user</button>
    </div>
    <div class="row">
      <button class="danger" id="revbtn" onclick="post('/api/phase2/revoke')">Revoke lease</button>
      <button onclick="post('/api/phase2/verify')">Re-test the same credential</button>
    </div>
    <div id="p2ver" class="note" style="border-left-color:#484f58">-</div>
    <table><thead><tr><th>issued</th><th>key</th><th>session identity</th></tr></thead>
      <tbody id="p2hist"><tr><td colspan="3" style="color:#6e7681">none issued yet</td></tr></tbody></table>
    <p class="note"><b>Read this before demoing revoke.</b>
       <code>assumed_role</code> issues an AWS <i>STS</i> credential, and AWS provides no way to recall one
       &mdash; revoking the lease removes Vault's record, but the credential stays valid until its TTL expires.
       Short TTLs are the control. <code>iam_user</code> instead creates a throwaway IAM user, so revoking
       really does kill it instantly. Demo both and the difference lands.</p>
  </div>

  <div class="card logcol">
    <h2>Live call log</h2>
    <p class="why">Every hop, in one place: app&rarr;Vault, Vault&rarr;AWS, app&rarr;AWS.</p>
    <div class="row" style="margin:0 0 8px">
      <button onclick="post('/api/login')">Re-authenticate to Vault</button>
    </div>
    <div class="log" id="log"></div>
  </div>
</div>

<script>
let S=null, lastKey=null, SKEW=0;
const $=id=>document.getElementById(id);
const cls=a=>a==='app → vault'?'a-appvault':a==='app → aws'?'a-appaws':a==='vault → aws'?'a-vaultaws':'a-app';
const short=a=>a==='app → vault'?'app→vault':a==='app → aws'?'app→aws':a==='vault → aws'?'vault→aws':'app';

async function post(u){ await fetch(u,{method:'POST'}); await load(); }

async function load(){
  try{ S = await (await fetch('/api/state')).json(); }catch(e){ return; }
  SKEW = S.now - Date.now()/1000;
  const a=S.auth, c=S.config;
  $('cfg').textContent = `${c.vault_addr}  ns=${c.vault_namespace}  auth=${c.auth_mount}/${c.vault_role}  aws=${c.aws_mount}  pod=${c.pod}`;
  const p=$('authpill');
  if(a.status==='authenticated'){ p.className='pill ok'; p.textContent=`vault token ok · ${a.policies.join(',')}`; }
  else { p.className='pill err'; p.textContent=a.status==='error'?('auth error: '+(a.error||'').slice(0,60)):a.status; }

  const cn=S.connection||{};
  $('conn').className      = 'conn '+(cn.method||'');
  $('conntitle').textContent  = cn.title||'-';
  $('conndetail').textContent = cn.detail||'-';
  $('connsecret').textContent = cn.secret||'-';
  $('connregion').textContent = cn.region||'-';
  $('connnote').textContent   = cn.note||'';

  const p1=S.phase1;
  $('p1user').textContent = p1.username||'-';
  $('p1rot').textContent  = p1.rotation_period? p1.rotation_period+'s' : '-';
  $('p1key').textContent  = p1.access_key||'-';
  $('p1sec').textContent  = p1.secret_preview||'-';
  if(p1.access_key && lastKey && p1.access_key!==lastKey){
    const k=$('p1key'); k.classList.add('flash'); setTimeout(()=>k.classList.remove('flash'),2500);
  }
  if(p1.access_key) lastKey=p1.access_key;
  $('p1arn').textContent = p1.whoami? (p1.whoami.ok? p1.whoami.arn : 'ERROR '+p1.whoami.error) : '-';
  $('p1s3').textContent  = p1.s3? (p1.s3.ok? p1.s3.buckets.join(', ') : 'denied') : '-';
  $('p1hist').innerHTML = (p1.history||[]).length
    ? p1.history.map(h=>`<tr><td>${h.ts}</td><td class="mono" style="color:#6e7681">${h.old}</td><td class="mono" style="color:#3fb950">${h.new}</td></tr>`).join('')
    : '<tr><td colspan="3" style="color:#6e7681">watching for rotation...</td></tr>';

  const cur=S.phase2.current;
  if(cur){
    $('p2kind').textContent  = cur.kind;
    $('p2lease').textContent = cur.lease_id.split('/').pop();
    $('p2key').textContent   = cur.access_key;
    $('p2sec').textContent   = cur.secret_preview;
    $('p2tok').textContent   = cur.session_preview;
    $('p2arn').textContent   = cur.whoami? (cur.whoami.ok? cur.whoami.arn : 'ERROR '+cur.whoami.error) : '-';
    $('p2s3').textContent    = cur.s3? (cur.s3.ok? cur.s3.buckets.join(', ') : 'denied') : '-';
    $('revbtn').disabled     = cur.revoked;
    document.querySelectorAll('#p2key,#p2arn').forEach(e=>e.classList.toggle('stale',cur.revoked));
  }
  const v=S.phase2.verify;
  if(!v){ $('p2ver').innerHTML='<span style="color:#6e7681">Issue a credential, revoke it, then re-test to see what AWS actually does.</span>'; }
  else if(v.ok && v.mode==='sts' && v.revoked){
    $('p2ver').innerHTML = '<span style="color:#d29922"><b>Still accepted by AWS — and that is correct.</b></span><br>'
      + 'AWS cannot recall an STS credential. Vault dropped the lease, but this credential keeps working until its TTL runs out. '
      + 'The mitigation is a short TTL, or an IAM policy denying <code>aws:TokenIssueTime</code> before now.';
  }
  else if(!v.ok && v.revoked){
    $('p2ver').innerHTML = '<span style="color:#3fb950"><b>Rejected by AWS — the credential is gone.</b></span><br>'
      + 'Vault deleted the throwaway IAM user, so the key no longer maps to anything.';
  }
  else { $('p2ver').innerHTML = v.ok? '<span style="color:#3fb950">valid: '+v.arn+'</span>'
                                    : '<span style="color:#f85149">rejected: '+(v.error||'').slice(0,120)+'</span>'; }
  $('p2hist').innerHTML = (S.phase2.issued||[]).length
    ? S.phase2.issued.map(h=>`<tr><td>${h.ts}<br><span style="color:#6e7681">${h.mode==='sts'?'assumed_role':'iam_user'}</span></td><td class="mono">${h.access_key}</td><td class="mono" style="color:#d2a8ff">${(h.arn||'').split('/').slice(-1)[0]}</td></tr>`).join('')
    : '<tr><td colspan="3" style="color:#6e7681">none issued yet</td></tr>';

  $('log').innerHTML = S.log.map(e=>`<div class="ev ${e.status}">
      <div class="t">${e.ts}</div>
      <div class="a ${cls(e.actor)}">${short(e.actor)}</div>
      <div class="d"><b>${e.action}</b> ${e.target?'&middot; '+e.target:''} ${e.ms!=null?'<span style="color:#6e7681">'+e.ms+'ms</span>':''}<br>${e.detail||''}</div>
    </div>`).join('');
  tick();
}

function tick(){
  if(!S) return;
  const p1=S.phase1;
  if(p1.expires_at && p1.rotation_period){
    const left = Math.max(0, p1.expires_at - (Date.now()/1000 + SKEW));
    $('p1ttl').textContent = Math.ceil(left)+'s';
    $('p1bar').style.width = Math.min(100, 100 - left/p1.rotation_period*100).toFixed(1)+'%';
  }
  const cur=S.phase2.current;
  if(cur){
    const left = Math.max(0, cur.lease_duration - (Date.now()/1000 + SKEW - cur.issued_at));
    $('p2ttl').textContent = cur.revoked? 'revoked' : Math.ceil(left)+'s';
    $('p2bar').style.width = cur.revoked? '100%' : (100 - left/cur.lease_duration*100).toFixed(1)+'%';
  }
}
load(); setInterval(load, 3000); setInterval(tick, 1000);
</script></body></html>"""

if __name__ == "__main__":
    threading.Thread(target=poller, daemon=True).start()
    log("app", "demo app started", f"pod {os.environ.get('POD_NAME', '?')}",
        f"vault={VAULT_ADDR} ns={VAULT_NS}", "ok")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
