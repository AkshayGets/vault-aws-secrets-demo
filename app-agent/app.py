#!/usr/bin/env python3
"""
Vault -> AWS credential demo, version 2 - Vault Agent Injector.

The point of this version is what is MISSING. There is no Vault address, no Vault
token, no login, no Vault API call and no Vault library anywhere in this file. A
sidecar the platform team added does all of that and writes credentials to files.

This application only:
  1. reads two files, and
  2. calls AWS with whatever it finds in them.

Compare with app/app.py, which does its own Kubernetes auth login and reads Vault
paths directly. Same demo, same AWS calls, roughly a third of the code.

Deliberately stdlib-only, SigV4 signed inline, so nothing is hidden in a library.
"""
import datetime, hashlib, hmac, json, os, threading, time
import urllib.error, urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# The only configuration this app has. Both are file paths, not endpoints, and
# neither is a secret. The Vault Agent sidecar decides what lands in them.
STATIC_FILE = os.environ.get("STATIC_CRED_FILE", "/vault/secrets/aws-static.json")
DYNAMIC_FILE = os.environ.get("DYNAMIC_CRED_FILE", "/vault/secrets/aws-dynamic.json")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "3"))

STATE = {
    "files": {},
    "static": {"history": []},
    "dynamic": {},
    "log": [],
    "config": {
        "static_file": STATIC_FILE, "dynamic_file": DYNAMIC_FILE, "region": AWS_REGION,
        "pod": os.environ.get("POD_NAME", "?"),
        "k8s_ns": os.environ.get("POD_NAMESPACE", "demo-apps"),
    },
}
LOCK = threading.Lock()
SEQ = [0]


def log(actor, action, detail="", status="ok", ms=None):
    with LOCK:
        SEQ[0] += 1
        STATE["log"].insert(0, {
            "n": SEQ[0], "ts": datetime.datetime.now().strftime("%H:%M:%S"),
            "actor": actor, "action": action, "detail": detail, "status": status, "ms": ms,
        })
        del STATE["log"][250:]


def mask(secret, keep=4):
    if not secret:
        return ""
    return secret[:keep] + "•" * 10 + secret[-2:] if len(secret) > keep + 2 else "•" * 10


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


def aws_whoami(creds, label):
    """sts:GetCallerIdentity - proves WHICH identity this credential maps to."""
    body = b"Action=GetCallerIdentity&Version=2011-06-15"
    try:
        xml, ms = sigv4("POST", f"https://sts.{AWS_REGION}.amazonaws.com/", "sts",
                        creds["access_key"], creds["secret_key"], creds.get("session_token"),
                        body, {"content-type": "application/x-www-form-urlencoded"})
        ns = "{https://sts.amazonaws.com/doc/2011-06-15/}"
        arn = ET.fromstring(xml).find(f".//{ns}Arn").text
        log("app → aws", "sts:GetCallerIdentity", f"{label} → {arn}", "ok", ms)
        return {"ok": True, "arn": arn, "ms": ms}
    except urllib.error.HTTPError as e:
        msg = e.read().decode()[:200]
        log("app → aws", "sts:GetCallerIdentity", f"{label} → {msg}", "error")
        return {"ok": False, "error": msg}
    except Exception as e:
        log("app → aws", "sts:GetCallerIdentity", f"{label} → {e}", "error")
        return {"ok": False, "error": str(e)}


def aws_list_buckets(creds, label):
    """s3:ListAllMyBuckets - proves the credential is AUTHORIZED, not merely valid."""
    try:
        xml, ms = sigv4("GET", f"https://s3.{AWS_REGION}.amazonaws.com/", "s3",
                        creds["access_key"], creds["secret_key"], creds.get("session_token"))
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        names = [b.find(f"{ns}Name").text for b in ET.fromstring(xml).iter(f"{ns}Bucket")]
        log("app → aws", "s3:ListAllMyBuckets", f"{label} → {len(names)} bucket(s)", "ok", ms)
        return {"ok": True, "buckets": names, "ms": ms}
    except urllib.error.HTTPError as e:
        msg = e.read().decode()[:200]
        log("app → aws", "s3:ListAllMyBuckets", f"{label} → {msg}", "error")
        return {"ok": False, "error": msg}
    except Exception as e:
        log("app → aws", "s3:ListAllMyBuckets", f"{label} → {e}", "error")
        return {"ok": False, "error": str(e)}


# ------------------------------------------------------- reading the injected files

def read_cred_file(path):
    """The entire 'integration'. No Vault client, no token, no network call."""
    try:
        st = os.stat(path)
        with open(path) as fh:
            raw = fh.read()
        return {"exists": True, "mtime": st.st_mtime, "size": st.st_size,
                "raw": raw, "data": json.loads(raw)}
    except FileNotFoundError:
        return {"exists": False, "error": "not present yet - the sidecar has not rendered it"}
    except json.JSONDecodeError as e:
        return {"exists": True, "error": f"file is not valid JSON yet: {e}"}
    except Exception as e:
        return {"exists": False, "error": str(e)}


def refresh(kind, path, force=False):
    """Re-read a file and, if its contents changed, call AWS with the new credential."""
    f = read_cred_file(path)
    prev = STATE["files"].get(kind, {})
    STATE["files"][kind] = {
        "path": path, "exists": f.get("exists", False), "error": f.get("error"),
        "mtime": f.get("mtime"), "size": f.get("size"),
    }
    if not f.get("exists") or f.get("error"):
        return
    d = f["data"]
    changed = prev.get("mtime") != f["mtime"]
    slot = STATE[kind]
    old_key = slot.get("access_key")

    if changed and old_key and old_key != d.get("access_key"):
        log("sidecar → file", f"re-rendered {os.path.basename(path)}",
            f"{old_key} → {d['access_key']}", "rotate")
        slot["history"] = ([{"ts": datetime.datetime.now().strftime("%H:%M:%S"),
                             "old": old_key, "new": d["access_key"]}]
                           + slot.get("history", []))[:15]
        slot["flash"] = time.time()

    slot["access_key"] = d.get("access_key")
    slot["secret_preview"] = mask(d.get("secret_key"))
    slot["has_session_token"] = bool(d.get("session_token"))
    slot["expiration"] = d.get("expiration")
    slot["ttl"] = d.get("ttl")
    slot["arn_from_vault"] = d.get("arn")
    slot["rendered_at"] = f["mtime"]

    if changed or force or not slot.get("whoami"):
        creds = {"access_key": d.get("access_key"), "secret_key": d.get("secret_key"),
                 "session_token": d.get("session_token")}
        label = f"{kind} credential {d.get('access_key')}"
        slot["whoami"] = aws_whoami(creds, label)
        slot["s3"] = aws_list_buckets(creds, label)


def poller():
    log("app", "started", "watching the two files the sidecar writes", "ok")
    while True:
        for kind, path in (("static", STATIC_FILE), ("dynamic", DYNAMIC_FILE)):
            try:
                refresh(kind, path)
            except Exception as e:
                log("app", f"error reading {kind}", str(e), "error")
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
            pub = dict(STATE)
            pub["now"] = time.time()
            return self._send(200, json.dumps(pub))
        return self._send(404, "{}")

    def do_POST(self):
        if self.path == "/api/refresh":
            try:
                refresh("static", STATIC_FILE, force=True)
                refresh("dynamic", DYNAMIC_FILE, force=True)
                return self._send(200, json.dumps({"ok": True}))
            except Exception as e:
                return self._send(500, json.dumps({"ok": False, "error": str(e)}))
        return self._send(404, "{}")


PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<title>Vault Agent Injector Demo</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#fbfaf8;color:#1c1a17;font:14px/1.6 ui-sans-serif,-apple-system,"Segoe UI",sans-serif}
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
header{padding:18px 24px;border-bottom:1px solid #e6e1d8;display:flex;align-items:baseline;gap:14px;flex-wrap:wrap}
h1{font-size:16px;margin:0;font-weight:650;letter-spacing:-.01em}
.sub{color:#7a7266;font-size:12px}
.pill{padding:2px 9px;border-radius:20px;font-size:11px;border:1px solid #d8d1c5;background:#fff}
.pill.ok{background:#eaf5ec;border-color:#a8ceb1;color:#2f6d3d}
.pill.err{background:#fdeceb;border-color:#e6b0ab;color:#a32b22}
.wrap{max-width:1180px;margin:0 auto;padding:20px 24px 60px;display:flex;flex-direction:column;gap:18px}
.hero{background:#fff;border:1px solid #e6e1d8;border-radius:10px;padding:18px 20px}
.hero h2{margin:0 0 4px;font-size:14px;font-weight:650}
.hero p{margin:0 0 14px;color:#7a7266;font-size:12.5px;max-width:70ch}
.files{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:900px){.files{grid-template-columns:1fr}}
.file{border:1px solid #e6e1d8;border-radius:8px;background:#fdfcfa;padding:12px 14px}
.file.flash{border-color:#3f9c53;box-shadow:0 0 0 3px #3f9c5322}
.file h3{margin:0 0 8px;font-size:12px;font-weight:600;display:flex;justify-content:space-between;gap:8px}
.file .p{font-size:11.5px;color:#7a7266;word-break:break-all}
.blob{margin-top:8px;background:#1c1a17;color:#e9e4da;border-radius:6px;padding:10px 11px;
      font-size:11px;line-height:1.65;overflow-x:auto;white-space:pre}
.blob .k{color:#9ec7ff}.blob .v{color:#ffd9a0}.blob .m{color:#7a7266}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.card{background:#fff;border:1px solid #e6e1d8;border-radius:10px;padding:18px 20px}
.card h2{margin:0 0 3px;font-size:14px;font-weight:650;display:flex;align-items:center;gap:9px}
.card .why{color:#7a7266;font-size:12.5px;margin:0 0 14px;max-width:52ch}
.tag{font-size:10px;padding:2px 8px;border-radius:4px;background:#eef2fb;color:#2f5aa8;border:1px solid #cdd9f0;font-weight:600}
.tag.d{background:#f5eefb;color:#6b3fa0;border-color:#ddcbf0}
.key{font-size:17px;letter-spacing:.3px;padding:10px 12px;background:#fdfcfa;border:1px solid #e6e1d8;
     border-radius:7px;word-break:break-all;transition:all .5s}
.key.flash{background:#eaf5ec;border-color:#3f9c53}
.kv{display:grid;grid-template-columns:132px 1fr;gap:5px 12px;font-size:12.5px;margin:12px 0 0}
.kv div:nth-child(odd){color:#7a7266}
.arn{background:#fdfcfa;border:1px solid #e6e1d8;border-radius:7px;padding:9px 11px;
     word-break:break-all;font-size:11.5px;color:#2f5aa8;margin-top:4px}
.lbl{color:#7a7266;font-size:11px;margin:14px 0 5px}
table{width:100%;border-collapse:collapse;font-size:11.5px;margin-top:12px}
th{text-align:left;color:#7a7266;font-weight:500;padding:5px 6px;border-bottom:1px solid #e6e1d8}
td{padding:5px 6px;border-bottom:1px solid #f0ece4}
button{background:#1c1a17;color:#fbfaf8;border:0;border-radius:7px;padding:8px 14px;font-size:12.5px;
       cursor:pointer;font-weight:500}
button:hover{background:#3a352e}
.log{background:#fff;border:1px solid #e6e1d8;border-radius:10px;padding:14px 18px}
.log h2{margin:0 0 10px;font-size:14px;font-weight:650}
.ev{display:grid;grid-template-columns:58px 108px 1fr;gap:10px;padding:5px 4px;border-bottom:1px solid #f4f0e9;font-size:11.5px}
.ev .t{color:#a49a8c}
.ev .a{font-size:9.5px;padding:2px 6px;border-radius:4px;text-align:center;height:18px;line-height:14px;border:1px solid}
.a-appaws{background:#eaf5ec;color:#2f6d3d;border-color:#bcdcc4}
.a-sidecar{background:#f5eefb;color:#6b3fa0;border-color:#ddcbf0}
.a-app{background:#f2efe9;color:#6b6355;border-color:#ded8cc}
.ev .d{color:#4a453d;word-break:break-all}
.ev.error .d{color:#a32b22}
.note{font-size:12px;color:#7a7266;border-left:3px solid #e6e1d8;padding-left:12px;margin-top:14px;line-height:1.6}
.absent{color:#a32b22;font-size:12px}
</style></head><body>
<header>
  <h1>Vault Agent Injector</h1>
  <span class="pill" id="pill">starting…</span>
  <span class="sub mono" id="cfg"></span>
</header>

<div class="wrap">

  <div class="hero">
    <h2>What this application knows about Vault</h2>
    <p><strong>Nothing.</strong> There is no Vault address, no token, no login and no Vault
       library in this app. A sidecar container authenticates on the pod's behalf and writes
       these two files. The app reads files — that is the entire integration.</p>
    <div class="files">
      <div class="file" id="fstatic">
        <h3><span>Phase 1 · rotating static key</span><span class="mono" id="fstatic-age">-</span></h3>
        <div class="p mono" id="fstatic-path">-</div>
        <div class="blob" id="fstatic-body">waiting for the sidecar…</div>
      </div>
      <div class="file" id="fdynamic">
        <h3><span>Phase 2 · just-in-time credential</span><span class="mono" id="fdynamic-age">-</span></h3>
        <div class="p mono" id="fdynamic-path">-</div>
        <div class="blob" id="fdynamic-body">waiting for the sidecar…</div>
      </div>
    </div>
    <p class="note">Both files are owned by the sidecar. When Vault rotates the Phase 1 key the
       sidecar rewrites the file; when the Phase 2 lease nears expiry it fetches a new credential
       and rewrites that one. The application is never told — it just re-reads.</p>
  </div>

  <div class="grid">
    <div class="card">
      <h2><span class="tag">PHASE 1</span> Rotating static key</h2>
      <p class="why">Vault owns an existing IAM user's access key and replaces it every minute.
         The user, its ARN and its policies never change.</p>
      <div class="lbl">access key id in the file right now</div>
      <div class="key mono" id="s-key">-</div>
      <div class="kv">
        <div>secret</div><div class="mono" id="s-sec">-</div>
        <div>next rotation</div><div class="mono" id="s-exp">-</div>
        <div>s3 buckets</div><div class="mono" id="s-s3">-</div>
      </div>
      <div class="lbl">identity when the app calls AWS</div>
      <div class="arn mono" id="s-arn">-</div>
      <table><thead><tr><th>file rewritten</th><th>old key</th><th>new key</th></tr></thead>
        <tbody id="s-hist"><tr><td colspan="3" style="color:#a49a8c">watching…</td></tr></tbody></table>
      <p class="note">The ARN stays identical across every rewrite. Stable identity,
         disposable credential — and the app never noticed.</p>
    </div>

    <div class="card">
      <h2><span class="tag d">PHASE 2</span> Just-in-time credential</h2>
      <p class="why">No standing credential. Vault assumes an IAM role on demand and the
         result expires by itself. The sidecar renews it before it lapses.</p>
      <div class="lbl">access key id in the file right now</div>
      <div class="key mono" id="d-key">-</div>
      <div class="kv">
        <div>secret</div><div class="mono" id="d-sec">-</div>
        <div>session token</div><div class="mono" id="d-tok">-</div>
        <div>lease ttl</div><div class="mono" id="d-ttl">-</div>
        <div>s3 buckets</div><div class="mono" id="d-s3">-</div>
      </div>
      <div class="lbl">identity when the app calls AWS</div>
      <div class="arn mono" id="d-arn">-</div>
      <p class="note">This is an STS session of <code>role/dynamic-role</code>, not an IAM
         user — nothing was created in IAM and nothing needs cleaning up. Note the session
         name: CloudTrail attributes every action back to the Vault role that asked.</p>
      <div style="margin-top:14px"><button onclick="post('/api/refresh')">Re-read files &amp; call AWS</button></div>
    </div>
  </div>

  <div class="log">
    <h2>What actually happened</h2>
    <div id="log"></div>
  </div>
</div>

<script>
const $=i=>document.getElementById(i);
let S={};
function esc(s){return (s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function age(t,now){ if(!t) return '-'; const d=Math.max(0,Math.round(now-t)); return d<60? d+'s ago' : Math.floor(d/60)+'m '+(d%60)+'s ago'; }

function blob(f, slot){
  if(!f || !f.exists) return '<span class="m">'+esc((f&&f.error)||'not present yet')+'</span>';
  if(f.error) return '<span class="m">'+esc(f.error)+'</span>';
  const rows=[['access_key', slot.access_key], ['secret_key', slot.secret_preview]];
  if(slot.has_session_token) rows.push(['session_token','(present, masked)']);
  if(slot.expiration) rows.push(['expiration', slot.expiration]);
  if(slot.ttl) rows.push(['ttl', slot.ttl]);
  return '{\n'+rows.map(r=>'  <span class="k">"'+r[0]+'"</span>: <span class="v">"'+esc(r[1])+'"</span>').join(',\n')+'\n}';
}

async function load(){
  try{ S = await (await fetch('/api/state')).json(); }catch(e){ return; }
  const now=S.now, c=S.config, F=S.files||{}, st=S.static||{}, dy=S.dynamic||{};
  $('cfg').textContent = `pod=${c.pod}  ns=${c.k8s_ns}  region=${c.region}`;

  const ready = (F.static&&F.static.exists) && (F.dynamic&&F.dynamic.exists);
  const p=$('pill');
  p.className='pill '+(ready?'ok':'err');
  p.textContent = ready ? 'both credential files present · no Vault code in this app'
                        : 'waiting for the sidecar to render files';

  for(const [k,slot] of [['static',st],['dynamic',dy]]){
    const f=F[k]||{};
    $('f'+k+'-path').textContent = f.path||'-';
    $('f'+k+'-age').textContent  = f.exists? ('rendered '+age(f.mtime,now)) : 'absent';
    $('f'+k+'-body').innerHTML   = blob(f, slot);
    const el=$('f'+k);
    if(slot.flash && now-slot.flash < 4) el.classList.add('flash'); else el.classList.remove('flash');
  }

  $('s-key').textContent = st.access_key||'-';
  $('s-sec').textContent = st.secret_preview||'-';
  $('s-exp').textContent = st.expiration||'-';
  $('s-arn').textContent = st.whoami? (st.whoami.ok? st.whoami.arn : 'ERROR '+st.whoami.error) : '-';
  $('s-s3').textContent  = st.s3? (st.s3.ok? st.s3.buckets.join(', ') : 'denied') : '-';
  if(st.flash && now-st.flash < 4) $('s-key').classList.add('flash'); else $('s-key').classList.remove('flash');
  $('s-hist').innerHTML = (st.history&&st.history.length)
    ? st.history.map(h=>`<tr><td>${esc(h.ts)}</td><td class="mono">${esc(h.old)}</td><td class="mono">${esc(h.new)}</td></tr>`).join('')
    : '<tr><td colspan="3" style="color:#a49a8c">watching…</td></tr>';

  $('d-key').textContent = dy.access_key||'-';
  $('d-sec').textContent = dy.secret_preview||'-';
  $('d-tok').textContent = dy.has_session_token? 'present (STS)' : 'none';
  $('d-ttl').textContent = dy.ttl||'-';
  $('d-arn').textContent = dy.whoami? (dy.whoami.ok? dy.whoami.arn : 'ERROR '+dy.whoami.error) : '-';
  $('d-s3').textContent  = dy.s3? (dy.s3.ok? dy.s3.buckets.join(', ') : 'denied') : '-';

  $('log').innerHTML = (S.log||[]).slice(0,45).map(e=>{
    const cls = e.actor.startsWith('app → aws') ? 'a-appaws' : (e.actor.startsWith('sidecar')?'a-sidecar':'a-app');
    return `<div class="ev ${e.status==='error'?'error':''}"><div class="t mono">${esc(e.ts)}</div>`+
           `<div class="a ${cls}">${esc(e.actor)}</div>`+
           `<div class="d"><b>${esc(e.action)}</b> ${esc(e.detail)}${e.ms?` <span style="color:#a49a8c">${e.ms}ms</span>`:''}</div></div>`;
  }).join('');
}
async function post(u){ await fetch(u,{method:'POST'}); load(); }
load(); setInterval(load, 2000);
</script>
</body></html>"""


if __name__ == "__main__":
    threading.Thread(target=poller, daemon=True).start()
    ThreadingHTTPServer(("", 8080), Handler).serve_forever()
