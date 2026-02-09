import os
import re
import time
import json
import base64
import threading
from datetime import datetime, timedelta, timezone
from collections import deque, OrderedDict

import requests
try:
    import ddddocr  # type: ignore
    _HAS_DDDDOCR = True
except Exception:
    ddddocr = None  # type: ignore
    _HAS_DDDDOCR = False
from flask import Flask, request, jsonify, render_template_string, send_from_directory, make_response
try:
    from apscheduler.schedulers.background import BackgroundScheduler  # type: ignore
    _HAS_APS = True
except Exception:
    BackgroundScheduler = None  # type: ignore
    _HAS_APS = False
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

app = Flask(__name__)

# =========================
# Background images (keep app(1).py behavior)
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BG_DIR = os.getenv("BG_DIR", os.path.join(BASE_DIR, "pic"))
BG_DIR = os.path.abspath(BG_DIR)

def list_bg_files():
    if not os.path.isdir(BG_DIR):
        return []
    exts = {".jpg", ".jpeg", ".png", ".webp"}
    files = []
    for name in os.listdir(BG_DIR):
        p = os.path.join(BG_DIR, name)
        if os.path.isfile(p) and os.path.splitext(name.lower())[1] in exts:
            files.append(name)
    files.sort()
    return files


def bg_url_for(name: str):
    try:
        mtime = int(os.path.getmtime(os.path.join(BG_DIR, name)))
    except Exception:
        mtime = int(time.time())
    return f"/bg/{name}?v={mtime}"


@app.get("/bg/<path:filename>")
def bg_file(filename):
    return send_from_directory(BG_DIR, filename)


@app.get("/favicon.ico")
def favicon():
    # Optional: silence browser 404 for favicon
    return ("", 204)


# =========================
# Environments (from cms-2.1.8.js mapping)
# =========================
DEFAULT_PROD_UAT_KEY = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNR7I+SpqIZM5w3Aw4lrUl"
    "hrs7VurKbeViYXNhOfIgP/4acsWvJy5dPb/FejzUiv2cAiz5As2DJEQYEM10L"
    "vnmpnKx9Dq+QDo7WXnT6H2szRtX/8Q56Rlzp9bJMlZy7/i0xevlDrWZMWqx2IK"
    "3ZhO9+0nPu4z4SLXaoQGIrs7JxwIDAQAB"
)

TEST_FIRST_PUBLIC_KEY = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaJkRNFpoQ5YkE86LuJQ/CtMaZ"
    "UxIyiU6kId1U+XBKfTQM82e+ptTfpx5TMguOn0YlF88L4PaKPIP6idFEjBup+7o0"
    "/bWFHjvuCla5v77uy1hB9xaGWSehqvZ1/ZFbas/r3Hkr0gsMf5NJqgGfYGS9otB"
    "QQltIInygzxrnj1+hdQIDAQAB"
)

# NOTE: account/password are read from env vars only (safer). Defaults for local dev.
DEFAULT_ACCOUNT = os.getenv("CMS_ACCOUNT", "tbh2356@126.com")
DEFAULT_PASSWORD = os.getenv("CMS_PASSWORD", "112233qq")

UAT_ACCOUNT = os.getenv("CMS_ACCOUNT", "6")
UAT_PASSWORD = os.getenv("CMS_PASSWORD", "112233qq")

T_ACCOUNT = os.getenv("CMS_ACCOUNT", "3")
T_PASSWORD = os.getenv("CMS_PASSWORD", "1")

CLUB_ID = int(os.getenv("CLUB_ID", "104137139"))
TCLUB_ID = int(os.getenv("CLUB_ID", "168123"))
UCLUB_ID = int(os.getenv("CLUB_ID", "16801"))
LOGIN_INTERVAL_MIN = int(os.getenv("LOGIN_INTERVAL_MIN", "90"))

ENVS = {
    "prod": {
        "name": "PROD",
        "api_base": "https://cmsapi3.qiucheng-wangluo.com",
        "referer": "https://cms.ayybyyy.com/",
        "first_public_key": os.getenv("FIRST_PUBLIC_KEY_PROD", DEFAULT_PROD_UAT_KEY),
        "account": os.getenv("CMS_PROD_ACCOUNT", DEFAULT_ACCOUNT),
        "password": os.getenv("CMS_PROD_PASSWORD", DEFAULT_PASSWORD),
        "club_id": CLUB_ID,
    },
    "uat": {
        "name": "UAT",
        "api_base": "https://cms-api.yahhp.shop",
        "referer": "https://cms.yahhp.shop/",
        "first_public_key": os.getenv("FIRST_PUBLIC_KEY_UAT", DEFAULT_PROD_UAT_KEY),
        "account": os.getenv("CMS_UAT_ACCOUNT", UAT_ACCOUNT),
        "password": os.getenv("CMS_UAT_PASSWORD", UAT_PASSWORD),
        "club_id": UCLUB_ID,
    },
    "test": {
        "name": "TEST",
        "api_base": "https://cms-distributed.lunarsphere.xyz:8081",
        "referer": "https://cms-web.lunarsphere.xyz/",
        "first_public_key": os.getenv("FIRST_PUBLIC_KEY_TEST", TEST_FIRST_PUBLIC_KEY),
        "account": os.getenv("CMS_TEST_ACCOUNT", T_ACCOUNT),
        "password": os.getenv("CMS_TEST_PASSWORD", T_PASSWORD),
        "club_id": TCLUB_ID,
    },
}


def _assert_env(env: str):
    if env not in ENVS:
        raise KeyError(f"unknown env: {env}")

def _ensure_env(env: str):
    # backward-compatible alias
    return _assert_env(env)


# =========================
# Logs (per env)
# =========================
LOG_MAX = 800
LOG_LOCK = threading.Lock()
ENV_LOGS = {k: deque(maxlen=LOG_MAX) for k in ENVS.keys()}


def log(env: str, msg: str):
    s = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {msg}"
    with LOG_LOCK:
        if env not in ENV_LOGS:
            ENV_LOGS[env] = deque(maxlen=LOG_MAX)
        ENV_LOGS[env].appendleft(s)


def log_sep(env: str, title: str):
    log(env, "── " + title + " " + "─" * 30)


def get_logs(env: str, limit: int = 350):
    with LOG_LOCK:
        return list(ENV_LOGS[env])[:limit]


def clear_logs(env: str):
    with LOG_LOCK:
        ENV_LOGS[env].clear()


# =========================
# Per-env runtime state
# =========================
STATE_LOCK = threading.Lock()
STATE = {
    k: {
        "token": "",
        "last_login_ok": False,
        "last_login_at": "",
        "last_login_err": "",
        "last_login_ts": 0.0,
        "next_due_ts": 0.0,
        "clubctx_ok": False,
        "clubctx_last_at": "",
        "clubctx_last_err": "",
    }
    for k in ENVS.keys()
}

# =========================
# Manage-mode accounts + token (independent from Unlock page)
# - Default: inherit env's base account/password (unlock defaults)
# - CMS功能管理页支持：同环境多账号保存/选择/删除，并在页面展示（仅展示账号，不展示密码）
# =========================
MANAGE_CREDS_FILE = os.path.abspath(os.getenv("MANAGE_CREDS_FILE", os.path.join(BASE_DIR, "data", "manage_creds.json")))
MANAGE_CREDS_LOCK = threading.Lock()

# env -> {"active": "<account>", "accounts": [{"account": "...", "password": "..."}, ...]}
MANAGE_CREDS = {env: {"active": "", "accounts": []} for env in ENVS.keys()}

MANAGE_STATE_LOCK = threading.Lock()
MANAGE_STATE = {
    env: {
        "token": "",
        "last_login_ok": False,
        "last_login_at": "",
        "last_login_err": "",
        "last_login_ts": 0.0,
        "clubctx_ok": False,
        "clubctx_last_at": "",
        "clubctx_last_err": "",
        "active_account": "",
    }
    for env in ENVS.keys()
}

def _normalize_manage_creds_env(payload: dict) -> dict:
    # Backward compatibility:
    # 1) old: {"account": "...", "password": "..."}
    # 2) mid: {"active": "...", "accounts": [{"account","password"}]}
    if not isinstance(payload, dict):
        return {"active": "", "accounts": []}

    if "accounts" not in payload and ("account" in payload or "password" in payload):
        a = str(payload.get("account") or "").strip()
        p = str(payload.get("password") or "").strip()
        accounts = [{"account": a, "password": p}] if (a and p) else []
        return {"active": a if a and p else "", "accounts": accounts}

    active = str(payload.get("active") or "").strip()
    accounts_in = payload.get("accounts") or []
    accounts = []
    if isinstance(accounts_in, list):
        for it in accounts_in:
            if not isinstance(it, dict):
                continue
            a = str(it.get("account") or "").strip()
            p = str(it.get("password") or "").strip()
            if a and p:
                accounts.append({"account": a, "password": p})
    # ensure active exists
    if active and not any(x["account"] == active for x in accounts):
        active = accounts[0]["account"] if accounts else ""
    if not active and accounts:
        active = accounts[0]["account"]
    return {"active": active, "accounts": accounts}

def _load_manage_creds():
    try:
        if not os.path.isfile(MANAGE_CREDS_FILE):
            return
        with open(MANAGE_CREDS_FILE, "r", encoding="utf-8") as f:
            j = json.load(f) or {}
        if not isinstance(j, dict):
            return
        with MANAGE_CREDS_LOCK:
            for env in ENVS.keys():
                MANAGE_CREDS[env] = _normalize_manage_creds_env(j.get(env) or {})
    except Exception:
        pass

def _save_manage_creds():
    _safe_mkdir(os.path.dirname(MANAGE_CREDS_FILE))
    with MANAGE_CREDS_LOCK:
        data = {env: MANAGE_CREDS.get(env) or {"active": "", "accounts": []} for env in ENVS.keys()}
    with open(MANAGE_CREDS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def list_manage_accounts(env: str):
    with MANAGE_CREDS_LOCK:
        item = MANAGE_CREDS.get(env) or {"active": "", "accounts": []}
        active = str(item.get("active") or "").strip()
        accounts = [{"account": x.get("account") or ""} for x in (item.get("accounts") or []) if (x.get("account") or "").strip()]
    return {"active": active, "accounts": accounts}

def _get_manage_account_password(env: str, account: str):
    account = str(account or "").strip()
    if not account:
        return "", ""
    with MANAGE_CREDS_LOCK:
        item = MANAGE_CREDS.get(env) or {}
        for it in (item.get("accounts") or []):
            if str(it.get("account") or "").strip() == account:
                return account, str(it.get("password") or "").strip()
    return "", ""

def get_manage_creds(env: str):
    # pick active; if none configured, inherit unlock creds
    with MANAGE_CREDS_LOCK:
        item = MANAGE_CREDS.get(env) or {}
        active = str(item.get("active") or "").strip()
    if active:
        a, p = _get_manage_account_password(env, active)
        if a and p:
            return a, p
    return ENVS[env]["account"], ENVS[env]["password"]

def upsert_manage_account(env: str, account: str, password: str, set_active: bool = True):
    account = str(account or "").strip()
    password = str(password or "").strip()
    if not account or not password:
        raise ValueError("account/password required")

    with MANAGE_CREDS_LOCK:
        item = MANAGE_CREDS.get(env) or {"active": "", "accounts": []}
        accounts = item.get("accounts") or []
        # remove existing same account
        accounts = [x for x in accounts if str(x.get("account") or "").strip() != account]
        accounts.insert(0, {"account": account, "password": password})
        item["accounts"] = accounts[:30]  # hard cap
        if set_active:
            item["active"] = account
        MANAGE_CREDS[env] = item

    _save_manage_creds()
    # mirror to state for UI
    set_manage_state(env, active_account=account)

def select_manage_account(env: str, account: str):
    account = str(account or "").strip()
    with MANAGE_CREDS_LOCK:
        item = MANAGE_CREDS.get(env) or {"active": "", "accounts": []}
        if account and any(str(x.get("account") or "").strip() == account for x in (item.get("accounts") or [])):
            item["active"] = account
        elif item.get("accounts"):
            item["active"] = str(item["accounts"][0].get("account") or "").strip()
        MANAGE_CREDS[env] = item
    _save_manage_creds()
    set_manage_state(env, active_account=str(MANAGE_CREDS[env].get("active") or ""))

def delete_manage_account(env: str, account: str):
    account = str(account or "").strip()
    with MANAGE_CREDS_LOCK:
        item = MANAGE_CREDS.get(env) or {"active": "", "accounts": []}
        accounts = [x for x in (item.get("accounts") or []) if str(x.get("account") or "").strip() != account]
        item["accounts"] = accounts
        active = str(item.get("active") or "").strip()
        if active == account:
            item["active"] = str(accounts[0].get("account") or "").strip() if accounts else ""
        MANAGE_CREDS[env] = item
    _save_manage_creds()
    set_manage_state(env, active_account=str(MANAGE_CREDS[env].get("active") or ""))

def set_manage_state(env: str, **kwargs):
    with MANAGE_STATE_LOCK:
        MANAGE_STATE[env].update(kwargs)

def get_manage_state(env: str):
    with MANAGE_STATE_LOCK:
        return dict(MANAGE_STATE[env])

def manage_set_token(env: str, token: str):
    set_manage_state(env, token=(token or ""))

def manage_get_token(env: str) -> str:
    return (get_manage_state(env).get("token") or "").strip()

def manage_ensure_club_context(env: str, token: str):
    # same clubInfo, but record into MANAGE_STATE
    log_sep(env, "MANAGE CLUB CONTEXT clubInfo")
    sc, j = fetch_club_info(env, token)
    log(env, f"INFO  [manage] clubInfo status={sc} body={j if isinstance(j, dict) else str(j)[:400]}")
    ok = sc == 200 and isinstance(j, dict) and j.get("iErrCode") == 0
    if ok:
        set_manage_state(env, clubctx_ok=True, clubctx_last_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), clubctx_last_err="")
        log(env, "SUCCESS [manage] clubInfo 上下文建立成功（iErrCode=0）")
        return True
    set_manage_state(env, clubctx_ok=False, clubctx_last_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), clubctx_last_err=str(j)[:500])
    log(env, "ERROR [manage] clubInfo 上下文失败")
    return False

def manage_refresh_token_once(env: str, source: str = "manage"):
    account, password = get_manage_creds(env)
    log_sep(env, f"MANAGE LOGIN FLOW ({source})")
    try:
        token = CLIENTS[env].login_and_get_token(account, password)
        set_manage_state(
            env,
            token=token,
            last_login_ok=True,
            last_login_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            last_login_err="",
            last_login_ts=time.time(),
            active_account=account,
        )
        ok_ctx = manage_ensure_club_context(env, token)
        if not ok_ctx:
            set_manage_state(env, last_login_ok=False, last_login_err="login ok but clubInfo fail")
            return False, "clubInfo fail"
        return True, "manage login+context ok"
    except Exception as e:
        set_manage_state(env, last_login_ok=False, last_login_err=str(e), last_login_ts=time.time())
        log_sep(env, "MANAGE LOGIN FAILED")
        log(env, f"ERROR [manage] 登录流程失败: {e}")
        return False, str(e)

# load manage creds at import
_load_manage_creds()


def set_state(env: str, **kwargs):
    with STATE_LOCK:
        STATE[env].update(kwargs)


def get_state(env: str):
    with STATE_LOCK:
        return dict(STATE[env])


def bump_next_due(env: str, minutes: int):
    ts = time.time() + minutes * 60
    set_state(env, next_due_ts=ts)
    return ts


def next_due_epoch_ms(env: str) -> int:
    st = get_state(env)
    ts = float(st.get("next_due_ts") or 0.0)
    if ts <= 0:
        return 0
    return int(ts * 1000)


# =========================
# User cache (per env) + persistence
# =========================
USERCACHE_LOCK = threading.Lock()
USERCACHE_MAX = 200
USERCACHE = {k: OrderedDict() for k in ENVS.keys()}  # env -> OrderedDict(showid->profile)

USERCACHE_PERSIST = (os.getenv("USERCACHE_PERSIST", "1").strip().lower() not in ("0", "false", "no"))
USERCACHE_FILE = os.getenv("USERCACHE_FILE", os.path.join(BASE_DIR, "data", "usercache.json"))
USERCACHE_FILE = os.path.abspath(USERCACHE_FILE)


def _safe_mkdir(p: str):
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        pass


def _save_usercache():
    if not USERCACHE_PERSIST:
        return
    try:
        _safe_mkdir(os.path.dirname(USERCACHE_FILE))
        with USERCACHE_LOCK:
            payload = {
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "envs": {env: list(USERCACHE[env].values()) for env in ENVS.keys()},
            }
        tmp = USERCACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp, USERCACHE_FILE)
    except Exception as e:
        # do not crash
        for env in ENVS.keys():
            log(env, f"WARNING USERCACHE 持久化写入失败: {e}")


def _load_usercache():
    if not USERCACHE_PERSIST:
        return
    try:
        if not os.path.isfile(USERCACHE_FILE):
            return
        with open(USERCACHE_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        envs = payload.get("envs") or {}
        if not isinstance(envs, dict):
            return
        with USERCACHE_LOCK:
            for env in ENVS.keys():
                USERCACHE[env].clear()
                items = envs.get(env) or []
                if not isinstance(items, list):
                    continue
                for it in items:
                    showid = str((it or {}).get("showid") or "").strip()
                    if not showid:
                        continue
                    USERCACHE[env][showid] = {
                        "showid": showid,
                        "uuid": (it or {}).get("uuid"),
                        "strNick": (it or {}).get("strNick") or "",
                        "strCover": (it or {}).get("strCover") or "",
                        "cached_at": (it or {}).get("cached_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                while len(USERCACHE[env]) > USERCACHE_MAX:
                    USERCACHE[env].popitem(last=False)
        for env in ENVS.keys():
            log(env, f"INFO  USERCACHE 已从磁盘恢复: env={env} count={len(USERCACHE[env])}")
    except Exception as e:
        for env in ENVS.keys():
            log(env, f"WARNING USERCACHE 从磁盘恢复失败: {e}")


_load_usercache()



# --- Runtime credentials persistence (per environment) ---
CREDS_PERSIST = (os.getenv("CREDS_PERSIST", "1").lower() not in ("0", "false", "no"))
CREDS_FILE = os.getenv("CREDS_FILE", os.path.join(BASE_DIR, "data", "creds.json"))
CREDS_FILE = os.path.abspath(CREDS_FILE)
CREDS = {k: {"account": "", "password": ""} for k in ENVS.keys()}


def _save_runtime_conf():
    if not CREDS_PERSIST:
        return
    try:
        _safe_mkdir(os.path.dirname(CREDS_FILE))
        data = {env: {"account": ENVS[env].get("account",""), "password": ENVS[env].get("password","")} for env in ENVS.keys()}
        with open(CREDS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _load_runtime_conf():
    if not CREDS_PERSIST:
        return
    try:
        if not os.path.exists(CREDS_FILE):
            return
        with open(CREDS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f) or {}
        for env in ENVS.keys():
            c = data.get(env) or {}
            a = (c.get("account") or "").strip()
            p = (c.get("password") or "").strip()
            if a and p:
                ENVS[env]["account"] = a
                ENVS[env]["password"] = p
                CREDS[env] = {"account": a, "password": p}
    except Exception:
        pass


_load_runtime_conf()



def cache_user(env: str, profile: dict):
    showid = str(profile.get("showid") or "").strip()
    if not showid:
        return
    with USERCACHE_LOCK:
        od = USERCACHE[env]
        if showid in od:
            del od[showid]
        od[showid] = {
            "showid": showid,
            "uuid": profile.get("uuid"),
            "strNick": profile.get("strNick") or "",
            "strCover": profile.get("strCover") or "",
            "cached_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        while len(od) > USERCACHE_MAX:
            od.popitem(last=False)
    _save_usercache()


def list_cached_users(env: str):
    with USERCACHE_LOCK:
        return list(reversed(list(USERCACHE[env].values())))


def delete_cached_user(env: str, showid: str) -> bool:
    showid = str(showid or "").strip()
    if not showid:
        return False
    removed = False
    with USERCACHE_LOCK:
        if showid in USERCACHE[env]:
            del USERCACHE[env][showid]
            removed = True
    if removed:
        _save_usercache()
    return removed


# =========================
# CMS client
# =========================
class CMSAutoLogin:
    def __init__(self, env: str, cfg: dict):
        self.env = env
        self.cfg = cfg
        self.session = requests.Session()
        self.ocr = ddddocr.DdddOcr() if _HAS_DDDDOCR else None
        self.max_attempts = 5

        self.api_base = cfg["api_base"].rstrip("/")
        self.referer = cfg["referer"].rstrip("/") + "/"
        self.first_public_key = cfg["first_public_key"]

        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": self.referer,
        }

    def _url(self, path: str) -> str:
        return self.api_base + path

    def get_captcha_token(self):
        url = self._url("/cms-api/token/generateCaptchaToken")
        r = self.session.post(url, headers=self.headers, timeout=15)
        r.raise_for_status()
        j = r.json()
        if j.get("iErrCode") != 0:
            raise RuntimeError(f"generateCaptchaToken失败: {j.get('sErrMsg')}")
        return j.get("result")

    def get_captcha_img_b64(self, captcha_token: str):
        url = self._url("/cms-api/captcha")
        r = self.session.post(url, headers=self.headers, data={"token": captcha_token}, timeout=15)
        r.raise_for_status()
        j = r.json()
        if j.get("iErrCode") != 0:
            raise RuntimeError(f"captcha失败: {j.get('sErrMsg')}")
        return j.get("result")

    def recognize_captcha(self, captcha_base64: str) -> str:
        if not self.ocr:
            raise RuntimeError('缺少依赖 ddddocr：请 pip install ddddocr 或在 requirements.txt 添加')
        img = base64.b64decode(captcha_base64)
        txt = self.ocr.classification(img)
        txt = re.sub(r"[^a-zA-Z0-9]", "", txt)
        if len(txt) > 4:
            txt = txt[:4]
        return txt.upper()

    def load_public_key(self, key_str: str):
        try:
            if "-----BEGIN" in key_str:
                return RSA.import_key(key_str)
            try:
                der = base64.b64decode(key_str)
                return RSA.import_key(der)
            except Exception:
                # maybe hex
                hex_str = re.sub(r"\s+", "", key_str)
                if len(hex_str) % 2 != 0:
                    hex_str = "0" + hex_str
                try:
                    der = bytes.fromhex(hex_str)
                    return RSA.import_key(der)
                except Exception:
                    return RSA.import_key(key_str)
        except Exception as e:
            raise RuntimeError(f"加载公钥失败: {e}")

    def rsa_encrypt_long(self, text: str, public_key_str: str) -> str:
        public_key = self.load_public_key(public_key_str)
        key_size = public_key.n.bit_length() // 8
        max_block = key_size - 11
        out = []
        for i in range(0, len(text), max_block):
            block = text[i:i + max_block]
            cipher = PKCS1_v1_5.new(public_key)
            out.append(cipher.encrypt(block.encode("utf-8")))
        return base64.b64encode(b"".join(out)).decode("utf-8")

    def login(self, account: str, password: str, captcha: str, captcha_token: str):
        url = self._url("/cms-api/login")

        first_pw = self.rsa_encrypt_long(password, self.first_public_key)
        second_pw = self.rsa_encrypt_long(first_pw, captcha_token)
        enc_account = self.rsa_encrypt_long(account, captcha_token)

        data = {
            "account": enc_account,
            "data": second_pw,
            "safeCode": captcha,
            "token": captcha_token,
            "locale": "zh",
        }

        r = self.session.post(url, headers=self.headers, data=data, timeout=20)
        r.raise_for_status()
        return r.json()

    def login_and_get_token(self, account: str, password: str) -> str:
        for attempt in range(1, self.max_attempts + 1):
            try:
                log(self.env, f"INFO  登录尝试 {attempt}/{self.max_attempts}")
                captcha_token = self.get_captcha_token()
                log(self.env, f"INFO  captcha_token 获取成功: {str(captcha_token)[:22]}...")
                img_b64 = self.get_captcha_img_b64(captcha_token)
                captcha_text = self.recognize_captcha(img_b64)
                log(self.env, f"INFO  OCR 识别验证码: {captcha_text}")

                j = self.login(account, password, captcha_text, captcha_token)
                if j.get("iErrCode") != 0:
                    log(self.env, f"WARNING 登录失败 iErrCode={j.get('iErrCode')} msg={j.get('sErrMsg')}")
                    continue

                token = (j.get("result") or "").strip()
                if not token:
                    log(self.env, "ERROR 登录成功但未返回 token")
                    continue

                log_sep(self.env, "LOGIN TOKEN")
                log(self.env, f"SUCCESS 登录成功，token={token}")
                return token

            except Exception as e:
                log(self.env, f"ERROR 登录异常: {e}")

        raise RuntimeError("多次登录尝试失败")


CLIENTS = {env: CMSAutoLogin(env, cfg) for env, cfg in ENVS.items()}


def _cms_headers(env: str, token: str, accept: str = "application/json, text/javascript, */*; q=0.01"):
    cfg = ENVS[env]
    return {
        "accept": accept,
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "token": token,
        "referer": cfg["referer"],
    }


def _cms_url(env: str, path: str):
    return ENVS[env]["api_base"].rstrip("/") + path


def fetch_club_info(env: str, token: str):
    url = _cms_url(env, "/cms-api/club/clubInfo")
    r = requests.post(url, headers=_cms_headers(env, token, accept="*/*"), data={"clubId": str(ENVS[env]["club_id"])}, timeout=15)
    ct = r.headers.get("content-type", "")
    try:
        j = r.json() if "application/json" in ct else {"raw": r.text}
    except Exception:
        j = {"raw": r.text}
    return r.status_code, j


def ensure_club_context(env: str, token: str):
    log_sep(env, "CLUB CONTEXT clubInfo")
    sc, j = fetch_club_info(env, token)
    log(env, f"INFO  clubInfo status={sc} body={j if isinstance(j, dict) else str(j)[:400]}")
    ok = sc == 200 and isinstance(j, dict) and j.get("iErrCode") == 0
    if ok:
        set_state(env, clubctx_ok=True, clubctx_last_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), clubctx_last_err="")
        log(env, "SUCCESS clubInfo 上下文建立成功（iErrCode=0）")
        return True
    set_state(env, clubctx_ok=False, clubctx_last_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), clubctx_last_err=str(j)[:500])
    log(env, f"ERROR clubInfo 上下文失败")
    return False


def refresh_token_once(env: str, source: str = "auto"):
    cfg = ENVS[env]
    account = cfg["account"]
    password = cfg["password"]

    log_sep(env, f"LOGIN FLOW ({source})")
    try:
        token = CLIENTS[env].login_and_get_token(account, password)
        set_state(
            env,
            token=token,
            last_login_ok=True,
            last_login_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            last_login_err="",
            last_login_ts=time.time(),
        )

        # build context
        ok_ctx = ensure_club_context(env, token)
        if not ok_ctx:
            set_state(env, last_login_ok=False, last_login_err="login ok but clubInfo fail")
            return False, "clubInfo fail"

        bump_next_due(env, LOGIN_INTERVAL_MIN)
        return True, "login+context ok"

    except Exception as e:
        set_state(env, last_login_ok=False, last_login_err=str(e), last_login_ts=time.time())
        log_sep(env, "LOGIN FAILED")
        log(env, f"ERROR 登录流程失败: {e}")
        bump_next_due(env, 2)  # short retry window for watchdog
        return False, str(e)


def ensure_auth_and_context(env: str):
    st = get_state(env)
    if st.get("token") and st.get("clubctx_ok"):
        return True, "ok"
    ok, msg = refresh_token_once(env, source="ensure")
    return ok, msg


# =========================
# CMS ops: user lookup / unlock
# =========================

def fetch_user_by_showid(env: str, showid: str, token: str):
    url = _cms_url(env, "/cms-api/user/getSpecifyUserByShowId")
    r = requests.post(
        url,
        headers={
            **_cms_headers(env, token),
            "accept-language": "zh",
        },
        data={"showId": str(showid), "clubId": str(ENVS[env]["club_id"])},
        timeout=15,
    )
    ct = r.headers.get("content-type", "")
    if "application/json" in ct:
        return r.json()
    return {"raw": r.text}


def unlock_club_manager(env: str, showid: str, token: str):
    url = _cms_url(env, "/cms-api/club/unlockClubManager")
    r = requests.post(url, headers=_cms_headers(env, token), data={"showid": str(showid)}, timeout=15)
    ct = r.headers.get("content-type", "")
    try:
        j = r.json() if "application/json" in ct else {"raw": r.text}
    except Exception:
        j = {"raw": r.text}
    return r.status_code, j


# =========================
# Scheduler: per-env 90min + watchdog (double insurance)
# =========================
SCHED = BackgroundScheduler(timezone=timezone.utc) if _HAS_APS else None

WATCHDOG_EVERY_SEC = int(os.getenv("WATCHDOG_EVERY_SEC", "25"))
WATCHDOG_GRACE_SEC = int(os.getenv("WATCHDOG_GRACE_SEC", "180"))  # 3 minutes grace


def _job_login_env(env: str):
    # record scheduled run + move next due forward even if login fails
    bump_next_due(env, LOGIN_INTERVAL_MIN)
    refresh_token_once(env, source="auto")


def _job_watchdog():
    now = time.time()
    for env in ENVS.keys():
        st = get_state(env)
        due = float(st.get("next_due_ts") or 0.0)
        last_ts = float(st.get("last_login_ts") or 0.0)

        # if due passed and no run observed
        if due > 0 and now >= due + WATCHDOG_GRACE_SEC:
            log_sep(env, "WATCHDOG MISSED")
            log(env, "WARNING 定时登录疑似未执行，立即补跑一次")
            refresh_token_once(env, source="watchdog")
            continue

        # if last login too old
        if last_ts > 0 and (now - last_ts) > (LOGIN_INTERVAL_MIN * 60 + WATCHDOG_GRACE_SEC):
            log_sep(env, "WATCHDOG STALE")
            log(env, "WARNING 上次登录过久，立即补跑一次")
            refresh_token_once(env, source="watchdog_stale")


def start_scheduler_once():
    if SCHED is None:
        log('SYS','WARNING 未安装 apscheduler：自动登录定时任务不会运行，请 pip install apscheduler')
        return
    if getattr(SCHED, "running", False):
        return

    # schedule next due for each env
    for env in ENVS.keys():
        bump_next_due(env, LOGIN_INTERVAL_MIN)

    # auto login jobs
    for env in ENVS.keys():
        SCHED.add_job(
            _job_login_env,
            "interval",
            minutes=LOGIN_INTERVAL_MIN,
            id=f"login_{env}_{LOGIN_INTERVAL_MIN}m",
            replace_existing=True,
            max_instances=1,
            kwargs={"env": env},
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=5),
        )

    # watchdog
    SCHED.add_job(
        _job_watchdog,
        "interval",
        seconds=WATCHDOG_EVERY_SEC,
        id="watchdog_all",
        replace_existing=True,
        max_instances=1,
    )

    SCHED.start()


start_scheduler_once()


# =========================
# Health endpoint (front-end keepalive + self-check)
# =========================
@app.get("/api/health")
def api_health():
    # also bump online heartbeat by returning scheduler state
    return jsonify({
        "ok": True,
        "scheduler_running": bool(getattr(SCHED, "running", False)),
        "now": datetime.now().isoformat(),
    })


# =========================
# API endpoints
# =========================
@app.get("/api/envs")
def api_envs():
    return jsonify({
        "ok": True,
        "envs": [{"key": k, "name": v["name"], "referer": v["referer"], "api_base": v["api_base"], "club_id": v["club_id"]} for k, v in ENVS.items()],
        "login_interval_min": LOGIN_INTERVAL_MIN,
    })


@app.get("/api/status_all")
def api_status_all():
    out = {}
    for env in ENVS.keys():
        st = get_state(env)
        out[env] = {
            "env": env,
            "name": ENVS[env]["name"],
            "has_token": bool(st.get("token")),
            "last_login_ok": bool(st.get("last_login_ok")),
            "last_login_at": st.get("last_login_at") or "",
            "last_login_err": st.get("last_login_err") or "",
            "clubctx_ok": bool(st.get("clubctx_ok")),
            "clubctx_last_at": st.get("clubctx_last_at") or "",
            "clubctx_last_err": st.get("clubctx_last_err") or "",
            "next_login_epoch_ms": next_due_epoch_ms(env),
            "cache_count": len(USERCACHE[env]),
        }
    return jsonify({
        "ok": True,
        "server_epoch_ms": int(time.time() * 1000),
        "login_interval_min": LOGIN_INTERVAL_MIN,
        "env_status": out,
    })


@app.get("/api/<env>/logs")
def api_logs_env(env):
    _assert_env(env)
    return jsonify({"ok": True, "env": env, "lines": get_logs(env, 600)})


@app.post("/api/<env>/logs/clear")
def api_logs_clear_env(env):
    _assert_env(env)
    clear_logs(env)
    log(env, "INFO  日志已清空（用户操作）")
    return jsonify({"ok": True})


@app.get("/api/<env>/cache")
def api_cache_env(env):
    _assert_env(env)
    return jsonify({"ok": True, "env": env, "items": list_cached_users(env)})


@app.post("/api/<env>/cache/delete")
def api_cache_delete_env(env):
    _assert_env(env)
    showid = (request.form.get("showid") or "").strip()
    if not showid:
        return jsonify({"ok": False, "msg": "showid required"}), 400
    ok = delete_cached_user(env, showid)
    return jsonify({"ok": ok, "env": env, "showid": showid})


@app.post("/api/<env>/login_now")
def api_login_now_env(env):
    _assert_env(env)
    ok, msg = refresh_token_once(env, source="manual")
    st = get_state(env)
    return jsonify({
        "ok": ok,
        "msg": msg,
        "env": env,
        "last_login_at": st.get("last_login_at"),
        "has_token": bool(st.get("token")),
        "next_login_epoch_ms": next_due_epoch_ms(env),
    })


@app.post("/api/<env>/cms/user_lookup")
def api_user_lookup_env(env):
    _assert_env(env)
    showid = (request.form.get("showid") or "").strip()
    if not showid:
        return jsonify({"ok": False, "msg": "showid required"}), 400

    ok, msg = ensure_auth_and_context(env)
    if not ok:
        return jsonify({"ok": False, "msg": f"auth/context not ready: {msg}"}), 503

    token = get_state(env).get("token")
    try:
        j = fetch_user_by_showid(env, showid, token)
        if not isinstance(j, dict):
            return jsonify({"ok": False, "msg": "bad response", "raw": j}), 502
        if j.get("iErrCode") != 0:
            return jsonify({"ok": False, "msg": f"iErrCode={j.get('iErrCode')}", "raw": j}), 200

        result = j.get("result") or {}
        profile = {
            "showid": str(result.get("sShowID") or showid),
            "uuid": result.get("uuid"),
            "strNick": result.get("strNick") or "",
            "strCover": result.get("strCover") or "",
        }
        cache_user(env, profile)
        log_sep(env, "USER LOOKUP")
        log(env, f"SUCCESS 查询成功 showid={profile['showid']} uuid={profile['uuid']} nick={profile['strNick']}")

        # return cached profile (with cached_at)
        cached = None
        with USERCACHE_LOCK:
            cached = dict(USERCACHE[env].get(profile["showid"]))
        return jsonify({"ok": True, "env": env, "profile": cached})

    except Exception as e:
        log(env, f"ERROR user_lookup 异常: {e}")
        return jsonify({"ok": False, "msg": str(e)}), 502


@app.post("/api/<env>/cms/unlock")
def api_unlock_env(env):
    _assert_env(env)
    showid = (request.form.get("showid") or "").strip()
    if not showid:
        return jsonify({"ok": False, "msg": "showid required"}), 400

    ok, msg = ensure_auth_and_context(env)
    if not ok:
        return jsonify({"ok": False, "msg": f"auth/context not ready: {msg}"}), 503

    token = get_state(env).get("token")

    try:
        sc, body = unlock_club_manager(env, showid, token)
        # success condition: status=200 and body {"iErrCode":0}
        success = (sc == 200 and isinstance(body, dict) and body.get("iErrCode") == 0)

        log_sep(env, "UNLOCK")
        log(env, f"INFO  解封响应 status={sc} body={body}")

        return jsonify({
            "ok": True,
            "env": env,
            "status_code": sc,
            "body": body,
            "unlock_success": bool(success),
        })

    except Exception as e:
        log(env, f"ERROR unlock 异常: {e}")
        return jsonify({"ok": False, "msg": str(e)}), 502




@app.get("/api/<env>/auth/manage_accounts")
def api_manage_accounts(env):
    _ensure_env(env)
    return jsonify({"ok": True, "env": env, **list_manage_accounts(env)})

@app.post("/api/<env>/auth/manage_accounts/save")
def api_manage_accounts_save(env):
    _ensure_env(env)
    account = (request.form.get("account") or "").strip()
    password = (request.form.get("password") or "").strip()
    if not account or not password:
        return jsonify({"ok": False, "error": "account/password required"}), 400
    try:
        upsert_manage_account(env, account, password, set_active=True)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    ok, msg = manage_refresh_token_once(env, source="manual_save")
    return jsonify({"ok": bool(ok), "msg": msg, "active": account})

@app.post("/api/<env>/auth/manage_accounts/select")
def api_manage_accounts_select(env):
    _ensure_env(env)
    account = (request.form.get("account") or "").strip()
    select_manage_account(env, account)
    # do not auto login; proxy will ensure. Provide state anyway.
    st = get_manage_state(env)
    return jsonify({"ok": True, "active": st.get("active_account") or list_manage_accounts(env).get("active")})

@app.post("/api/<env>/auth/manage_accounts/delete")
def api_manage_accounts_delete(env):
    _ensure_env(env)
    account = (request.form.get("account") or "").strip()
    if not account:
        return jsonify({"ok": False, "error": "account required"}), 400
    delete_manage_account(env, account)
    return jsonify({"ok": True, **list_manage_accounts(env)})

@app.post("/api/<env>/cms/manage_login_now")
def api_manage_login_now_env(env):
    _ensure_env(env)
    ok, msg = manage_refresh_token_once(env, source="manual")
    st = get_manage_state(env)
    return jsonify({
        "ok": bool(ok),
        "msg": msg,
        "env": env,
        "active_account": st.get("active_account") or list_manage_accounts(env).get("active") or "",
        "last_login_at": st.get("last_login_at") or "",
        "has_token": bool(st.get("token")),
        "clubctx_ok": bool(st.get("clubctx_ok")),
    })

# Backward-compatible endpoint (old front-end) -> treat as save+login
@app.post("/api/<env>/auth/set_credentials")
def api_set_credentials(env):
    _ensure_env(env)
    account = (request.form.get("account") or "").strip()
    password = (request.form.get("password") or "").strip()
    if not account or not password:
        return jsonify({"ok": False, "error": "account/password required"}), 400
    try:
        upsert_manage_account(env, account, password, set_active=True)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    ok, msg = manage_refresh_token_once(env, source="manual")
    return jsonify({"ok": bool(ok), "msg": msg})



@app.post("/api/<env>/cms/proxy")
def api_cms_proxy(env):
    # Backend proxy for CMS功能管理: uses MANAGE account/token (independent from 解封账号)
    _ensure_env(env)

    path = (request.form.get("path") or "").strip()
    body = request.form.get("body") or ""  # raw x-www-form-urlencoded string
    accept = (request.form.get("accept") or "application/json, text/javascript, */*; q=0.01").strip()

    if not path.startswith("/cms-api/"):
        return jsonify({"ok": False, "error": "path must start with /cms-api/"}), 400

    st = get_manage_state(env)
    token = (st.get("token") or "").strip()

    # ensure manage login
    if not token or not st.get("clubctx_ok"):
        ok, msg = manage_refresh_token_once(env, source="proxy")
        st = get_manage_state(env)
        token = (st.get("token") or "").strip()
        if not ok or not token:
            return jsonify({"ok": False, "error": "manage login required", "msg": msg}), 401

    # final guard: ensure context
    if not get_manage_state(env).get("clubctx_ok"):
        try:
            manage_ensure_club_context(env, token)
        except Exception as e:
            log(env, f"ERR   [manage] ensure_club_context exception: {e}")

    url = _cms_url(env, path)
    headers = _cms_headers(env, token, accept=accept)

    try:
        r = requests.post(url, headers=headers, data=body, timeout=30)
        ctype = (r.headers.get("content-type") or "").lower()
        if "application/json" in ctype:
            try:
                return jsonify({"ok": True, "status_code": r.status_code, "body": r.json()})
            except Exception:
                return jsonify({"ok": True, "status_code": r.status_code, "body": r.text})
        return jsonify({"ok": True, "status_code": r.status_code, "body": r.text})
    except Exception as e:
        log(env, f"ERR   [manage] proxy request failed: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.get("/api/backgrounds")
def api_backgrounds():
    files = list_bg_files()
    return jsonify({"ok": True, "dir": BG_DIR, "items": [bg_url_for(f) for f in files]})


# =========================
# UI (single-page with navbar + env selector)
# =========================
HTML = r"""
<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
  <title>HH@by测试组✅CMS多环境登录解封工具</title>
  <style>
    :root{
      --bg0:#050816; --bg1:#0a102a;
      --card: rgba(255,255,255,.07);
      --border: rgba(185,200,255,.16);
      --text: rgba(234,240,255,.95);
      --muted: rgba(234,240,255,.62);
      --good: rgba(50,255,155,.92);
      --warn: rgba(255,201,71,.92);
      --bad: rgba(255,77,109,.95);
      --blue: rgba(108,168,255,.95);
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --tint0: rgba(7,10,18,.08);
      --tint1: rgba(11,16,32,.28);
    }

    html,body{background:transparent;}
    body{margin:0; padding:18px; min-height:100vh; color:var(--text); font-family: Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;}

    body::before{
      content:''; position:fixed; inset:0; z-index:-3;
      background-image: var(--bg-image, none);
      background-size: cover; background-position:center; background-repeat:no-repeat;
      filter: brightness(1.10) saturate(1.08) contrast(1.02);
      transform: translateZ(0);
    }
    body::after{
      content:''; position:fixed; inset:0; z-index:-2; pointer-events:none;
      background:
        radial-gradient(900px 500px at 20% 15%, rgba(108,168,255,.18), transparent 55%),
        radial-gradient(800px 520px at 85% 20%, rgba(50,255,155,.14), transparent 55%),
        radial-gradient(900px 600px at 40% 95%, rgba(255,77,109,.10), transparent 60%),
        linear-gradient(180deg, rgba(0,0,0,.18), rgba(0,0,0,.35)),
        linear-gradient(160deg, var(--tint0), var(--tint1));
    }

    .wrap{max-width:1180px; margin:0 auto;}
    .nav{display:flex; align-items:center; justify-content:space-between; gap:12px; padding:12px 14px; border-radius:18px; background:rgba(0,0,0,.25); border:1px solid var(--border); backdrop-filter: blur(10px);}
    .brand{display:flex; align-items:center; gap:10px; font-weight:950;}
    .brand .dot{width:10px; height:10px; border-radius:999px; background: var(--good); box-shadow:0 0 0 6px rgba(50,255,155,.14);} 
    .nav-right{display:flex; align-items:center; gap:10px; flex-wrap:wrap; justify-content:flex-end;}
    .chip{font-family:var(--mono); font-size:12px; padding:8px 10px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.22);} 
    .chip b{font-weight:950;}
    .chip.good{border-color: rgba(50,255,155,.35);} 
    .chip.bad{border-color: rgba(255,77,109,.40);} 

    .grid{display:grid; grid-template-columns: 1.2fr .8fr; gap:14px; margin-top:14px;}
    @media (max-width:920px){.grid{grid-template-columns:1fr;}}

    .card{border:1px solid var(--border); background:var(--card); border-radius:18px; padding:14px; box-shadow: 0 20px 60px rgba(0,0,0,.35); backdrop-filter: blur(12px);} 
    .section-title{font-weight:950; letter-spacing:.2px; margin:0 0 10px 0;}
    .muted{color:var(--muted);}

    .row{display:flex; gap:10px; align-items:center; flex-wrap:wrap;}
    .label{
      color:#ff4d6d;
      display:inline-flex; align-items:center;
      padding:6px 10px; border-radius:999px;
      background: rgba(255,77,109,.12);
      border: 1px solid rgba(255,77,109,.28);
      box-shadow: 0 0 0 5px rgba(255,77,109,.08);
      font-weight:900;
    }
    select,input:not([type=checkbox]){border-radius:12px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.22); color:var(--text); padding:10px 12px; outline:none;}
    input:not([type=checkbox]){min-width: 220px;}

    input[type=checkbox]{min-width:unset; padding:0; background:transparent; border:1px solid rgba(185,200,255,.35); border-radius:4px; width:18px; height:18px; box-sizing:border-box;}


    .btn{border:none; border-radius:12px; padding:10px 12px; font-weight:900; cursor:pointer;}
    .btn-good{background:rgba(50,255,155,.20); color:rgba(220,255,240,.98); border:1px solid rgba(50,255,155,.35);} 
    .btn-brightgreen{background:rgba(50,255,155,.88); color:#062114; border:1px solid rgba(50,255,155,.98); box-shadow:0 10px 28px rgba(50,255,155,.24);} 
    .btn-brightgreen:hover{filter:brightness(1.04);} 
    .btn-warn{background:rgba(255,201,71,.18); color:rgba(255,242,210,.98); border:1px solid rgba(255,201,71,.35);} 
    .btn-ghost{background:rgba(255,255,255,.06); color:var(--text); border:1px solid rgba(255,255,255,.14);} 

    .player-card{position:relative; display:flex; gap:12px; align-items:center; padding:12px; border-radius:16px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.18);} 
    .avatar{width:44px; height:44px; border-radius:14px; overflow:hidden; border:1px solid rgba(255,255,255,.16); flex:0 0 auto; background:rgba(255,255,255,.06);} 
    .avatar img{width:100%; height:100%; object-fit:cover; display:block;}
    .p-meta{flex:1; min-width:0;}
    .p-nick{font-weight:950; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
    .p-sub{display:flex; gap:8px; flex-wrap:wrap; margin-top:6px;}
    .pill{font-family:var(--mono); font-size:12px; padding:6px 8px; border-radius:999px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.18);} 
    .p-actions{display:flex; gap:8px; align-items:flex-end; flex-direction:column;}

    .del-x{position:absolute; top:8px; left:8px; width:26px; height:26px; border-radius:10px; border:1px solid rgba(255,255,255,.14);
      background:rgba(255,77,109,.18); color:rgba(255,255,255,.92); font-weight:950; cursor:pointer;
      display:flex; align-items:center; justify-content:center; line-height:1; z-index:20;}

    .note-box{margin-top:8px; display:flex; flex-direction:column; gap:6px;}
    .note-label{font-family:var(--mono); font-size:12px; color:rgba(234,240,255,.70);} 
    .note-input{width: 180px; padding:9px 10px; border-radius:12px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.22); color:var(--text); outline:none; font-family:var(--mono); font-size:14px;} 
    .note-input.saved{color:rgba(255,77,109,.95); border-color:rgba(255,77,109,.45); background:rgba(255,77,109,.10); box-shadow:0 0 0 5px rgba(255,77,109,.10); font-weight:950; letter-spacing:.2px;} 

    #cacheListWrap{max-height: 586px; overflow-y:auto; padding-right:4px;}

    pre{margin:0; font-family:var(--mono); font-size:12px; color:rgba(234,240,255,.90); white-space:pre-wrap; word-break:break-word; line-height:1.35;}

    #toastHost{position:fixed; left:50%; top:42%; transform:translate(-50%,-50%); z-index:9999; pointer-events:none;}
    .toast{pointer-events:none; min-width:260px; max-width:540px; border-radius:16px; padding:12px 14px; border:1px solid rgba(255,255,255,.16); background:rgba(0,0,0,.42); backdrop-filter: blur(10px);
      box-shadow:0 30px 80px rgba(0,0,0,.45);}
    .toast.good{border-color:rgba(50,255,155,.35);} .toast.bad{border-color:rgba(255,77,109,.45);} 
    .toast .t{font-weight:950; margin-bottom:4px;}
    .toast .m{color:rgba(234,240,255,.88); font-family:var(--mono); font-size:12px;}

    @media (max-width:520px){
      body{padding:12px;}
      .nav{flex-direction:column; align-items:flex-start;}
      .nav-right{justify-content:flex-start;}
      input{min-width: 0; width:100%;}
      #cacheListWrap{max-height: 320px;}
      .p-actions{align-items:stretch; width:100%;}
      .note-input{width: 100%;}
    }
  
    /* top tabs */
    .tabbtn{
      padding:10px 14px;
      border-radius:14px;
      border:1px solid rgba(185,200,255,.16);
      background: rgba(255,255,255,.06);
      color: rgba(234,240,255,.88);
      cursor:pointer;
      font-weight:900;
      letter-spacing:.2px;
      transition: transform .08s ease, background .18s ease, border-color .18s ease, box-shadow .18s ease;
    }
    .tabbtn:hover{ transform: translateY(-1px); background: rgba(255,255,255,.08); }
    .tabbtn.active{ border:2px solid rgba(108,168,255,.92); box-shadow: 0 12px 30px rgba(0,0,0,.25), 0 0 0 2px rgba(108,168,255,.18) inset; background: rgba(108,168,255,.10); }

    /* env nav buttons */
    .envbtn{
      padding:8px 12px;
      border-radius:14px;
      border:1px solid rgba(185,200,255,.16);
      background: rgba(255,255,255,.05);
      color: rgba(234,240,255,.85);
      cursor:pointer;
      font-weight:950;
      letter-spacing:.2px;
      transition: transform .08s ease, background .18s ease, border-color .18s ease;
      user-select:none;
    }
    .envbtn:hover{ transform: translateY(-1px); }
    .envbtn.active{ box-shadow: 0 12px 30px rgba(0,0,0,.25); }
    .envbtn.prod.active{ border-color: rgba(108,168,255,.60); background: rgba(108,168,255,.18); }
    .envbtn.uat.active{ border-color: rgba(255,201,71,.65); background: rgba(255,201,71,.18); }
    .envbtn.test.active{ border-color: rgba(50,255,155,.55); background: rgba(50,255,155,.16); }

  
  .mini-title{margin-top:10px;font-size:13px;font-weight:900;color:rgba(234,240,255,.92);letter-spacing:.3px}
  .tablewrap{overflow:auto;border:1px solid rgba(185,200,255,.14);border-radius:12px;background:rgba(10,14,22,.35)}
  table.tbl{border-collapse:collapse;width:100%;min-width:520px}
  table.tbl th, table.tbl td{border:1px solid rgba(185,200,255,.14);padding:8px;font-size:13px}
  table.tbl th{background:rgba(16,22,38,.45);color:rgba(234,240,255,.9);font-weight:900}
  table.tbl td{color:rgba(234,240,255,.86)}
  .kv-muted{opacity:.75}

  /* tighter checkbox column + prevent overlap */
  .memberCheck2, .applyCheck2, #selectAllMembers2{
    width:18px; height:18px;
    accent-color: #32ff9b;
    cursor:pointer;
  }
  .chkCol2{ width:44px; min-width:44px; max-width:44px; text-align:center; overflow:hidden; }
  .chkCol2 input[type=checkbox]{ margin:0 auto; display:block; }

    .hint{color:var(--muted); font-size:12px; font-family:var(--mono); line-height:1.3;}
    .hr{height:1px; background:rgba(185,200,255,.14); margin:12px 0; border-radius:999px;}
    /* logbox: used by manage logs + list containers. Increase height as requested. */
    .logbox{margin:0; padding:12px; border-radius:14px; border:1px solid rgba(255,255,255,.14); background:rgba(0,0,0,.18); max-height:1120px; overflow:auto; font-family:var(--mono); font-size:12px; color:rgba(234,240,255,.90); white-space:pre-wrap; word-break:break-word; line-height:1.35;}
    /* listbox: for tables/lists, avoid pre-wrap affecting layout */
    .listbox{margin:0; padding:10px; border-radius:14px; border:1px solid rgba(185,200,255,.14); background:rgba(10,14,22,.28); overflow:auto; color:rgba(234,240,255,.90); white-space:normal; font-family:var(--sans);}
    .listbox table, .listbox th, .listbox td{white-space:nowrap;}
    .listbox .tablewrap{white-space:normal;}
    

    /* club selector: user wants black text */
    #clubSelect2, #clubSelect2 option{ color:#000 !important; background:#fff !important; }

    /* logs pane: add more visible height */
    #logs{min-height:560px; max-height:1120px; overflow:auto;}


  .center840{max-width:840px;width:100%;margin:0 auto;}
  
  .selectAllLabel2{
  display:inline-flex;
  align-items:center;
  gap:8px;
  font-size:15px;
  font-weight:950;
  color:rgba(255,201,71,.96);  /* 亮眼一点 */
  letter-spacing:.2px;
}

.selectAllLabel2 input[type="checkbox"]{
  width:18px;
  height:18px;
  accent-color: rgba(255,201,71,.96);
}

</style>
</head>
<body>
<div class="wrap">
  <div class="nav">
    <div class="brand"><span class="dot"></span>CMS 多环境登录解封工具✅HH@by测试组</div>
    <div class="nav-right">
      <span class="chip" id="nowClock">--</span>
      <span class="chip" id="serverChip">server: --</span>
    </div>
  </div>

  <div class="card" style="margin-top:14px;">
    <div class="row" id="envChips" style="gap:8px;"></div>
  </div>


  <div class="card" style="margin-top:12px;">
    <div class="row" style="gap:10px; flex-wrap:wrap;">
      <button class="tabbtn active" id="tab_unlock" onclick="switchTop('unlock')">CMS解封功能</button>
      <button class="tabbtn" id="tab_manage" onclick="switchTop('manage')">CMS功能管理</button>
    </div>
  </div>

  <div id="pageUnlock">
  <div class="grid">
    <div class="card">
      <div class="section-title">CMS 解封 / 查询（按环境隔离）</div>
      <div class="row" style="margin-bottom:10px;">
        <span class="label">操作环境</span>
        <div class="row" id="envNav" style="gap:8px; flex-wrap:wrap;"></div>
        <button class="btn btn-ghost" onclick="loginNow()">立即登录</button>
        <button class="btn btn-ghost" onclick="clearLogs()">清空日志</button>
      </div>

      <div class="row" style="margin-bottom:10px;">
        <span class="label">输入 showid</span>
        <input id="showidSearch" value="10198130419" placeholder="例如 10518356534" />
        <button class="btn btn-warn" onclick="lookupUser()">查询资料</button>
        <button class="btn btn-good" onclick="unlockDirect()">一键解封CMS</button>
      </div>

      <div class="section-title" style="margin-top:14px;">查询后自动缓存列表（点击可选择/一键解封CMS）</div>
      <div id="cacheListWrap"><div id="cacheList"></div></div>

    </div>

    <div class="card">
      <div class="section-title">执行日志（当前环境）</div>
      <div class="row" style="margin-bottom:8px;"><span class="muted" id="envInfo">--</span></div>
      <div class="card" style="padding:12px; background:rgba(0,0,0,.18);">
        <pre id="logs">--</pre>
      </div>
    </div>
  </div>
</div>

<div id="toastHost"></div>


  </div><!-- /pageUnlock -->

  <div id="pageManage" style="display:none;">
    <div class="grid">
      <div class="card">
        <div class="section-title">CMS 功能管理（按环境隔离，逻辑对齐油猴脚本）</div>

        <div class="row" style="gap:10px; flex-wrap:wrap; align-items:center; margin-top:8px;">
          <span class="label">操作环境</span>
          <div class="row" id="envNavManage" style="gap:8px; flex-wrap:wrap;"></div>
           <button class="btn btn-ghost" onclick="loginNowManage()">立即登录</button>
           <button class="btn btn-ghost" onclick="clearLogsManage()">清空日志</button>
        </div>
<!-- 第1行：账号选择 -->
<div class="row" style="gap:10px; flex-wrap:wrap; margin-top:12px; align-items:center;">
  <span class="label" style="min-width:88px;">账号</span>

  <select id="manageAccountSelect" style="max-width:360px; min-width:240px;" onchange="onManageAccountSelectChange()">
    <option value="">（未选择）</option>
  </select>

  <span class="hint" id="manageAccountHint" style="font-family:var(--mono);">当前：--</span>

  <button class="btn btn-ghost" onclick="deleteSelectedManageAccount()">删除所选账号</button>
</div>

<!-- 第2行A：新增/更新账号（账号） -->
<div class="row" style="gap:10px; flex-wrap:wrap; margin-top:8px; align-items:center;">
  <span class="label" style="min-width:88px;">新增/更新账号</span>
  <input id="cfgAccount" placeholder="输入账号（将保存到当前环境）" style="max-width:260px;" />
  <button class="btn btn-good" onclick="saveCreds()">保存并登录</button>
</div>

<!-- 第2行B：密码 -->
<div class="row" style="gap:10px; flex-wrap:wrap; margin-top:8px; align-items:center;">
  <span class="label" style="min-width:88px;">密码</span>
  <input id="cfgPassword" placeholder="输入密码（仅后端保存）" type="password" style="max-width:260px;" />
  <span class="hint">（同一环境可保存多个账号；页面只展示账号，不展示密码；切换环境自动切换账号列表）</span>
</div>



        <div class="hr"></div>

        <div class="center840">

        <div class="row" style="gap:10px; flex-wrap:wrap; align-items:center;">
          <button class="btn btn-brightgreen" id="loadClubsBtn2" onclick="cmsLoadClubs()">加载俱乐部列表</button>
          <select id="clubSelect2" style="min-width: 420px; max-width: 100%;"></select>
          <button class="btn btn-ghost" onclick="copyClubId()">复制-clubId、双击复制showid</button>
        </div>

        <!-- 俱乐部成员加载：必须在俱乐部列表下面 -->
        <div class="row" style="margin-top:10px;gap:10px;flex-wrap:wrap;align-items:center;">
          <button class="btn btn-brightgreen" onclick="cmsLoadMembers()">加载俱乐部成员</button>
          <div class="hint">提示：下面所有按钮均对“勾选的俱乐部成员”生效（加币/贵宾/解封/分配代理等）</div>
        </div>

        <div class="row" style="margin-top:10px;gap:10px;flex-wrap:wrap;align-items:center;">
          <button class="btn btn-warn" onclick="cmsSetManager()">设为管理</button>
          <button class="btn btn-warn" onclick="cmsCancelManager()">取消管理</button>
          <button class="btn btn-blue" onclick="cmsSetAllPerm()">设置全部权限</button>
          <button class="btn btn-blue" onclick="cmsSetVIP()">设置贵宾</button>
          <button class="btn btn-blue" onclick="cmsCancelVIP()">取消贵宾</button>
        </div>

        <div class="row" style="margin-top:10px;gap:10px;flex-wrap:wrap;align-items:center;">
          <span class="label">联盟币</span>
          <input id="creditAmount2" value="1" style="max-width:120px;" />
          <button class="btn btn-good" onclick="cmsAddCredit()">勾选成员加币</button>
          <button class="btn btn-bad" onclick="cmsKickMembers()">踢出勾选成员</button>
        </div>

        <div class="row" style="margin-top:10px;gap:10px;flex-wrap:wrap;align-items:center;">
          <span class="label" style="color:#ff4d6d;">解封管理员 showid</span>
          <input id="unlockManagerShowIdInput2" placeholder="可留空，勾选管理也可" style="max-width:220px;" />
          <button class="btn btn-good" onclick="cmsUnlockManagers()">解封管理员</button>
        </div>

        <div class="row" style="margin-top:10px;gap:8px;flex-wrap:wrap;align-items:center;justify-content:flex-start;">
          <span class="hint" style="color:rgba(255,201,71,.92);font-weight:900;">钻石基金批量操作（对勾选成员生效）</span>
          <label style="font-size:14px;color:rgba(234,240,255,.92);font-weight:900;">转账:</label>
          <input id="diamondTransferAmount" type="number" value="233" style="width:78px;padding:6px;border:1px solid rgba(185,200,255,.25);border-radius:10px;background:rgba(10,14,22,.35);color:rgba(234,240,255,.92);">
          <button id="diamondTransferBtn" class="btn btn-good" onclick="diamondTransfer()">批量转账</button>

          <label style="font-size:14px;color:rgba(234,240,255,.92);font-weight:900;">回收:</label>
          <input id="diamondRecallAmount" type="number" value="69" style="width:78px;padding:6px;border:1px solid rgba(185,200,255,.25);border-radius:10px;background:rgba(10,14,22,.35);color:rgba(234,240,255,.92);">
          <button id="diamondRecallBtn" class="btn btn-danger" onclick="diamondRecall()">批量回收</button>
        </div>

        <div class="row" style="margin-top:10px;gap:10px;flex-wrap:wrap;align-items:center;">
          <button id="loadVIPListBtn" class="btn btn-blue" style="background:#16a085;border-color:rgba(22,160,133,.55);" onclick="loadVipList()">获取贵宾列表</button>
          <button id="assignAgentBtn" class="btn btn-blue" style="background:#8e44ad;border-color:rgba(142,68,173,.55);" onclick="openAssignAgent()">分配贵宾代理</button>
        </div>

        <div id="vipBox2" class="listbox" style="margin-top:10px;max-height:520px;overflow:auto;display:none;"></div>

        <div id="agentAssignBox2" style="display:none;margin-top:10px;border:1px solid rgba(185,200,255,.14);border-radius:14px;background:rgba(10,14,22,.28);padding:10px;">
          <div class="row" style="gap:8px;flex-wrap:wrap;align-items:center;">
            <span class="hint" style="color:rgba(234,240,255,.92);font-weight:900;">成员 → 贵宾代理映射（逻辑对齐 cms-2.1.8.js）</span>
            <button class="btn btn-ghost" onclick="loadMemberAndAgentLists()">加载成员+贵宾列表</button>
            <label class="hint" style="display:flex;align-items:center;gap:6px;">
              <input type="checkbox" id="selectAllMembersForAgent" /> 全选成员
            </label>
            <span class="hint" id="agentHint2" style="margin-left:auto;"></span>
          </div>

          <div class="row" style="gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px;">
            <span class="label">选择贵宾代理</span>
            <select id="agentForMembersList" class="input" style="min-width:260px;"></select>
            <img id="agentAvatar2" src="" alt="avatar" style="width:28px;height:28px;border-radius:50%;border:1px solid rgba(185,200,255,.25);object-fit:cover;display:none;">
            <button id="assignMembersToAgentBtn" class="btn btn-good">分配选中成员</button>
            <button id="setNoAgentForMembersBtn" class="btn btn-danger">设置无贵宾</button>
          </div>

          <div style="overflow:auto;max-height:360px;margin-top:10px;border:1px solid rgba(185,200,255,.14);border-radius:12px;background:rgba(0,0,0,.12);">
            <table style="width:100%;border-collapse:collapse;min-width:740px;">
              <thead>
                <tr style="background:rgba(108,168,255,.10);">
                  <th class="chkCol2" style="padding:6px;border:1px solid rgba(185,200,255,.14);text-align:left;"></th>
                  <th style="padding:6px;border:1px solid rgba(185,200,255,.14);text-align:left;">昵称</th>
                  <th style="padding:6px;border:1px solid rgba(185,200,255,.14);text-align:left;">ShowID</th>
                  <th style="padding:6px;border:1px solid rgba(185,200,255,.14);text-align:left;">当前贵宾</th>
                </tr>
              </thead>
              <tbody id="membersForAgentListBodyContent2"></tbody>
            </table>
          </div>
        </div>

</div><div class="row" style="gap:10px; flex-wrap:wrap; margin-top:12px; align-items:center;">
          <div id="memberClubIdDisplay2" class="hint">当前俱乐部ID: --</div>
<label class="hint selectAllLabel2">
  <input type="checkbox" id="selectAllMembers2" /> 全选成员
</label>
        </div>
        <div id="memberSearchBoxWrapper2" style="margin-top:8px;"></div>
<!-- [START] 成员表格滚动容器 + 固定表头 + 绿色表头 -->
<div style="overflow:auto; max-height:520px; margin-top:10px; border:1px solid rgba(185,200,255,.14); border-radius:14px;">
  <table style="width:100%; border-collapse:collapse; min-width:1040px;">
    <thead>
      <tr>
        <th class="chkCol2" style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:6px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">单选</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">账号状态</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">角色</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">UUID</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">ShowID</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">头像</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">昵称</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">联盟币</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">钻石</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">星币</th>
        <th style="position:sticky; top:0; z-index:3; background:linear-gradient(180deg, rgba(50,255,155,.95) 0%, rgba(18,190,105,.92) 100%); color:#fff; padding:8px; border:1px solid rgba(50,255,155,.55); box-shadow:0 1px 0 rgba(255,255,255,.22) inset, 0 -1px 0 rgba(0,0,0,.25) inset;">金币</th>
      </tr>
    </thead>
    <tbody id="memberList2"></tbody>
  </table>
</div>
<!-- [END] 成员表格滚动容器 + 固定表头 + 绿色表头 -->


        <div class="hr"></div>

        <div class="row" style="gap:10px; flex-wrap:wrap; align-items:center;">
          <button class="btn btn-brightgreen" onclick="cmsLoadApplications()">加载入会申请</button>
          <button class="btn btn-good" onclick="cmsAcceptApply(1)">勾选同意（免审核）</button>
          <button class="btn btn-warn" onclick="cmsAcceptApply(0)">勾选同意（非免审）</button>
          <div class="hint">（入会申请列表按油猴脚本逻辑拉取并展示）</div>
        </div>

        <div style="overflow:auto; max-height:340px; margin-top:10px; border:1px solid rgba(185,200,255,.14); border-radius:14px;">
          <table style="width:100%; border-collapse:collapse; min-width:820px;">
            <thead>
              <tr style="background:rgba(255,201,71,.10);">
                <th class="chkCol2" style="padding:6px; border:1px solid rgba(185,200,255,.14);">选</th>
                <th style="padding:8px; border:1px solid rgba(185,200,255,.14);">ShowID</th>
                <th style="padding:8px; border:1px solid rgba(185,200,255,.14);">UUID</th>
                <th style="padding:8px; border:1px solid rgba(185,200,255,.14);">昵称</th>
                <th style="padding:8px; border:1px solid rgba(185,200,255,.14);">时间</th>
              </tr>
            </thead>
            <tbody id="applyList2"></tbody>
          </table>
        </div>

        <div class="hr"></div>

        
<div class="section-title" style="margin-top:0;">联盟信用信息（基础/成员/俱乐部）</div>
        <div class="row" style="gap:10px; flex-wrap:wrap; align-items:center;">
          <button class="btn btn-good" onclick="leagueLoadAll()">一键加载联盟信息</button>
          <button class="btn btn-ghost" onclick="leagueLoadBase()">加载联盟基础信息</button>
          <button class="btn btn-ghost" onclick="leagueLoadMembers()">加载联盟成员信用</button>
          <span class="hint">（会先读取当前俱乐部的联盟ID，再请求联盟接口）</span>
        </div>

        <div id="hostLeagueInfo2" style="margin-top:10px; padding:10px; border:1px solid rgba(185,200,255,.14); border-radius:14px; background:rgba(10,14,22,.28);"></div>

        <div id="leagueBasePills2" class="row" style="gap:8px; flex-wrap:wrap; margin-top:10px;"></div>

        <div class="mini-title">联盟基础字段（完整）</div>
        <div class="tablewrap">
          <table class="tbl">
            <thead><tr><th style="width:180px;">字段</th><th>值</th></tr></thead>
            <tbody id="leagueBaseTbody2"></tbody>
          </table>
        </div>

        <div class="mini-title" style="margin-top:12px;">联盟成员信用列表</div>
        <div class="tablewrap" style="max-height:260px;">
          <table class="tbl" style="min-width:860px;">
            <thead>
              <tr>
                <th style="width:44px; text-align:center;">选</th>
                <th style="width:120px;">类型</th>
                <th>俱乐部名</th>
                <th style="width:120px; text-align:center;">俱乐部ID</th>
                <th style="width:130px; text-align:center;">余额</th>
                <th style="width:90px; text-align:center;">状态</th>
              </tr>
            </thead>
            <tbody id="leagueMembersTbody2"></tbody>
          </table>
        </div>

        <pre id="leagueBox2" class="logbox" style="max-height:160px; overflow:auto; margin-top:10px; display:none;"></pre>

      </div>

      <div class="card">
        <div class="section-title">执行日志（当前环境）</div>
        <div id="envInfo2" class="hint" style="margin-top:-4px;"></div>
        <pre id="logs2" class="logbox"></pre>
      </div>
    </div>
  </div><!-- /pageManage -->
<script>
  let ENV_LIST = [];
  let CURRENT_ENV = 'prod';
  let STATUS_ALL = {};

  function pad2(n){ return String(n).padStart(2,'0'); }
  function fmtYMDHMS(ms){ const d=new Date(ms); return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`; }
  function fmtHMS(sec){ const h=Math.floor(sec/3600), m=Math.floor((sec%3600)/60), s=sec%60; return `${pad2(h)}:${pad2(m)}:${pad2(s)}`; }

  function escapeHtml(s){
    return String(s??'')
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;')
      .replace(/'/g,'&#39;');
  }

  function showToast({type='good', title='提示', msg='', duration=1800}={}){
    const host=document.getElementById('toastHost');
    host.innerHTML='';
    const el=document.createElement('div');
    el.className='toast ' + (type==='error' ? 'bad' : 'good');
    el.innerHTML=`<div class="t">${escapeHtml(title)}</div><div class="m">${escapeHtml(msg)}</div>`;
    host.appendChild(el);
    setTimeout(()=>{ if(host.contains(el)) host.removeChild(el); }, duration);
  }

  function setBgRandom(urls){
    if(!urls || !urls.length) return;
    // avoid same as last
    const last = sessionStorage.getItem('last_bg') || '';
    let u = urls[Math.floor(Math.random()*urls.length)];
    if(urls.length>1){
      let tries=0;
      while(u===last && tries<6){ u=urls[Math.floor(Math.random()*urls.length)]; tries++; }
    }
    sessionStorage.setItem('last_bg', u);
    document.documentElement.style.setProperty('--bg-image', `url("${u}")`);
  }

  async function initBackground(){
    try{
      const r=await fetch('/api/backgrounds', {cache:'no-store'});
      const j=await r.json();
      if(j.ok) setBgRandom(j.items);
    }catch(_e){}
  }

  function tickClock(){
    const d=new Date();
    document.getElementById('nowClock').textContent = `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
    // keep countdown chips smooth (every second)
    try{ renderEnvChips(); }catch(_e){}
  }


  function startClock(){
    // drift-correct: align to next second boundary
    let lastSec = -1;
    const loop = ()=>{
      const d = new Date();
      const sec = d.getSeconds();
      if(sec !== lastSec){
        lastSec = sec;
        tickClock();
      }
      const now = Date.now();
      const delay = 1000 - (now % 1000) + 6; // guard
      setTimeout(loop, delay);
    };
    loop();
    // some browsers throttle timers; refresh immediately on focus/visibility
    document.addEventListener('visibilitychange', ()=>{ if(!document.hidden) tickClock(); });
    window.addEventListener('focus', ()=>tickClock());
  }


  function renderEnvChips(){
    const wrap=document.getElementById('envChips');
    wrap.innerHTML='';
    const now = Date.now();
    for(const e of ENV_LIST){
      const st = STATUS_ALL[e.key] || {};
      const nextMs = st.next_login_epoch_ms || 0;
      const remain = nextMs ? Math.max(0, Math.floor((nextMs-now)/1000)) : 0;
      const ok = st.last_login_ok;
      const cls = ok ? 'good' : 'bad';
      const label = `${e.name}`;
      const txt = nextMs ? `next: ${fmtYMDHMS(nextMs)} (in ${fmtHMS(remain)})` : 'next: --';
      const el = document.createElement('span');
      el.className = 'chip ' + cls;
      el.innerHTML = `<b>${escapeHtml(label)}</b> ${escapeHtml(txt)}`;
      wrap.appendChild(el);
    }
  }

  
  function renderEnvNav(targetId){
    const wrap = document.getElementById(targetId);
    if(!wrap) return;
    wrap.innerHTML = '';
    for(const e of ENV_LIST){
      const b = document.createElement('button');
      b.className = `envbtn ${e.key}` + (e.key===CURRENT_ENV ? ' active' : '');
      b.textContent = (e.name || e.key).toUpperCase();
      b.onclick = async ()=>{
        CURRENT_ENV = e.key;
        try{ localStorage.setItem('cms_env', CURRENT_ENV); }catch(_e){}
        renderEnvNav('envNav');
        renderEnvNav('envNavManage');

        // reset manage-page club & member UI to avoid cross-env confusion
        try{
          const cs2 = document.getElementById('clubSelect2');
          if(cs2) cs2.innerHTML = '';
          const tb2 = document.getElementById('leagueMembersTbody2');
          if(tb2) tb2.innerHTML = '';
          const vipBox = document.getElementById('vipBox2');
          if(vipBox) vipBox.innerHTML = '';
          const mapBody = document.getElementById('membersForAgentListBodyContent2');
          if(mapBody) mapBody.innerHTML = '';
          const sec = document.getElementById('memberAgentSection');
          if(sec) sec.style.display = 'none';
          const memClub = document.getElementById('memberClubIdDisplay2');
          if(memClub) memClub.textContent = '--';
        }catch(_e){}

        refreshLogs();
        refreshLogsManage();
        refreshCache();
        // refresh status first, then update badges
        try{ await refreshStatusAll(); }catch(_e){}
        updateEnvBadges();
        manageAccountsLoad(true);

        // if this env already has a token (or becomes available), auto-load clubs to keep data in sync
        setTimeout(()=>{
          try{
            const st = STATUS_ALL[CURRENT_ENV] || {};
            if(st.has_token) cmsLoadClubs(true);
          }catch(_e){}
        }, 160);
      };
      wrap.appendChild(b);
    }
  }

  async function loadEnvs(){
    const r = await fetch('/api/envs', {cache:'no-store'});
    const j = await r.json();
    ENV_LIST = j.envs || [];
    // remember selection
    try{ CURRENT_ENV = localStorage.getItem('cms_env') || 'prod'; }catch(_e){ CURRENT_ENV='prod'; }
    if(!ENV_LIST.some(x=>x.key===CURRENT_ENV)) CURRENT_ENV = (ENV_LIST[0]?.key || 'prod');

    renderEnvNav('envNav');
    renderEnvNav('envNavManage');
    updateEnvBadges();
      manageAccountsLoad(true);
      refreshLogsManage();
  }

  function updateEnvBadges(){
    const st = STATUS_ALL[CURRENT_ENV] || {};
    const info = `${st.name||CURRENT_ENV} | token=${st.has_token?'yes':'no'} | ctx=${st.clubctx_ok?'ok':'no'} | cache=${st.cache_count||0}`;
    const el1=document.getElementById('envInfo'); if(el1) el1.textContent=info;
    const el2=document.getElementById('envInfo2'); if(el2) el2.innerHTML = `<span class="pill" style="font-weight:900;">ENV:</span> <span class="pill" style="font-weight:900;color:${envColor(CURRENT_ENV)}">${(st.name||CURRENT_ENV)}</span>`;
  }

  function envColor(env){
    if(env==='prod') return 'rgba(108,168,255,.95)';
    if(env==='uat')  return 'rgba(255,201,71,.92)';
    if(env==='test') return 'rgba(50,255,155,.92)';
    return 'rgba(234,240,255,.9)';
  }

async function refreshStatusAll(){
    const r = await fetch('/api/status_all', {cache:'no-store'});
    const j = await r.json();
    if(!j.ok) return;
    STATUS_ALL = j.env_status || {};
    document.getElementById('serverChip').textContent = `server: ${fmtYMDHMS(j.server_epoch_ms)}`;
    renderEnvChips();
    const st = STATUS_ALL[CURRENT_ENV] || {};
    document.getElementById('envInfo').textContent = `${st.name||CURRENT_ENV} | token=${st.has_token?'yes':'no'} | ctx=${st.clubctx_ok?'ok':'no'} | cache=${st.cache_count||0}`;
  }

  async function refreshLogs(){
    try{
      const r = await fetch(`/api/${CURRENT_ENV}/logs`, {cache:'no-store'});
      const j = await r.json();
      if(!j.ok) return;
      const txt=(j.lines||[]).join('\n');
      const a=document.getElementById('logs'); if(a) a.textContent=txt;
      const b=document.getElementById('logs2'); if(b) b.textContent=txt;
    }catch(_e){}
  }

  function getNote(showid){
    try{ return localStorage.getItem('note_' + CURRENT_ENV + '_' + showid) || ''; }catch(e){ return ''; }
  }
  let _noteTimer = {};
  function saveNote(showid, val){
    try{ localStorage.setItem('note_' + CURRENT_ENV + '_' + showid, val || ''); }catch(e){}
    const inp = document.getElementById('note-' + showid);
    if(inp){
      const has = (val||'').trim().length>0;
      inp.classList.toggle('saved', has);
    }
    const key = CURRENT_ENV + '_' + showid;
    const tip = document.getElementById('noteSaved-' + showid);
    if(tip){
      tip.style.display='block';
      clearTimeout(_noteTimer[key]);
      _noteTimer[key] = setTimeout(()=>{ tip.style.display='none'; }, 900);
    }
  }

  async function copyToClipboard(text){
    try{ await navigator.clipboard.writeText(text); return true; }catch(_){
      const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0';
      document.body.appendChild(ta); ta.select();
      try{ document.execCommand('copy'); document.body.removeChild(ta); return true; }catch(e){ document.body.removeChild(ta); return false; }
    }
  }
  async function copyShowid(showid){
    const ok = await copyToClipboard(String(showid));
    if(ok) showToast({type:'success', title:'已复制', msg:`showid=${showid}`, duration:1200});
    else showToast({type:'error', title:'复制失败', msg:'浏览器阻止复制', duration:2200});
  }

  function renderPlayerCard(p){
    const showid = String(p.showid||'');
    const uuid = p.uuid ?? '';
    const nick = p.strNick || '';
    const cover = p.strCover || '';
    const cachedAt = p.cached_at ? `<span class="pill">cached: ${escapeHtml(p.cached_at)}</span>` : '';
    const note = getNote(showid);
    const noteCls = note ? 'saved' : '';

    return `
      <div class="player-card">
        ${p.cached_at ? `<button class="del-x" title="删除该缓存" onclick="deleteCached('${showid}', event)">×</button>` : ``}
        <div class="avatar">${cover ? `<img src="${escapeHtml(cover)}"/>` : ''}</div>
        <div class="p-meta">
          <div class="p-nick">${escapeHtml(nick)}</div>
          <div class="p-sub">
            <span class="pill">
              <span style="color:rgba(108,168,255,.95); font-weight:900;">showid:</span>
              <span ondblclick="copyShowid('${showid}')" style="font-weight:950; font-size:14px; color:rgba(234,240,255,.98); cursor:copy; text-decoration:underline; text-decoration-color: rgba(108,168,255,.35); text-underline-offset:2px;">${escapeHtml(showid)}</span>
            </span>
            <span class="pill">
              <span style="color:rgba(50,255,155,.92); font-weight:900;">uuid:</span>
              <span style="font-weight:950; font-size:14px; color:rgba(234,240,255,.98);">${escapeHtml(uuid)}</span>
            </span>
            ${cachedAt}
          </div>
        </div>
        <div class="p-actions">
          <button class="btn btn-warn" onclick="selectCached('${showid}')">选择</button>
          <button class="btn btn-good" onclick="unlockWithShowid('${showid}')">一键解封CMS</button>
          <div class="note-box">
            <div class="note-label">备注登录账号</div>
            <input class="note-input ${noteCls}" id="note-${showid}" placeholder="例如：tbh2356@126.com" value="${escapeHtml(note)}" oninput="saveNote('${showid}', this.value)" />
          </div>
        </div>
      </div>
    `;
  }

  let selectedShowid = '';
  function selectCached(showid){
    selectedShowid = showid;
    document.getElementById('showidSearch').value = showid;
    showToast({type:'success', title:'已选择', msg:`showid=${showid}`, duration:1200});
  }

  async function refreshCache(){
    try{
      const r = await fetch(`/api/${CURRENT_ENV}/cache`, {cache:'no-store'});
      const j = await r.json();
      if(!j.ok) return;
      const list = j.items || [];
      const el = document.getElementById('cacheList');
      el.innerHTML = list.map(renderPlayerCard).join('');

      // if empty, auto cache default once (browser-side)
      if(list.length===0){
        const onceKey = 'auto_default_cached_' + CURRENT_ENV;
        if(!sessionStorage.getItem(onceKey)){
          sessionStorage.setItem(onceKey, '1');
          await lookupUser(true);
        }
      }
    }catch(_e){}
  }

  async function deleteCached(showid, ev){
    try{ if(ev) ev.stopPropagation(); }catch(_e){}
    try{
      const form = new URLSearchParams();
      form.append('showid', showid);
      const r = await fetch(`/api/${CURRENT_ENV}/cache/delete`, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'}, body: form.toString()});
      const j = await r.json();
      if(j.ok){
        showToast({type:'success', title:'已删除缓存', msg:`showid=${showid}`, duration:1400});
        await refreshCache();
        await refreshStatusAll();
      }else{
        showToast({type:'error', title:'删除失败', msg: j.msg || 'unknown', duration:3000});
      }
    }catch(e){
      showToast({type:'error', title:'请求异常', msg: e.message || String(e), duration:3000});
    }
  }

  async function loginNow(){
    try{
      const r = await fetch(`/api/${CURRENT_ENV}/login_now`, {method:'POST'});
      const j = await r.json();
      if(j.ok){
        showToast({type:'success', title:'登录完成', msg:`${CURRENT_ENV} ${j.msg}`, duration:1600});
      }else{
        showToast({type:'error', title:'登录失败', msg: j.msg || 'unknown', duration:3400});
      }
      await refreshStatusAll();
      await refreshLogs();
      // auto load clubs after login
      setTimeout(()=>{ cmsLoadClubs(true); }, 120);
    }catch(e){
      showToast({type:'error', title:'异常', msg: e.message || String(e), duration:3400});
    }
  }

  async function clearLogs(){
    await fetch(`/api/${CURRENT_ENV}/logs/clear`, {method:'POST'});
    await refreshLogs();
  }

  

  // =========================
  // CMS功能管理：多账号 + 独立登录 + 独立日志面板
  // =========================
  async function refreshLogsManage(){
    try{
      const r = await fetch(`/api/${CURRENT_ENV}/logs`, {cache:'no-store'});
      const j = await r.json();
      if(!j.ok) return;
      const txt=(j.lines||[]).join('\n');
      const a=document.getElementById('logs2'); if(a) a.textContent=txt || '--';
    }catch(_e){}
  }

  async function clearLogsManage(){
    await fetch(`/api/${CURRENT_ENV}/logs/clear`, {method:'POST'});
    await refreshLogsManage();
  }

  async function loginNowManage(){
    try{
      const r = await fetch(`/api/${CURRENT_ENV}/cms/manage_login_now`, {method:'POST'});
      const j = await r.json();
      if(j.ok){
        showToast({type:'success', title:'管理端登录完成', msg:`${ENV_NAME(CURRENT_ENV)} | ${j.active_account||'--'}`, duration:1600});
      }else{
        showToast({type:'error', title:'管理端登录失败', msg: j.msg || 'unknown', duration:3400});
      }
      await manageAccountsLoad(true);
      await refreshStatusAll();
      await refreshLogsManage();
      setTimeout(()=>{ cmsLoadClubs(true); }, 120);
    }catch(e){
      showToast({type:'error', title:'异常', msg: e.message || String(e), duration:3400});
    }
  }

  async function manageAccountsLoad(silent=false){
    const sel = document.getElementById('manageAccountSelect');
    const hint = document.getElementById('manageAccountHint');
    if(sel){
      sel.innerHTML = '<option value="">（未选择）</option>';
    }
    try{
      const r = await fetch(`/api/${CURRENT_ENV}/auth/manage_accounts`, {cache:'no-store'});
      const j = await r.json();
      if(!j.ok) return;

      const active = j.active || '';
      const arr = (j.accounts||[]).map(x=>String(x.account||'').trim()).filter(Boolean);
      if(sel){
        for(const a of arr){
          const opt = document.createElement('option');
          opt.value = a;
          opt.textContent = a;
          if(a===active) opt.selected = true;
          sel.appendChild(opt);
        }
      }
      if(hint){
        hint.innerHTML = `当前：<b style="color:rgba(50,255,155,.92);font-weight:950;">${escapeHtml(active||'--')}</b>`;
      }
      // mirror into envInfo2 line as well
      const ei2 = document.getElementById('envInfo2');
      if(ei2){
        const envLabel = ENV_NAME(CURRENT_ENV);
        ei2.innerHTML = `<span style="font-family:var(--mono);">env=${escapeHtml(envLabel)} | account=<b style="color:rgba(255,201,71,.92);font-weight:950;">${escapeHtml(active||'--')}</b></span>`;
      }
      if(!silent && !active && arr.length){
        showToast({type:'info', title:'提示', msg:'已加载账号列表，可在下拉中选择', duration:1600});
      }
    }catch(e){
      if(!silent) showToast({type:'error', title:'加载账号失败', msg: e.message || String(e), duration:2400});
    }
  }

  async function onManageAccountSelectChange(){
    const sel = document.getElementById('manageAccountSelect');
    const account = (sel?.value||'').trim();
    const form = new URLSearchParams(); form.set('account', account);
    try{
      await fetch(`/api/${CURRENT_ENV}/auth/manage_accounts/select`, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'}, body: form.toString()});
      await manageAccountsLoad(true);
      showToast({type:'success', title:'已切换账号', msg: account||'（未选择）', duration:1200});
    }catch(e){
      showToast({type:'error', title:'切换失败', msg: e.message || String(e), duration:2200});
    }
  }

  async function deleteSelectedManageAccount(){
    const sel = document.getElementById('manageAccountSelect');
    const account = (sel?.value||'').trim();
    if(!account){
      showToast({type:'error', title:'未选择账号', msg:'请选择要删除的账号', duration:1600});
      return;
    }
    const form = new URLSearchParams(); form.set('account', account);
    try{
      const r = await fetch(`/api/${CURRENT_ENV}/auth/manage_accounts/delete`, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'}, body: form.toString()});
      const j = await r.json();
      if(j.ok){
        await manageAccountsLoad(true);
        showToast({type:'success', title:'已删除', msg: account, duration:1400});
      }else{
        showToast({type:'error', title:'删除失败', msg: j.error||'unknown', duration:2200});
      }
    }catch(e){
      showToast({type:'error', title:'删除失败', msg: e.message || String(e), duration:2200});
    }
  }

async function lookupUser(isAutoDefault=false){
    const showid = (document.getElementById('showidSearch').value||'').trim();
    if(!showid) return;
    const form = new URLSearchParams();
    form.append('showid', showid);
    const r = await fetch(`/api/${CURRENT_ENV}/cms/user_lookup`, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'}, body: form.toString()});
    const j = await r.json();
    if(j.ok){
      if(!isAutoDefault){
        showToast({type:'success', title:'查询成功', msg:`showid=${showid} uuid=${j.profile.uuid}`, duration:1600});
      }
      await refreshCache();
      await refreshStatusAll();
    }else{
      showToast({type:'error', title:'查询失败', msg: j.msg || 'unknown', duration:3200});
    }
    await refreshLogs();
  }

  async function unlockWithShowid(showid){
    document.getElementById('showidSearch').value = showid;
    await unlockDirect();
  }

  async function unlockDirect(){
    const showid = (document.getElementById('showidSearch').value||'').trim();
    if(!showid) return;
    const form = new URLSearchParams();
    form.append('showid', showid);
    const r = await fetch(`/api/${CURRENT_ENV}/cms/unlock`, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'}, body: form.toString()});
    const j = await r.json();
    if(j.ok && j.unlock_success){
      showToast({type:'success', title:'解封成功', msg:`status=200 iErrCode=0 showid=${showid}`, duration:2200});
    }else if(j.ok){
      const ierr = (j.body && j.body.iErrCode!==undefined) ? j.body.iErrCode : 'N/A';
      showToast({type:'error', title:'解封失败', msg:`status=${j.status_code} iErrCode=${ierr}`, duration:3600});
    }else{
      showToast({type:'error', title:'解封请求失败', msg:j.msg||'unknown', duration:3600});
    }
    await refreshLogs();
    await refreshStatusAll();
  }

  startClock();
  setInterval
  // ===== Top navigation: Unlock vs Manage =====
  function switchTop(which){
    const pu=document.getElementById('pageUnlock');
    const pm=document.getElementById('pageManage');
    const bu=document.getElementById('tab_unlock');
    const bm=document.getElementById('tab_manage');
    if(which==='manage'){
      pu.style.display='none'; pm.style.display='block';
      bu.classList.remove('active'); bm.classList.add('active');
      // mirror env nav in manage row
      renderEnvNav('envNavManage');
      updateEnvBadges();
      manageAccountsLoad(true);
      refreshLogsManage();
      // default: load clubs once (if empty)
      setTimeout(()=>{ 
        const sel=document.getElementById('clubSelect2');
        if(sel && sel.options.length===0) cmsLoadClubs(true);
      }, 120);
    }else{
      pm.style.display='none'; pu.style.display='block';
      bm.classList.remove('active'); bu.classList.add('active');
      renderEnvNav('envNav');
      updateEnvBadges();
    }
  }

  function sleep(ms){ return new Promise(res=>setTimeout(res, ms)); }

  async function saveCreds(){
    const a=(document.getElementById('cfgAccount')?.value||'').trim();
    const p=(document.getElementById('cfgPassword')?.value||'').trim();
    if(!a || !p){
      showToast({type:'error', title:'缺少账号/密码', msg:'请在 CMS功能管理 中输入账号密码', duration:2200});
      return;
    }
    const form=new URLSearchParams();
    form.set('account', a); form.set('password', p);
    const r = await fetch(`/api/${CURRENT_ENV}/auth/manage_accounts/save`, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'}, body: form.toString()});
    const j = await r.json();
    if(j.ok){
      // 清空密码输入，避免误操作；账号会进入下拉并成为当前环境 active
      const pw = document.getElementById('cfgPassword'); if(pw) pw.value='';
      const ac = document.getElementById('cfgAccount'); if(ac) ac.value='';
      await manageAccountsLoad(true);
      showToast({type:'success', title:'保存并登录成功', msg:`${ENV_NAME(CURRENT_ENV)} | ${j.active||a}`, duration:1800});
      await refreshStatusAll();
      await refreshLogsManage();
      // auto load clubs after login
      setTimeout(()=>{ cmsLoadClubs(true); }, 120);
    }else{
      showToast({type:'error', title:'保存失败', msg:(j.error||j.msg||'unknown'), duration:2400});
    }
  }
  async function cmsProxy(path, bodyStr, accept){
    const form=new URLSearchParams();
    form.set('path', path);
    form.set('body', bodyStr || '');
    if(accept) form.set('accept', accept);
    const r = await fetch(`/api/${CURRENT_ENV}/cms/proxy`, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'}, body: form.toString()});
    const j = await r.json();
    // normalize: if body is a JSON string, parse into object
    try{ if(j && typeof j.body==='string' && (j.body.trim().startsWith('{')||j.body.trim().startsWith('['))){ j.body = JSON.parse(j.body); } }catch(_e){}
    return j;
  }

  function clubOptionText(c){
    // MUST match油猴脚本格式（字段不漏）
    return `${c.sClubName}（俱乐部ID：${c.lClubID}） 成员数:${c.iCurMembers}  -  管理员:${c.iCurManageMembers}/${c.iMaxManageMembers}`;
  }

  async function cmsLoadClubs(silent){
    const sel=document.getElementById('clubSelect2');
    if(!sel) return;
    sel.innerHTML = '';
    const res = await cmsProxy('/cms-api/club/getClubList', '', "application/json, text/javascript, */*; q=0.01");
    if(!res.ok){
      if(!silent) showToast({type:'error', title:'加载俱乐部失败', msg: res.error || res.msg || 'no token', duration:2200});
      return;
    }
    const j = (res.body && typeof res.body==='object') ? res.body : (()=>{
      try{ return JSON.parse(res.body||'{}'); }catch(_e){ return {}; }
    })();
    if(j.iErrCode !== 0){
      if(!silent) showToast({type:'error', title:'加载俱乐部失败', msg: `iErrCode=${j.iErrCode} ${escapeHtml(j.sErrMsg||'')}`, duration:2600});
      return;
    }
    const clubs = j.result || [];
    for(const c of clubs){
      const op=document.createElement('option');
      op.value = String(c.lClubID);
      op.textContent = clubOptionText(c); // MUST match油猴脚本格式（字段不漏）
      sel.appendChild(op);
    }
    try{ localStorage.setItem('cmsClubs_'+CURRENT_ENV, JSON.stringify(clubs)); }catch(_e){}
    if(!silent) showToast({type:'success', title:'俱乐部列表获取成功', msg:`${CURRENT_ENV} clubs=${clubs.length}`, duration:1600});

    // 默认：加载俱乐部信息 -> 成员列表 -> 联盟信息（同一次操作链路）
    if(sel.options.length>0 && !sel.value){
      sel.selectedIndex = 0;
    }
    if(sel.value){
      await cmsLoadMembers(true);
      await leagueLoadAll();  // ✅ 同时加载联盟相关信息
    }
  }

  function copyClubId(){
    const sel=document.getElementById('clubSelect2');
    const v = sel?.value || '';
    if(!v) return;
    navigator.clipboard.writeText(v).then(()=>{
      showToast({type:'success', title:'已复制', msg:`clubId=${v}`, duration:1200});
    }).catch(()=>{
      showToast({type:'error', title:'复制失败', msg:'请手动复制', duration:1600});
    });
  }

  function roleHTML(level){
    if(level===1) return '<span style="color:#ff4d6d; font-weight:900;">群主</span>';
    if(level===2) return '<span style="color:rgba(108,168,255,.95); font-weight:900;">管理</span>';
    return '<span style="color:rgba(234,240,255,.78);">成员</span>';
  }


  function lockStatusHTML(lockStatus){
    if(lockStatus===0) return '<span style="display:inline-block;padding:2px 8px;border-radius:999px;background:rgba(50,255,155,.16);border:1px solid rgba(50,255,155,.35);color:rgba(50,255,155,.92);font-weight:900;">正常</span>';
    if(lockStatus===1) return '<span style="display:inline-block;padding:2px 8px;border-radius:999px;background:rgba(255,77,109,.16);border:1px solid rgba(255,77,109,.35);color:#ff4d6d;font-weight:900;">冻结</span>';
    return '<span style="opacity:.55">未知</span>';
  }

  function attachMemberSearch(){
    const wrapper = document.getElementById('memberSearchBoxWrapper2');
    if(!wrapper) return;
    wrapper.innerHTML = `
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <input id="memberSearchInput2" type="text" placeholder="输入 UUID / ShowID / 昵称 模糊搜索"
  style="flex:1;min-width:240px;padding:10px 12px;border-radius:12px;border:1px solid rgba(185,200,255,.16);background:rgba(255,255,255,.05);color:rgba(234,240,255,.92);" />
<style>#memberSearchInput2::placeholder{color:#000 !important;}</style>
        <button id="btnClearSearch2" class="btn btn-bad" style="padding:10px 14px;">清空</button>
      </div>
    `;
    function doFilter(){
      const kw=(document.getElementById('memberSearchInput2').value||'').trim().toLowerCase();
      document.querySelectorAll('#memberList2 tr').forEach(tr=>{
        const txt=[tr.dataset.uuid,tr.dataset.showid,tr.dataset.nick].join('|').toLowerCase();
        tr.style.display = txt.includes(kw) ? '' : 'none';
      });
    }
    wrapper.querySelector('#memberSearchInput2').addEventListener('input', doFilter);
    wrapper.querySelector('#btnClearSearch2').addEventListener('click', ()=>{
      wrapper.querySelector('#memberSearchInput2').value='';
      doFilter();
    });
  }

  async function cmsLoadMembers(silent){
    const cid = document.getElementById('clubSelect2')?.value;
    if(!cid){ if(!silent) showToast({type:'error', title:'请选择俱乐部', msg:'', duration:1600}); return; }
    const memberList=document.getElementById('memberList2');
    memberList.innerHTML = `<tr><td colspan="10" style="padding:12px;text-align:center;color:rgba(234,240,255,.75);">加载中...</td></tr>`;
    document.getElementById('memberClubIdDisplay2').textContent = `当前俱乐部ID: ${cid}`;

    // clubInfo: diamond fund + leagueId
    let leagueId = '';
    try{
      const clubInfoRes = await cmsProxy('/cms-api/club/clubInfo', `clubId=${cid}`, '*/*');
      const cj = clubInfoRes.body || {};
      if(cj.iErrCode===0 && cj.result){
        const diamondFund = cj.result.lDiamond || 0;
        leagueId = cj.result.iCreditLeagueId || '';
document.getElementById('memberClubIdDisplay2').innerHTML =
  `<span style="font-size:18px; font-weight:950; letter-spacing:.2px;">
     <span style="color:rgba(255,80,80,.96); font-weight:1000;">当前俱乐部ID: ${cid}</span>
     <span style="opacity:.55; padding:0 8px;">|</span>
     <span style="color:rgba(50,255,155,.95); font-weight:980;">钻石基金: ${diamondFund}</span>
     ${leagueId ? `<span style="opacity:.55; padding:0 8px;">|</span>
                  <span style="color:rgba(255,201,71,.96); font-weight:1000;">联盟ID: ${leagueId}</span>` : ``}
   </span>`;
      }
    }catch(_e){}

    const res = await cmsProxy('/cms-api/club/getClubMemberList', `clubId=${cid}&sort=-1&keyword=&pageNumber=1&pageSize=1000`);
    if(!res.ok){ if(!silent) showToast({type:'error', title:'加载成员失败', msg: res.error||res.msg||'', duration:2200}); return; }
    const j = res.body || {};
    if(j.iErrCode!==0){
      memberList.innerHTML = `<tr><td colspan="10" style="padding:12px;text-align:center;">加载失败: ${j.iErrCode}</td></tr>`;
      if(!silent) showToast({type:'error', title:'加载成员失败', msg:`iErrCode=${j.iErrCode}`, duration:2200});
      return;
    }

    // manager lockStatus map (only for 群主/管理员)
    let managerLockMap = {};
    try{
      const mr = await cmsProxy('/cms-api/club/getClubManagerList', `clubId=${cid}`);
      const mj = mr.body || {};
      if(mr.ok && mj.iErrCode===0 && Array.isArray(mj.result)){
        for(const it of mj.result){
          const sid = String(it.sShowID || it.sShowId || it.showId || it.showid || '');
          if(!sid) continue;
          managerLockMap[sid] = Number(it.lockStatus);
        }
      }
    }catch(_e){}

    let list = (j.result?.list || []);
    // sort: 群主-管理-成员 then balance desc
    const rp={1:0,2:1,4:2};
    list.sort((a,b)=>{
      const da=(rp[a.userClubLevel]??9)-(rp[b.userClubLevel]??9);
      if(da!==0) return da;
      return (b.balance||0)-(a.balance||0);
    });

    attachMemberSearch();
    memberList.innerHTML='';
    for(const m of list){
      const tr=document.createElement('tr');
      tr.dataset.uuid = String(m.uuid||'');
      tr.dataset.showid = String(m.showId||m.showid||'');
      tr.dataset.nick = String(m.strNick||'');
      const uuid = tr.dataset.uuid;
      const showId = tr.dataset.showid;
      const lvl = Number(m.userClubLevel||4);
      tr.innerHTML = `
        <td class="chkCol2" style="border:1px solid rgba(185,200,255,.14); padding:6px;">
          <input type="checkbox" class="memberCheck2" style="display:block;margin:0 auto;" data-uuid="${uuid}" data-showid="${showId}" data-level="${lvl}" />
        </td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">
          ${ (lvl===1||lvl===2) ? lockStatusHTML(managerLockMap[showId]) : '<span style="opacity:.45">—</span>' }
        </td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">${roleHTML(lvl)}</td>
        <td class="copyable2" data-copy="${uuid}" style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;cursor:pointer;">${uuid}</td>
        <td class="copyable2" data-copy="${showId}" style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;cursor:pointer;">${showId}</td>

        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">
          ${ (m.strSmallCover||m.strCover) ? `<img src="${m.strSmallCover||m.strCover}" style="width:28px;height:28px;border-radius:999px;object-fit:cover;border:1px solid rgba(185,200,255,.25);" />` : '<span style="opacity:.45">—</span>' }
        </td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;">${escapeHtml(m.strNick||m.nickName||'')}</td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">${m.balance??''}</td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">${m.coin||0}</td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">${m.starCoin||0}</td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">${m.lPopularity||0}</td>
      `;
      const cb = tr.querySelector('.memberCheck2');
      cb.addEventListener('change', ()=>{
        tr.style.backgroundColor = cb.checked ? 'rgba(86,204,242,.25)' : '';
      });
      memberList.appendChild(tr);
    }
    // copy on dblclick
    document.querySelectorAll('#memberList2 .copyable2').forEach(cell=>{
      cell.addEventListener('dblclick', ()=>{
        navigator.clipboard.writeText(cell.dataset.copy||'')
          .then(()=>showToast({type:'success', title:'已复制', msg:String(cell.dataset.copy||''), duration:1200}))
          .catch(()=>showToast({type:'error', title:'复制失败', msg:'', duration:1400}));
      });
    });
    // select all
    const all=document.getElementById('selectAllMembers2');
    all.onchange = function(){
      document.querySelectorAll('#memberList2 .memberCheck2').forEach(cb=>{
        cb.checked = all.checked;
        cb.dispatchEvent(new Event('change'));
      });
    };
    showToast({type:'success', title:'成员加载完成', msg:`${list.length} 条`, duration:1400});
  }

  function getCheckedMembers(){
    return Array.from(document.querySelectorAll('#memberList2 .memberCheck2:checked'));
  }

  function _checkedShowIds(){
    return getCheckedMembers().map(x=>String(x.dataset.showid||'')).filter(Boolean);
  }
async function diamondTransfer(){
  const cid = document.getElementById('clubSelect2')?.value;
  const amount = document.getElementById('diamondTransferAmount')?.value;
  const checkboxes = Array.from(document.querySelectorAll('#memberList2 .memberCheck2:checked'));
  if(checkboxes.length===0){ showToast({type:'error', title:'请先勾选用户', msg:'', duration:1600}); return; }

  let success=0, fail=0;
  for(const cb of checkboxes){
    const showid = cb.getAttribute('data-showid');
    const body = `num=${encodeURIComponent(amount)}&showid=${encodeURIComponent(showid)}`;
    try{
      const res = await cmsProxy('/cms-api/club/transferdiamond', body);
      const j = res.body || {};
      if(res.ok && j.iErrCode===0){
        success++;
        showToast({type:'success', title:'转账成功', msg:`showid=${showid} num=${amount}`, duration:900});
      }else if(j.iErrCode===666){
        fail++;
        showToast({type:'warn', title:'钻石不足', msg:`showid=${showid}`, duration:1600});
      }else{
        fail++;
        showToast({type:'error', title:'转账失败', msg:`showid=${showid} iErrCode=${j.iErrCode}`, duration:1800});
      }
    }catch(e){
      fail++;
      showToast({type:'error', title:'转账异常', msg:String(e?.message||e), duration:1800});
    }
    await sleep(0);
  }

  // 刷新钻石基金
  try{
    if(cid){
      const clubInfoRes = await cmsProxy('/cms-api/club/clubInfo', `clubId=${cid}`, '*/*');
      const cj = clubInfoRes.body || {};
      const diamondFund = cj?.result?.lDiamond ?? cj?.result?.lDiamondFund ?? 0;
      const idDisplay = document.getElementById('memberClubIdDisplay2');
      if(idDisplay) idDisplay.innerHTML = `当前俱乐部ID: ${cid} | <span style="color:rgba(50,255,155,.92);font-weight:950;">钻石基金: ${diamondFund}</span>`;
    }
  }catch(_e){}
  showToast({type: fail? 'warn':'success', title:'钻石转账完成', msg:`成功:${success} 失败:${fail}`, duration:2200});
  await cmsLoadMembers(true);
  const selectAll = document.getElementById('selectAllMembers2'); if(selectAll) selectAll.checked=false;
}
  async function diamondRecall(){
    const cid=document.getElementById('clubSelect2')?.value;
    const showIds=_checkedShowIds();
    const amt = Number(document.getElementById('diamondRecallAmount')?.value||0);
    if(!cid || showIds.length===0){ showToast({type:'error', title:'请选择成员', msg:'勾选后再操作', duration:1600}); return; }
    if(!amt || amt<=0){ showToast({type:'error', title:'金额无效', msg:'请输入正数', duration:1600}); return; }
    const bodyStr = `clubId=${cid}&amount=${amt}&showIds=${encodeURIComponent(showIds.join(','))}`;
    const res = await cmsProxy('/cms-api/club/fund/recall', bodyStr, "application/json, text/javascript, */*; q=0.01");
    const body = (res && res.body && typeof res.body==='object') ? res.body : (()=>{
      try{ return JSON.parse(res.body||'{}'); }catch(_e){ return {}; }
    })();
    const code = body.iErrCode;
    if(res.ok && code===0){
      showToast({type:'success', title:'钻石回收成功', msg:`人数:${showIds.length} 金额:${amt}`, duration:2200});
      await cmsLoadMembers(true);
      return;
    }
    showToast({type:'error', title:'钻石回收失败', msg:`iErrCode=${code} ${escapeHtml(body.sErrMsg||body.msg||res.error||'')}`, duration:4200});
  }

  async function loadVipList(){
  const cid=document.getElementById('clubSelect2')?.value;
  if(!cid){ showToast({type:'error', title:'请选择俱乐部', msg:'', duration:1600}); return; }
  const box=document.getElementById('vipBox2');
  box.style.display='block';
  box.innerHTML = `<div style="padding:10px;">加载中...</div>`;

  // 与油猴一致：/cms-api/agent/getClubAgentList 返回 {result:{data:[]}}
  const res = await cmsProxy('/cms-api/agent/getClubAgentList', `keyWord=&order=1&pageNumber=1&pageSize=100`);
  if(!res.ok){ box.innerHTML=`<div style="padding:10px;color:#ff4d6d;font-weight:900;">ERR: ${escapeHtml(res.error||res.msg||'')}</div>`; return; }
  const j=res.body||{};
  const list = (j.result && Array.isArray(j.result.data)) ? j.result.data : (Array.isArray(j.data) ? j.data : []);
  if(!list || list.length===0){
    box.innerHTML = `<div style="padding:10px;">未找到贵宾信息。</div>`;
    return;
  }

  const keysToShow = ['showId','nickName','creditBalance','slotDrawRatio',
    'texasDrawRatio','texasShareInsurance','omahaDrawRatio','omahaShareInsurance',
    'shortDrawRatio','shortShareInsurance','ofcDrawRatio','crbDrawRatio',
    'texasCowboyDrawRatio','texasCowboyBetBackRatio','mixedDrawRatio','sngDrawRatio','mttDrawRatio'];

  const headers = ['选择','showID','昵称','余额','小丑slot返利%',
    '德州返利%','德州保险%','奥马哈返利%','奥马哈保险%',
    '短牌返利%','短牌保险%','OF榜返利%','CRB返利%',
    '德州牛仔返利%','德州牛仔返点%','混合游戏返利%','SNG返利%','MTT返利%'];

  let html = `<div class="mini-title">贵宾列表（${list.length}）</div>
    <div class="tablewrap">
    <table class="tbl" style="width:max-content; min-width:unset; table-layout:auto;"><thead><tr>`;
  headers.forEach(h=>{
    if(h==='选择'){
      html += `<th class="chkCol2" style="padding:6px;"><input type="checkbox" id="selectAllVIPs2" style="width:18px;height:18px;display:block;margin:0 auto;" /></th>`;
    }else{
      html += `<th style="text-align:center;">${escapeHtml(h)}</th>`;
    }
  });
  html += `</tr></thead><tbody>`;

  for(const agent of list){
    const sid = agent.showId ?? '';
    html += `<tr data-showid="${escapeHtml(String(sid))}">`;
    html += `<td class="chkCol2" style="padding:6px;"><input type="checkbox" class="select-vip2" data-showid="${escapeHtml(String(sid))}" style="width:18px;height:18px;display:block;margin:0 auto;" /></td>`;
    for(const key of keysToShow){
      const v = (agent && (agent[key]!==undefined && agent[key]!==null)) ? agent[key] : '';
      const isRatio = (key.includes('Ratio') || key.includes('Back') || key.includes('Insurance'));
      if(isRatio){
        html += `<td style="text-align:center;">
          <input type="number" class="ratio-input2" data-ratio="${escapeHtml(key)}" value="${escapeHtml(String(v))}"
            style="width:70px;padding:6px;border:1px solid rgba(185,200,255,.25);border-radius:10px;background:rgba(10,14,22,.35);color:rgba(234,240,255,.92);" />
        </td>`;
      }else{
        const fw = (key==='showId') ? 'font-weight:900;color:rgba(108,168,255,.95);' : (key==='creditBalance' ? 'font-weight:900;color:rgba(255,201,71,.92);' : '');
        html += `<td style="text-align:center;${fw}">${escapeHtml(String(v))}</td>`;
      }
    }
    html += `</tr>`;
  }

  html += `</tbody></table></div>`;

  html += `<div class="row" style="margin-top:10px;gap:10px;flex-wrap:wrap;align-items:center;">
      <input id="vipBatchRatio2" type="number" placeholder="输入返利比例（0-100）" min="0" max="100"
        style="width:200px;padding:8px 10px;border:1px solid rgba(185,200,255,.25);border-radius:12px;background:rgba(10,14,22,.35);color:rgba(234,240,255,.92);" />
      <button class="btn btn-blue" style="background:#16a085;border-color:rgba(22,160,133,.55);" onclick="vipBatchFillRatioInputs()">设置统一返利比例(填入)</button>
      <button class="btn btn-good" onclick="vipBatchSaveRatios()">保存选中贵宾比例</button>
    </div>
    <div class="hint" style="margin-top:6px;">提示：勾选贵宾后可批量填入比例；保存会调用 /cms-api/agent/setAgentRatio</div>`;

  box.innerHTML = html;

  const all = box.querySelector('#selectAllVIPs2');
  if(all){
    all.onchange = function(){
      const cbs = box.querySelectorAll('.select-vip2');
      cbs.forEach(cb=>cb.checked = this.checked);
    };
  }
}

function vipBatchFillRatioInputs(){
  const box=document.getElementById('vipBox2');
  const v = (document.getElementById('vipBatchRatio2')?.value || '').trim();
  if(!v){ showToast({type:'error', title:'请输入返利比例', msg:'', duration:1600}); return; }
  let ratio = parseFloat(v);
  if(isNaN(ratio) || ratio<0 || ratio>100){ showToast({type:'error', title:'返利比例无效', msg:'范围0-100', duration:2000}); return; }
  const selected = box.querySelectorAll('.select-vip2:checked');
  if(!selected.length){ showToast({type:'error', title:'请选择贵宾', msg:'', duration:1600}); return; }
  selected.forEach(cb=>{
    const sid = cb.getAttribute('data-showid');
    const row = box.querySelector(`tr[data-showid="${CSS.escape(sid)}"]`);
    if(!row) return;
    row.querySelectorAll('.ratio-input2').forEach(inp=>{
      const k = inp.getAttribute('data-ratio')||'';
      let val = ratio;
      if(k==='texasCowboyBetBackRatio' && val>3) val = 3;
      inp.value = String(val);
    });
  });
  showToast({type:'success', title:'已填入', msg:`已对${selected.length}个贵宾填入`, duration:1600});
}

async function vipBatchSaveRatios(){
  const box=document.getElementById('vipBox2');
  const selected = Array.from(box.querySelectorAll('.select-vip2:checked'));
  if(!selected.length){ showToast({type:'error', title:'请选择贵宾', msg:'', duration:1600}); return; }

  const ratioMapping = {
    'mixedDrawRatio':'mixedRatio',
    'sngDrawRatio':'sngRatio',
    'mttDrawRatio':'mttRatio',
    'slotDrawRatio':'slotDrawRatio'
  };

  let ok=0, bad=0;
  for(let i=0;i<selected.length;i++){
    const sid = selected[i].getAttribute('data-showid');
    const row = box.querySelector(`tr[data-showid="${CSS.escape(sid)}"]`);
    if(!row){ bad++; continue; }
    const inputs = Array.from(row.querySelectorAll('.ratio-input2'));
    let bodyParams = `agentShowId=${encodeURIComponent(String(sid||''))}`;
    inputs.forEach(inp=>{
      const original = inp.getAttribute('data-ratio')||'';
      const mapped = ratioMapping[original] || original;
      const val = (inp.value||'').trim();
      bodyParams += `&${encodeURIComponent(mapped)}=${encodeURIComponent(val)}`;
    });

    const r = await cmsProxy('/cms-api/agent/setAgentRatio', bodyParams);
    const b = r.body||{};
    if(r.ok && (b.iErrCode===0 || b.result?.iErrCode===0)){ ok++; }
    else { bad++; }
    if(i<selected.length-1) await sleep(350);
  }
  showToast({type: bad? 'warn':'success', title:'保存贵宾比例完成', msg:`成功:${ok} 失败:${bad}`, duration:2400});
}

async function openAssignAgent(){
    const box=document.getElementById('agentAssignBox2');
    const willShow = (box.style.display==='none' || !box.style.display);
    box.style.display = willShow ? 'block' : 'none';
    if(!willShow) return;
    // 对齐 cms-2.1.8.js：打开分配区后，加载“成员列表 + 贵宾列表”两组数据
    await loadMemberAndAgentLists();
  }

  // ===== 分配贵宾代理：完全对齐 cms-2.1.8.js =====
  async function fetchMemberList(){
    // /cms-api/agent/getClubAllMemberList  body: keyWord=
    return await cmsProxy('/cms-api/agent/getClubAllMemberList', 'keyWord=');
  }
  async function fetchAgentList(){
    // /cms-api/agent/getClubAllAgentList  body: keyWord=
    return await cmsProxy('/cms-api/agent/getClubAllAgentList', 'keyWord=');
  }

  function _pickList(respBody){
    const b = respBody || {};
    const code = (b.iErrCode!==undefined) ? b.iErrCode : b.result?.iErrCode;
    let arr = [];
    if(Array.isArray(b.data)) arr = b.data;
    else if(Array.isArray(b.data?.list)) arr = b.data.list;
    else if(Array.isArray(b.result?.data)) arr = b.result.data;
    else if(Array.isArray(b.result?.data?.list)) arr = b.result.data.list;
    return {code, arr};
  }

  async function loadMemberAndAgentLists(){
    const cid = document.getElementById('clubSelect2')?.value;
    if(!cid){ showToast({type:'error', title:'请选择俱乐部', msg:'', duration:1600}); return; }

    const hint = document.getElementById('agentHint2');
    hint.textContent = '加载中...';

    try{
      const mr = await fetchMemberList();
      const ar = await fetchAgentList();

      if(!mr.ok){ hint.textContent = `获取成员列表失败: ${mr.error||mr.msg||''}`; return; }
      if(!ar.ok){ hint.textContent = `获取贵宾列表失败: ${ar.error||ar.msg||''}`; return; }

      const mPick = _pickList(mr.body);
      const aPick = _pickList(ar.body);
      if(mPick.code!==0){ hint.textContent = `获取成员列表失败 iErrCode=${mPick.code}`; return; }
      if(aPick.code!==0){ hint.textContent = `获取贵宾列表失败 iErrCode=${aPick.code}`; return; }

      const members = mPick.arr || [];
      const agents = aPick.arr || [];

      // 填充成员映射表（checkbox / nickName / showId / agentNickName）
      const tbody = document.getElementById('membersForAgentListBodyContent2');
      let rowsHtml = '';
      for(const m of members){
        const showId = String(m.showId||m.sShowID||m.sShowId||m.showid||'');
        const nickName = String(m.nickName||m.strNick||m.sNick||m.sNickName||'-');
        const agentNick = String(m.agentNickName||m.agentNick||m.agentName||m.strAgentNick||'');
        rowsHtml += `
          <tr style="${agentNick ? 'background: rgba(187,222,251,.35);' : ''}">
            <td class="chkCol2" style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:left;">
              <input type="checkbox" data-showid="${escapeHtml(showId)}" />
            </td>
            <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:left;">${escapeHtml(nickName)}</td>
            <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:left;">${escapeHtml(showId)}</td>
            <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:left;">${agentNick ? escapeHtml(agentNick) : '-'}</td>
          </tr>`;
      }
      tbody.innerHTML = rowsHtml;

      // 填充贵宾列表下拉（nickName(showId) + avatar）
      const agentSel = document.getElementById('agentForMembersList');
      agentSel.innerHTML = '';
      for(const a of agents){
        const sid = String(a.showId||a.sShowID||a.sShowId||a.showid||'');
        const nick = String(a.nickName||a.strNick||a.sNick||a.sNickName||'');
        const cover = String(a.strCover||a.cover||a.avatar||'');
        if(!sid) continue;
        const opt = new Option(`${nick} (${sid})`, sid);
        if(cover) opt.setAttribute('data-cover', cover);
        agentSel.add(opt);
      }

      // avatar preview 同步
      const avatarImg = document.getElementById('agentAvatar2');
      const syncAvatar = ()=>{
        const o = agentSel.options[agentSel.selectedIndex];
        const url = o?.getAttribute('data-cover')||'';
        if(avatarImg){
          if(url){ avatarImg.src=url; avatarImg.style.display='inline-block'; }
          else { avatarImg.style.display='none'; }
        }
      };
      agentSel.onchange = syncAvatar;
      syncAvatar();

      // 全选成员复选框逻辑（对齐油猴）
      const allCb = document.getElementById('selectAllMembersForAgent');
      if(allCb && !allCb._binded){
        allCb._binded = true;
        allCb.addEventListener('change', function(){
          const cbs = tbody.querySelectorAll('input[type="checkbox"]');
          cbs.forEach(cb=>{ cb.checked = this.checked; });
        });
      }

      // 绑定按钮事件（仅绑定一次）
      const assignBtn = document.getElementById('assignMembersToAgentBtn');
      if(assignBtn && !assignBtn._binded){
        assignBtn._binded = true;
        assignBtn.addEventListener('click', async ()=>{
          const selected = Array.from(tbody.querySelectorAll('input[type="checkbox"]:checked'))
            .map(cb=>cb.getAttribute('data-showid'))
            .filter(Boolean);
          const agentShowId = agentSel.value;
          if(!selected.length){ return showToast({type:'error', title:'请至少选择一个成员', msg:'', duration:1800}); }
          if(!agentShowId){ return showToast({type:'error', title:'请选择一个贵宾代理', msg:'', duration:1800}); }
          const body = `showIds=${encodeURIComponent(selected.join(','))}&agentShowId=${encodeURIComponent(agentShowId)}`;
          const res = await cmsProxy('/cms-api/agent/setAgencyRelative', body);
          const j = res.body||{};
          if(res.ok && (j.iErrCode===0 || j.result?.iErrCode===0)){
            showToast({type:'success', title:'分配成功', msg:`成员:${selected.length} -> ${agentShowId}`, duration:2200});
            await loadMemberAndAgentLists();
          }else{
            showToast({type:'error', title:'分配失败', msg:`iErrCode=${j.iErrCode ?? j.result?.iErrCode ?? 'unknown'}`, duration:2600});
          }
        });
      }
      const noAgentBtn = document.getElementById('setNoAgentForMembersBtn');
      if(noAgentBtn && !noAgentBtn._binded){
        noAgentBtn._binded = true;
        noAgentBtn.addEventListener('click', async ()=>{
          const selected = Array.from(tbody.querySelectorAll('input[type="checkbox"]:checked'))
            .map(cb=>cb.getAttribute('data-showid'))
            .filter(Boolean);
          if(!selected.length){ return showToast({type:'error', title:'请至少选择一个成员', msg:'', duration:1800}); }
          const body = `showIds=${encodeURIComponent(selected.join(','))}`;
          const res = await cmsProxy('/cms-api/agent/setNoAgentForUsers', body);
          const j = res.body||{};
          if(res.ok && (j.iErrCode===0 || j.result?.iErrCode===0)){
            showToast({type:'success', title:'设置无贵宾成功', msg:`成员:${selected.length}`, duration:2200});
            await loadMemberAndAgentLists();
          }else{
            showToast({type:'error', title:'设置无贵宾失败', msg:`iErrCode=${j.iErrCode ?? j.result?.iErrCode ?? 'unknown'}`, duration:2600});
          }
        });
      }

      hint.textContent = `成员:${members.length} 贵宾:${agents.length}（高亮=已绑定贵宾）`;
    }catch(e){
      console.error(e);
      hint.textContent = '加载成员和贵宾列表出错，请检查网络或联系管理员';
      showToast({type:'error', title:'加载失败', msg:String(e||''), duration:2600});
    }
  }


  async function cmsSetManager(){
    const cid=document.getElementById('clubSelect2')?.value;
    const cbs=getCheckedMembers();
    if(!cid || cbs.length===0){ showToast({type:'error', title:'请选择成员', msg:'', duration:1600}); return; }
    let ok=0, bad=0;
    for(let i=0;i<cbs.length;i++){
      const uuid=cbs[i].dataset.uuid;
      const r=await cmsProxy('/cms-api/club/addClubManager', `clubId=${cid}&uuid=${uuid}`);
      const body=r.body||{};
      if(r.ok && body.iErrCode===0) ok++; else bad++;
      if(i<cbs.length-1) await sleep(6200);
    }
    showToast({type: bad? 'warn':'success', title:'设为管理完成', msg:`成功:${ok} 失败:${bad}`, duration:2200});
    await cmsLoadMembers(true);
    // 同时加载联盟相关信息
    await leagueLoadAll();
  }

  async function cmsCancelManager(){
    const cid=document.getElementById('clubSelect2')?.value;
    const cbs=getCheckedMembers();
    if(!cid || cbs.length===0){ showToast({type:'error', title:'请选择成员', msg:'', duration:1600}); return; }
    let ok=0, bad=0;
    for(let i=0;i<cbs.length;i++){
      const showid=cbs[i].dataset.showid;
      const r=await cmsProxy('/cms-api/club/deleteClubManager', `clubId=${cid}&showid=${showid}`);
      const body=r.body||{};
      if(r.ok && body.iErrCode===0) ok++; else bad++;
      if(i<cbs.length-1) await sleep(6200);
    }
    showToast({type: bad? 'warn':'success', title:'取消管理完成', msg:`成功:${ok} 失败:${bad}`, duration:2200});
    await cmsLoadMembers(true);
    // 同时加载联盟相关信息
    await leagueLoadAll();
  }

  async function cmsSetAllPerm(){
    const cbs=getCheckedMembers();
    if(cbs.length===0){ showToast({type:'error', title:'请选择成员', msg:'', duration:1600}); return; }
    const pemissionStr='1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1%2C1';
    let ok=0,bad=0;
    for(let i=0;i<cbs.length;i++){
      const showid=cbs[i].dataset.showid;
      const r=await cmsProxy('/cms-api/club/grantManagerPermision', `showId=${showid}&pemissionStr=${pemissionStr}`);
      const body=r.body||{};
      if(r.ok && body.iErrCode===0) ok++; else bad++;
      if(i<cbs.length-1) await sleep(6200);
    }
    showToast({type: bad? 'warn':'success', title:'权限设置完成', msg:`成功:${ok} 失败:${bad}`, duration:2200});
    await cmsLoadMembers(true);
    // 同时加载联盟相关信息
    await leagueLoadAll();
  }

  async function cmsSetVIP(){
    const cbs=getCheckedMembers();
    if(cbs.length===0){ showToast({type:'error', title:'请选择成员', msg:'', duration:1600}); return; }
    let ok=0,bad=0;
    for(let i=0;i<cbs.length;i++){
      const showid=cbs[i].dataset.showid;
      const r=await cmsProxy('/cms-api/agent/setUserAgent', `showId=${showid}`);
      const body=r.body||{};
      if(r.ok && body.iErrCode===0) ok++; else bad++;
      if(i<cbs.length-1) await sleep(6200);
    }
    showToast({type: bad? 'warn':'success', title:'设置贵宾完成', msg:`成功:${ok} 失败:${bad}`, duration:2200});
    await cmsLoadMembers(true);
    // 同时加载联盟相关信息
    await leagueLoadAll();
  }

  async function cmsCancelVIP(){
    const cbs=getCheckedMembers();
    if(cbs.length===0){ showToast({type:'error', title:'请选择成员', msg:'', duration:1600}); return; }
    let ok=0,bad=0;
    for(let i=0;i<cbs.length;i++){
      const showid=cbs[i].dataset.showid;
      const r=await cmsProxy('/cms-api/agent/deteleAgent', `showId=${showid}`);
      const body=r.body||{};
      if(r.ok && body.iErrCode===0) ok++; else bad++;
      if(i<cbs.length-1) await sleep(6200);
    }
    showToast({type: bad? 'warn':'success', title:'取消贵宾完成', msg:`成功:${ok} 失败:${bad}`, duration:2200});
    await cmsLoadMembers(true);
    // 同时加载联盟相关信息
    await leagueLoadAll();
  }

  async function cmsAddCredit(){
    const cid=document.getElementById('clubSelect2')?.value;
    const amount=(document.getElementById('creditAmount2')?.value||'').trim();
    const cbs=getCheckedMembers();
    if(!cid || !amount || cbs.length===0){ showToast({type:'error', title:'请选择成员/金额', msg:'', duration:1600}); return; }
    let ok=0,bad=0;
    for(let i=0;i<cbs.length;i++){
      const showid=cbs[i].dataset.showid;
      const r=await cmsProxy('/cms-api/leaguecredit/setPlayerCreditCoin', `showId=${showid}&clubId=${cid}&num=${amount}`);
      const body=r.body||{};
      if(r.ok && body.iErrCode===0) ok++; else bad++;
      if(i<cbs.length-1) await sleep(6200);
    }
    showToast({type: bad? 'warn':'success', title:'加币完成', msg:`成功:${ok} 失败:${bad}`, duration:2200});
    await cmsLoadMembers(true);
    // 同时加载联盟相关信息
    await leagueLoadAll();
  }

  async function cmsKickMembers(){
    const cbs=getCheckedMembers();
    if(cbs.length===0){ showToast({type:'error', title:'请选择成员', msg:'', duration:1600}); return; }
    const onlyMembers = cbs.filter(cb=>cb.dataset.level==='4');
    if(onlyMembers.length!==cbs.length){
      if(!confirm(`只能踢出"成员"角色。选中${cbs.length}，可踢${onlyMembers.length}，继续?`)) return;
    }
    if(onlyMembers.length===0){ showToast({type:'error', title:'没有可踢出的成员', msg:'', duration:1800}); return; }
    let ok=0,bad=0;
    for(let i=0;i<onlyMembers.length;i++){
      const uuid=onlyMembers[i].dataset.uuid;
      const r=await cmsProxy('/cms-api/club/fire', `userUuid=${uuid}`);
      const body=r.body||{};
      if(r.ok && body.iErrCode===0) ok++; else bad++;
      if(i<onlyMembers.length-1) await sleep(6200);
    }
    showToast({type: bad? 'warn':'success', title:'踢出完成', msg:`成功:${ok} 失败:${bad}`, duration:2200});
    await cmsLoadMembers(true);
    // 同时加载联盟相关信息
    await leagueLoadAll();
  }

  async function cmsUnlockManagers(){
    const input=(document.getElementById('unlockManagerShowIdInput2')?.value||'').trim();
    const cbs=getCheckedMembers();
    let ids=[];
    if(cbs.length>0){
      const mgr = cbs.filter(cb=>cb.dataset.level==='2');
      if(mgr.length===0 && !input){
        showToast({type:'error', title:'请勾选管理员或输入showid', msg:'', duration:1800}); return;
      }
      ids.push(...mgr.map(cb=>cb.dataset.showid));
    }
    if(input){
      if(!/^\d+$/.test(input)){ showToast({type:'error', title:'showid格式不正确', msg:'请输入纯数字', duration:1800}); return; }
      ids.push(input);
    }
    ids=[...new Set(ids)];
    let ok=0,bad=0;
    for(let i=0;i<ids.length;i++){
      const showid=ids[i];
      const r=await cmsProxy('/cms-api/club/unlockClubManager', `showid=${showid}`);
      const body=r.body||{};
      if(r.ok && body.iErrCode===0) ok++; else bad++;
      if(ids.length>1 && i<ids.length-1) await sleep(6200);
    }
    document.getElementById('unlockManagerShowIdInput2').value='';
    showToast({type: bad? 'warn':'success', title:'解封完成', msg:`成功:${ok} 失败:${bad}`, duration:2200});
    await cmsLoadMembers(true);
    // 同时加载联盟相关信息
    await leagueLoadAll();
  }

  async function cmsLoadApplications(){
    const cid=document.getElementById('clubSelect2')?.value;
    if(!cid){ showToast({type:'error', title:'请选择俱乐部', msg:'', duration:1600}); return; }
    const tb=document.getElementById('applyList2');
    tb.innerHTML = `<tr><td colspan="5" style="padding:12px;text-align:center;">加载中...</td></tr>`;
    const res = await cmsProxy('/cms-api/club/getApplyList', `clubId=${cid}`);
    if(!res.ok){ showToast({type:'error', title:'加载申请失败', msg:res.error||res.msg||'', duration:2200}); return; }
    const j=res.body||{};
    if(j.iErrCode!==0){ tb.innerHTML=`<tr><td colspan="5" style="padding:12px;text-align:center;">加载失败:${j.iErrCode}</td></tr>`; return; }
    const list=j.result||[];
    tb.innerHTML='';
    for(const a of list){
      const tr=document.createElement('tr');
      tr.innerHTML=`
        <td style="border:1px solid rgba(185,200,255,.14);text-align:center;"><input type="checkbox" class="applyCheck2" data-uuid="${a.uuid}"/></td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">${a.showId}</td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">${a.uuid}</td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;">${escapeHtml(a.strNick||'')}</td>
        <td style="border:1px solid rgba(185,200,255,.14);padding:6px;text-align:center;">${new Date(a.applyTime).toLocaleString()}</td>
      `;
      tb.appendChild(tr);
    }
    showToast({type:'success', title:'申请列表已加载', msg:`${list.length} 条`, duration:1400});
  }

  async function cmsAcceptApply(_mode){
    const cid=document.getElementById('clubSelect2')?.value;
    const cbs=Array.from(document.querySelectorAll('#applyList2 .applyCheck2:checked'));
    if(!cid || cbs.length===0){ showToast({type:'error', title:'请选择申请', msg:'', duration:1600}); return; }
    let ok=0,bad=0;
    for(let i=0;i<cbs.length;i++){
      const uuid=cbs[i].dataset.uuid;
      const r=await cmsProxy('/cms-api/club/acceptApply', `userUuid=${uuid}&clubId=${cid}`);
      const body=r.body||{};
      if(r.ok && body.iErrCode===0) ok++; else bad++;
      if(i<cbs.length-1) await sleep(6200);
    }
    showToast({type: bad? 'warn':'success', title:'同意申请完成', msg:`成功:${ok} 失败:${bad}`, duration:2200});
    await cmsLoadApplications();
  }

  // =========================
// League (按 cms-2.1.8.js 逻辑)
// =========================
async function _getLeagueIdFromClub(){
  // 兜底：从 clubInfo 里取联盟ID（若后端字段存在）
  const cid = document.getElementById('clubSelect2')?.value;
  if(!cid) return '';
  try{
    const clubInfoRes = await cmsProxy('/cms-api/club/clubInfo', `clubId=${cid}`, '*/*');
    const cj = clubInfoRes.body || {};
    return String(cj.result?.iCreditLeagueId || cj.result?.lCreditLeagueId || cj.result?.leagueId || '') || '';
  }catch(_e){ return ''; }
}

async function leagueLoadAll(){
  await leagueLoadBase(true);
  await leagueLoadMembers(true);
}

async function leagueLoadBase(silent){
  const pills = document.getElementById('leagueBasePills2');
  const tbody = document.getElementById('leagueBaseTbody2');
  const hostBox = document.getElementById('hostLeagueInfo2');
  const rawBox = document.getElementById('leagueBox2');
  if(pills) pills.innerHTML='';
  if(tbody) tbody.innerHTML = `<tr><td colspan="2" style="text-align:center;padding:12px;">加载中...</td></tr>`;
  if(hostBox) hostBox.innerHTML='';
  if(rawBox) rawBox.textContent='';

  // ✅ 油猴：getLeagueCreditBaseInfo 不传 body
  const res = await cmsProxy('/cms-api/leaguecredit/getLeagueCreditBaseInfo', '');
  if(!res.ok){
    if(tbody) tbody.innerHTML = `<tr><td colspan="2" style="text-align:center;padding:12px;color:#ff4d6d;font-weight:900;">请求失败</td></tr>`;
    if(!silent) showToast({type:'error', title:'联盟基础信息失败', msg: res.error||res.msg||'', duration:2200});
    return;
  }
  const j = res.body || {};
  if(rawBox) rawBox.textContent = JSON.stringify(j, null, 2);
  if(j.iErrCode!==0){
    if(tbody) tbody.innerHTML = `<tr><td colspan="2" style="text-align:center;padding:12px;color:#ff4d6d;font-weight:900;">iErrCode=${j.iErrCode}</td></tr>`;
    if(!silent) showToast({type:'error', title:'联盟基础信息失败', msg:`iErrCode=${j.iErrCode}`, duration:2200});
    return;
  }

  const info = j.data || {};
  const leagueId = info.leagueid ?? info.leagueId ?? '';
  const leagueName = info.leagueName ?? '';
  const creditBalance = info.creditBalance ?? '';

  if(pills){
    const pill = (k,v,color)=>`<span class="pill"><span style="color:${color};font-weight:900;">${k}:</span> <span style="font-weight:950;color:rgba(234,240,255,.98);">${escapeHtml(String(v??''))}</span></span>`;
    pills.innerHTML =
      pill('leagueId', leagueId, 'rgba(255,201,71,.92)') +
      (leagueName? pill('leagueName', leagueName, 'rgba(108,168,255,.95)'):'') +
      (creditBalance!==''? pill('creditBalance', creditBalance, 'rgba(50,255,155,.92)'):'');
  }

  if(hostBox){
    hostBox.innerHTML = `
      <div style="margin:5px 0;">
        <div style="font-weight:900; margin-bottom:5px; user-select:text; color:rgba(234,240,255,.92);">主机联盟信息</div>
        <div style="font-size:14px; color: rgba(108,168,255,.95); font-weight:900; user-select:text;">联盟ID:
          <span id="hostLeagueId2" contenteditable="true" style="color:rgba(255,201,71,.92);font-weight:950;">${escapeHtml(String(leagueId))}</span>
        </div>
        <div style="user-select:text; color:rgba(234,240,255,.86);">名称:
          <span style="color:rgba(234,240,255,.98);font-weight:900;">${escapeHtml(String(leagueName))}</span>
        </div>
        <div style="user-select:text; color:rgba(234,240,255,.86);">余额:
          <span style="color:rgba(50,255,155,.92);font-weight:950;">${escapeHtml(String(creditBalance))}</span>
        </div>
      </div>`;
  }

  // 全字段表：不漏任何字段
  if(tbody){
    const entries = Object.entries(info || {});
    tbody.innerHTML = '';
    if(entries.length===0){
      tbody.innerHTML = `<tr><td colspan="2" style="text-align:center;padding:12px;">无数据</td></tr>`;
    }else{
      for(const [k,v] of entries){
        const vv = (typeof v === 'object') ? JSON.stringify(v) : String(v);
        tbody.insertAdjacentHTML('beforeend',
          `<tr><td style="color:rgba(108,168,255,.95);font-weight:900;">${escapeHtml(k)}</td><td class="kv-muted" style="color:rgba(234,240,255,.92);">${escapeHtml(vv)}</td></tr>`);
      }
    }
  }
}

async function leagueLoadMembers(silent){
  const tbody = document.getElementById('leagueMembersTbody2');
  const rawBox = document.getElementById('leagueBox2');
  if(!tbody) return;
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:12px;">加载中...</td></tr>`;

  const all = [];
  // ✅ 油猴：getLeagueMermberCreditInfoList 不需要 leagueId
  for(let page=1; ; page++){
    const body = `keyword=&order=1&pageNumber=${page}&pageSize=100`;
    const res = await cmsProxy('/cms-api/leaguecredit/getLeagueMermberCreditInfoList', body);
    if(!res.ok){
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:12px;color:#ff4d6d;font-weight:900;">请求失败</td></tr>`;
      if(!silent) showToast({type:'error', title:'加载联盟俱乐部失败', msg: res.error||res.msg||'', duration:2200});
      return;
    }
    const j = res.body || {};
    if(j.iErrCode!==0){
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:12px;color:#ff4d6d;font-weight:900;">iErrCode=${j.iErrCode}</td></tr>`;
      if(!silent) showToast({type:'error', title:'加载联盟俱乐部失败', msg:`iErrCode=${j.iErrCode}`, duration:2200});
      return;
    }
    const list = j.data?.list || [];
    if(list.length===0) break;
    all.push(...list);
    if(list.length < 100) break;
  }

  tbody.innerHTML = '';
  if(all.length===0){
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:12px;">无数据</td></tr>`;
    if(rawBox) rawBox.textContent = JSON.stringify({count:0, list:[]}, null, 2);
    return;
  }

  for(const club of all){
    const isLeagueLordText = (club.isLeagueLord===0)
      ? '<span style="color:#ff4d6d;font-weight:900;">附属俱乐部</span>'
      : '<span style="color:rgba(50,255,155,.92);font-weight:900;">主机俱乐部</span>';
    const statusText = (club.creditStatus===1)
      ? '<span style="color:#ff4d6d;font-weight:900;">冻结</span>'
      : '<span style="color:rgba(50,255,155,.92);font-weight:900;">正常</span>';

    tbody.insertAdjacentHTML('beforeend', `
      <tr>
        <td style="border:1px solid rgba(185,200,255,.14); text-align:center;">
          <input type="checkbox" class="leagueClubCheck2" data-clubid="${escapeHtml(String(club.clubId))}" style="transform:scale(1.2); accent-color:#27ae60;" />
        </td>
        <td style="border:1px solid rgba(185,200,255,.14); padding:6px;">${isLeagueLordText}</td>
        <td style="border:1px solid rgba(185,200,255,.14); padding:6px;">${escapeHtml(String(club.clubName||''))}</td>
        <td style="border:1px solid rgba(185,200,255,.14); padding:6px; text-align:center; color:rgba(108,168,255,.95);font-weight:900;">${escapeHtml(String(club.clubId))}</td>
        <td style="border:1px solid rgba(185,200,255,.14); padding:6px; text-align:center; color:rgba(255,201,71,.92);font-weight:900;">${escapeHtml(String(club.creditBalance??''))}</td>
        <td style="border:1px solid rgba(185,200,255,.14); padding:6px; text-align:center;">${statusText}</td>
      </tr>`);
  }

  // 全选
  const selAll = document.getElementById('selectAllLeagueClubs2');
  if(selAll){
    selAll.onchange = function(){
      document.querySelectorAll('#leagueMembersTbody2 .leagueClubCheck2').forEach(cb => cb.checked = selAll.checked);
    };
  }

  if(rawBox) rawBox.textContent = JSON.stringify({count: all.length, list: all}, null, 2);
}

setInterval(async ()=>{ await refreshStatusAll(); }, 2500);
  setInterval(async ()=>{ await refreshLogs(); }, 2500);
  setInterval(async ()=>{ await refreshCache(); }, 6500);
  setInterval(()=>{ fetch('/api/health', {cache:'no-store'}).catch(()=>{}); }, 20000);

  (async function boot(){
    tickClock();
    await initBackground();
    await loadEnvs();
    await refreshStatusAll();
    await refreshLogs();
    await refreshCache();
  })();
</script>
</body>
</html>
"""


@app.get("/")
def home():
    return render_template_string(HTML)


# cache-control for bg images (encourage local caching)
@app.after_request
def add_cache_headers(resp):
    if request.path.startswith("/bg/"):
        resp.cache_control.public = True
        resp.cache_control.max_age = 60 * 60 * 24 * 30
    return resp


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5209"))
    app.run(host="0.0.0.0", port=port, debug=False)
