"""隔離性能試験専用の初期管理者を作り、実管理APIでWAFを有効にする。"""
import http.client
import http.cookies
import json
import secrets
import subprocess
import urllib.parse
import uuid

from probe_peak_mix import Fields


def initialize(image, volume, config, certificate, key):
    """測定用の新規volumeだけを初期化し、秘密をstdinで渡して管理者を作る。"""
    password = secrets.token_urlsafe(40)
    base = ["docker", "run", "--rm", "-i", "--network", "none", "-v", f"{volume}:/data",
            "-v", f"{config}:/etc/oimobbs/config.json:ro",
            "-v", f"{certificate}:/tls/cert.pem:ro", "-v", f"{key}:/tls/key.pem:ro", image]
    subprocess.run(base + ["init", "--config", "/etc/oimobbs/config.json"],
                   check=True, stdout=subprocess.DEVNULL)
    subprocess.run(base + ["admin", "init", "--config", "/etc/oimobbs/config.json",
                          "--login", "performance-probe", "--password-stdin"],
                   input=(password + "\n").encode(), check=True, stdout=subprocess.DEVNULL)
    return password


def enable(port, password, posting_rate=0, posting_concurrent=0):
    """認証・CSRF・再認証・CASを経て検査と頻度制限を保存し、確認した設定を返す。"""
    cookies = {}
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    origin = f"http://127.0.0.1:{port}"

    def request(method, path, body=None, headers=None, expected=200):
        """隔離管理サーバーへ要求し、Cookieを更新して期待した状態だけを返す。"""
        chosen = dict(headers or {})
        if method != "GET":
            chosen["Origin"] = origin
        if cookies:
            chosen["Cookie"] = "; ".join(k + "=" + v for k, v in cookies.items())
        connection.request(method, path, body, chosen)
        response = connection.getresponse()
        raw = response.read()
        for name, value in response.getheaders():
            if name.lower() == "set-cookie":
                for key, cookie in http.cookies.SimpleCookie(value).items():
                    cookies[key] = cookie.value
        if response.status != expected:
            raise RuntimeError(f"isolated WAF setup {path}: HTTP {response.status}")
        return dict((k.lower(), v) for k, v in response.getheaders()), raw

    try:
        _, page = request("GET", "/login")
        fields = Fields(page).values
        fields.update({"login": "performance-probe", "password": password})
        request("POST", "/login", urllib.parse.urlencode(fields).encode(),
                {"Content-Type": "application/x-www-form-urlencoded"}, expected=303)
        headers, _ = request("GET", "/api/v1/reauth")
        request("POST", "/api/v1/reauth", json.dumps({"password": password}),
                {"Content-Type": "application/json", "X-CSRF-Token": headers["x-csrf-token"]})
        headers, raw = request("GET", "/api/v1/waf")
        policy = json.loads(raw)["data"]["settings"]
        policy["enabled"] = True
        # 頻度による拒否と検査費用を区別し、既存の同時処理枠は維持する。
        policy["traffic"].update({"enabled": True, "client_rate": 10000, "client_burst": 100000,
                                  "global_rate": 100000, "global_burst": 200000})
        if posting_rate:
            policy["traffic"]["posting"].update({"global_rate": posting_rate, "global_burst": max(120, 2 * posting_rate)})
        if posting_concurrent:
            policy["traffic"]["posting"]["global_concurrent"] = posting_concurrent
        request("POST", "/api/v1/waf", json.dumps(policy),
                {"Content-Type": "application/json", "X-CSRF-Token": headers["x-csrf-token"],
                 "If-Match": headers["etag"], "Idempotency-Key": uuid.uuid4().hex})
        _, raw = request("GET", "/api/v1/waf")
        saved = json.loads(raw)["data"]
        if saved["settings"] != policy:
            raise RuntimeError("isolated WAF settings mismatch")
        return saved["settings"]
    finally:
        connection.close()
