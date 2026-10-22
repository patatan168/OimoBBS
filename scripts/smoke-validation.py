#!/usr/bin/env python3
"""検証環境にWebスレ立て・返信を行い、--verifyで再起動後の公開データを照合する。"""
import argparse
import hashlib
import html.parser
import http.cookiejar
import json
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
import uuid


class Fields(html.parser.HTMLParser):
    """確認フォームのhidden値だけを取り出す。"""
    def __init__(self, page):
        super().__init__()
        self.values = {}
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        row = dict(attrs)
        if tag == "input" and row.get("type") == "hidden":
            self.values[row["name"]] = row.get("value", "")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--base", default="https://patatanmc.f5.si")
parser.add_argument("--board", default="oimo")
parser.add_argument("--state", default="var/docker-smoke.json")
parser.add_argument("--verify", action="store_true")
args = parser.parse_args()
base = args.base.rstrip("/")
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())


def request(path, fields=None, method=None, headers=None):
    """TLSを検証し、Cookieを保持して応答本文とヘッダを返す。"""
    data = None if fields is None else urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Origin", base)
        req.add_header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read()


def post(key, title, message):
    """入力→確認→確定→同一再送で、同じ303 Locationになることを検査する。"""
    path = "/web/post?bbs=" + args.board
    status, _, page = request(path + "&key=" + key)
    assert status == 200, status
    fields = Fields(page.decode()).values
    fields.update({"FROM": "Docker検証", "mail": "sage", "MESSAGE": message})
    if not key:
        fields["subject"] = title
    status, _, page = request(path, fields)
    assert status == 200 and "書き込み確認" in page.decode(), (status, page)
    confirmed = Fields(page.decode()).values
    status, headers, page = request(path, confirmed)
    assert status == 303, (status, page)
    location = headers["Location"]
    status, headers, _ = request(path, confirmed)
    assert status == 303 and headers["Location"] == location, "再送が重複投稿になりました"
    return location


state_path = Path(args.state)
if args.verify:
    state = json.loads(state_path.read_text())
    assert state["base"] == base
    status, headers, body = request(state["dat_path"])
    assert status == 200 and hashlib.sha256(body).hexdigest() == state["sha256"]
    assert headers["ETag"] == state["etag"]
    print(json.dumps({"status": "PASS", "check": "restart persistence", "thread": state["thread"]}, ensure_ascii=False))
else:
    status, _, body = request("/bbsmenu.json")
    assert status == 200
    assert any(board["url"] == base + "/" + args.board + "/"
               for category in json.loads(body)["menu_list"] for board in category["category_content"])
    location = post("", "Docker動作確認 " + uuid.uuid4().hex[:8], "HTTPS経由のスレ立て確認です。\n<script> & 😀")
    key = urllib.parse.urlsplit(location).path.split("/")[4]
    dat_path = "/" + args.board + "/dat/" + key + ".dat"
    status, _, initial = request(dat_path)
    assert status == 200
    post(key, "", "返信・再起動後の保存確認です。")
    status, headers, body = request(dat_path)
    assert status == 200 and len(body.splitlines()) == 2
    assert "返信・再起動後" in body.decode("shift_jis")
    status, _, delta = request(dat_path, headers={"Range": f"bytes={len(initial)}-"})
    assert status == 206 and initial + delta == body
    status, head, head_body = request(dat_path, method="HEAD")
    assert status == 200 and head_body == b"" and int(head["Content-Length"]) == len(body)
    status, _, page = request(urllib.parse.urlsplit(location).path)
    assert status == 200 and b"&lt;script&gt;" in page
    status, _, _ = request("/admin/boards")
    assert status == 404
    state = {"base": base, "thread": location, "dat_path": dat_path,
             "sha256": hashlib.sha256(body).hexdigest(), "etag": headers["ETag"]}
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, ensure_ascii=False) + "\n")
    print(json.dumps({"status": "PASS", "checks": ["HTTPS", "menu", "web create", "confirmation", "dedup", "reply", "DAT", "Range", "HEAD", "HTML escape", "admin isolation"], "thread": location}, ensure_ascii=False))
