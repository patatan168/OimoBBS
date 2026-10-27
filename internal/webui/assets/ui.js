/* 公開・管理のナビゲーションで、現在のページを示す。 */
"use strict";

(() => {
// 管理画面の現在位置はHTMLに含まれる。大きな本文の解析やJS取得を待たせない。
if (document.body.classList.contains("admin")) return;
for (const link of document.querySelectorAll(".site-header nav a")) {
  if (new URL(link.href).hash) continue;
  const path = new URL(link.href).pathname;
  const board = link.dataset.board;
  const inBoard = board && (location.pathname.startsWith("/" + board + "/") || location.pathname.startsWith("/test/read.cgi/" + board + "/") || (location.pathname === "/web/post" && new URLSearchParams(location.search).get("bbs") === board));
  if (inBoard || location.pathname === path || (path !== "/" && location.pathname.startsWith(path + "/"))) {
    link.setAttribute("aria-current", "page");
  }
}

})();
