/* 管理画面の共通メニューと、同一管理パスのURLを扱う。 */
"use strict";

/** 管理画面のAPIと遷移先を設定された隠しパスに揃える。 */
function adminURL(path) {
  return (document.querySelector('meta[name="oimo-admin-base"]')?.content || "") + path;
}

/** 管理メニューは外側のクリックとEscapeで閉じ、キーボード操作時は開閉ボタンへ戻す。 */
function enhanceAdminMenu(menu) {
  document.addEventListener("click", event => {
    if (menu.open && !menu.contains(event.target)) menu.open = false;
  });
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape" || !menu.open) return;
    menu.open = false;
    menu.querySelector("summary").focus();
  });
}
for (const menu of document.querySelectorAll(".admin-menu")) enhanceAdminMenu(menu);
