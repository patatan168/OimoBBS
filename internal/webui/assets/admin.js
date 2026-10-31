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

/** 固定した板ナビの高さに合わせ、ページ内リンクの移動先が隠れないようにする。 */
function enhanceBoardContext(context) {
  const updateOffset = () => {
    const height = getComputedStyle(context).position === "sticky" ? context.getBoundingClientRect().height : 0;
    document.documentElement.style.setProperty('--board-context-height', `${Math.ceil(height) + 16}px`);
  };
  updateOffset();
  new ResizeObserver(updateOffset).observe(context);
}
for (const context of document.querySelectorAll('.board-context')) enhanceBoardContext(context);
