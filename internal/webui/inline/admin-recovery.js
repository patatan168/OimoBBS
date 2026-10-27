/* CSS/JSの取得前に認証が失効しても、このページ自身からログインへ戻す。 */
(() => {
  "use strict";
  let checking = false;
  const pending = new Set();
  window.addEventListener("error", async event => {
    const node = event.target;
    if (!(node instanceof HTMLLinkElement && node.rel === "stylesheet") && !(node instanceof HTMLScriptElement && node.src)) return;
    const base = document.querySelector('meta[name="oimo-admin-base"]')?.content || "";
    const url = new URL(node.href || node.src, location.href);
    if (url.origin !== location.origin || !url.pathname.startsWith(base + "/web/assets/page/")) return;
    pending.add(url.href);
    if (checking) return;
    checking = true;
    try {
      while (pending.size) {
        const next = pending.values().next().value;
        pending.delete(next);
        const response = await fetch(next, {method: "HEAD", credentials: "same-origin", cache: "no-store", redirect: "manual"});
        if (response.status === 401) { location.replace(base + "/login"); return; }
        // URLを明示して新しいGETにする。Firefoxのreloadで元の遷移元分類を引き継がない。
        if (response.type === "opaqueredirect") { location.replace(location.href); return; }
      }
    } catch {
      pending.clear();
    } finally {
      checking = false;
    }
  }, true);
})();
