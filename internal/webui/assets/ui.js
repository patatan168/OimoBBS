/* 素のJavaScriptによる表示補助。入力や資格情報を保存・外部送信しない。 */
"use strict";

/** 一覧を現在のページ内だけで絞り込む。JSなしでは全項目を表示する。 */
function enhanceList(list) {
  const rows = Array.from(list.children);
  if (rows.length < 2) return;
  const normalize = value => value.normalize("NFKC").toLocaleLowerCase();
  const texts = rows.map(row => normalize(row.dataset.filterText ?? row.textContent));
  const pageSize = Number(list.dataset.filterPageSize) || rows.length;
  let page = Math.max(0, Math.floor(rows.findIndex(row => row.open) / pageSize));
  const tools = document.createElement("div");
  tools.className = "filter-tools";
  const label = document.createElement("label");
  label.className = "filter-field";
  label.textContent = list.dataset.filterLabel || (list.classList.contains("country-options") ? "国名・コードで絞り込む" : "このページ内を絞り込む");
  const input = document.createElement("input");
  input.type = "search";
  input.placeholder = list.dataset.filterPlaceholder || (list.classList.contains("country-options") ? "例：日本、US" : "名前・タイトルで検索");
  label.append(input);
  tools.append(label);
  const kind = document.createElement("select");
  if (list.dataset.filterSelect) {
    const kindLabel = document.createElement("label");
    kindLabel.textContent = list.dataset.filterSelect;
    kind.append(new Option("すべて", ""));
    const options = new Map(rows.map(row => [row.dataset.filterKind, row.dataset.filterKindLabel]));
    for (const [value, name] of options) kind.append(new Option(name, value));
    kindLabel.append(kind);
    tools.append(kindLabel);
  }
  const count = document.createElement("p");
  count.className = "field-hint";
  count.setAttribute("role", "status");
  const pager = document.createElement("div");
  pager.className = "page-actions network-pager";
  const previous = document.createElement("button");
  const next = document.createElement("button");
  previous.type = next.type = "button";
  previous.textContent = `前の${pageSize}件`;
  next.textContent = `次の${pageSize}件`;
  const pageLabel = document.createElement("span");
  pager.append(previous, pageLabel, next);
  list.before(tools, count);
  list.after(pager);
  function filter(reset = false) {
    if (reset) page = 0;
    const query = normalize(input.value.trim());
    const matching = rows.map((row, index) => ({ row, index })).filter(({ row, index }) => texts[index].includes(query) && (!kind.value || row.dataset.filterKind === kind.value));
    const pages = Math.max(1, Math.ceil(matching.length / pageSize));
    page = Math.min(page, pages - 1);
    const visible = new Set(matching.slice(page * pageSize, (page + 1) * pageSize).map(item => item.row));
    for (const row of rows) row.hidden = !visible.has(row);
    count.textContent = matching.length === 0 ? "一致する項目がありません。検索語・回線区分を変えてください。" : `${rows.length}件中 ${matching.length}件が一致・${visible.size}件を表示`;
    pager.hidden = pages === 1;
    previous.disabled = page === 0;
    next.disabled = page === pages - 1;
    pageLabel.textContent = `${page + 1} / ${pages}ページ`;
  }
  input.addEventListener("input", () => filter(true));
  kind.addEventListener("change", () => filter(true));
  previous.addEventListener("click", () => { page--; filter(); tools.scrollIntoView({ block: "start" }); });
  next.addEventListener("click", () => { page++; filter(); tools.scrollIntoView({ block: "start" }); });
  filter();
}

for (const link of document.querySelectorAll(".site-header nav a")) {
  if (new URL(link.href).hash) continue;
  const path = new URL(link.href).pathname;
  const board = link.dataset.board;
  const inBoard = board && (location.pathname.startsWith("/" + board + "/") || location.pathname.startsWith("/test/read.cgi/" + board + "/") || (location.pathname === "/web/post" && new URLSearchParams(location.search).get("bbs") === board));
  if (inBoard || location.pathname === path || (path !== "/" && location.pathname.startsWith(path + "/"))) {
    link.setAttribute("aria-current", "page");
  }
}
for (const list of document.querySelectorAll("[data-filter-list]")) enhanceList(list);

/** レス番号を既存のread.cgi範囲へ渡す。履歴・入力内容は保存しない。 */
function enhanceResponseJump(main) {
  const form = main.querySelector("[data-response-jump]");
  if (!form) return;
  form.hidden = false;
  form.addEventListener("submit", event => {
    event.preventDefault();
    const input = form.elements.namedItem("response");
    if (!input.reportValidity()) return;
    const number = Number(input.value);
    const current = document.getElementById(String(number));
    if (current) {
      location.hash = String(number);
      current.tabIndex = -1;
      current.focus({ preventScroll: true });
    } else {
      location.assign(main.dataset.threadBase + number + "n");
    }
  });
}

/** 本文の返信番号だけをリンク化する。投稿文字列をHTMLとして解釈しない。 */
function enhanceResponseLinks(main) {
  for (const body of main.querySelectorAll("[data-response-body]")) {
    const text = body.textContent;
    const fragment = document.createDocumentFragment();
    let offset = 0;
    for (const match of text.matchAll(/>>([1-9][0-9]{0,4})(?![0-9])/g)) {
      fragment.append(document.createTextNode(text.slice(offset, match.index)));
      const link = document.createElement("a");
      link.textContent = match[0];
      link.href = document.getElementById(match[1]) ? "#" + match[1] : main.dataset.threadBase + match[1] + "n";
      fragment.append(link);
      offset = match.index + match[0].length;
    }
    if (offset === 0) continue;
    fragment.append(document.createTextNode(text.slice(offset)));
    body.replaceChildren(fragment);
  }
}
for (const main of document.querySelectorAll("[data-thread-base]")) {
  enhanceResponseJump(main);
  enhanceResponseLinks(main);
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
