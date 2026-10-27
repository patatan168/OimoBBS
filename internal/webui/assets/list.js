/* このページ内の一覧だけを絞り込む。国名の補完後に読み込む。 */
"use strict";

(() => {
/** 一覧を現在のページ内だけで絞り込む。JSなしでは全項目を表示する。 */
function enhanceList(list) {
  const rows = Array.from(list.children);
  if (rows.length < 2) return;
  const normalize = value => value.normalize("NFKC").toLocaleLowerCase();
  const texts = rows.map(row => normalize(row.dataset.filterText ?? row.textContent));
  const countryCodes = list.classList.contains("country-options") ? rows.map(row => row.querySelector("[data-country-code]")?.dataset.countryCode.toLowerCase() || "") : null;
  const paginated = Number(list.dataset.filterPageSize) > 0;
  let pageSize = Number(list.dataset.filterPageSize) || rows.length;
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
  pager.className = "filter-pager";
  pager.setAttribute("role", "group");
  pager.setAttribute("aria-label", (list.dataset.filterLabel || "一覧") + "・ページ送り");
  const previous = document.createElement("button");
  const next = document.createElement("button");
  previous.type = next.type = "button";
  previous.textContent = "前へ";
  next.textContent = "次へ";
  const pageField = document.createElement("label");
  pageField.textContent = "ページ";
  const pageSelect = document.createElement("select");
  pageSelect.setAttribute("aria-label", "ページ");
  pageField.append(pageSelect);
  const sizeField = document.createElement("label");
  sizeField.textContent = "表示件数";
  const sizeSelect = document.createElement("select");
  sizeSelect.setAttribute("aria-label", "表示件数");
  for (const size of [...new Set([10, 20, 50, pageSize])].sort((a, b) => a - b)) sizeSelect.append(new Option(size + "件", String(size)));
  sizeSelect.value = String(pageSize);
  sizeField.append(sizeSelect);
  pager.append(previous, pageField, next, sizeField);
  list.before(tools, count);
  let viewport;
  if (paginated) {
    viewport = document.createElement("div");
    viewport.className = "filter-viewport" + (rows.length <= 10 ? " filter-viewport-small" : "");
    viewport.tabIndex = 0;
    viewport.setAttribute("role", "region");
    viewport.setAttribute("aria-label", list.dataset.filterLabel || "一覧");
    list.before(pager, viewport);
    viewport.append(list);
  }
  function filter(reset = false) {
    if (reset) page = 0;
    const query = normalize(input.value.trim());
    // 2文字の国コードは完全一致にし、US検索へRussiaなどの英語名を混ぜない。
    const exactCountry = countryCodes && /^[a-z]{2}$/.test(query);
    const matching = rows.map((row, index) => ({ row, index })).filter(({ row, index }) =>
      (exactCountry ? countryCodes[index] === query : texts[index].includes(query)) && (!kind.value || row.dataset.filterKind === kind.value));
    const pages = Math.max(1, Math.ceil(matching.length / pageSize));
    page = Math.min(page, pages - 1);
    const visible = new Set(matching.slice(page * pageSize, (page + 1) * pageSize).map(item => item.row));
    for (const row of rows) row.hidden = !visible.has(row);
    count.textContent = matching.length === 0 ? (list.dataset.filterEmpty || "一致する項目がありません。検索語・回線区分を変えてください。") : `${rows.length}件中 ${matching.length}件が一致・${page * pageSize + 1}〜${page * pageSize + visible.size}件を表示`;
    pager.hidden = !paginated || rows.length <= 10;
    if (pageSelect.options.length !== pages) {
      pageSelect.replaceChildren(...Array.from({length: pages}, (_, index) => new Option(`${index + 1} / ${pages}`, String(index))));
    }
    pageSelect.value = String(page);
    previous.disabled = page === 0;
    next.disabled = page === pages - 1;
  }
  input.addEventListener("input", () => filter(true));
  kind.addEventListener("change", () => filter(true));
  /** 一覧内だけを先頭へ戻し、文書のスクロール位置とフォームの入力値は保つ。 */
  function showPage(value) {
    page = value;
    filter();
    if (viewport) viewport.scrollTop = 0;
  }
  previous.addEventListener("click", () => showPage(page - 1));
  next.addEventListener("click", () => showPage(page + 1));
  pageSelect.addEventListener("change", () => showPage(Number(pageSelect.value)));
  sizeSelect.addEventListener("change", () => {
    const first = page * pageSize;
    pageSize = Number(sizeSelect.value);
    showPage(Math.floor(first / pageSize));
  });
  filter();
  const opened = rows.find(row => row.open);
  if (viewport && opened) viewport.scrollTop += opened.getBoundingClientRect().top - viewport.getBoundingClientRect().top;
}

for (const list of document.querySelectorAll("[data-filter-list]")) enhanceList(list);

})();
