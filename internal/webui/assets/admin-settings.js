/* 編集した設定の確認と、詳細項目への移動を補助する。 */
"use strict";

(() => {
/** 設定の入力値を変更せず、表示名と比較用の値を項目ごとにまとめる。 */
function settingsSnapshot(form) {
  const groups = new Map();
  for (const field of form.querySelectorAll('input[name], select[name], textarea[name]')) {
    if (["hidden", "password", "submit", "button"].includes(field.type)) continue;
    if (!groups.has(field.name)) groups.set(field.name, []);
    groups.get(field.name).push(field);
  }
  const snapshot = new Map();
  for (const [name, fields] of groups) {
    const label = fields[0].labels?.[0]?.cloneNode(true);
    label?.querySelectorAll("input, select, textarea, small, .field-hint").forEach(node => node.remove());
    const context = fields[0].closest("fieldset")?.querySelector(":scope > legend")?.textContent.trim();
    const title = (context ? context + " — " : "") + (({allow_country:"投稿を許可する国", display_commands:"投稿コマンドの許可"})[name] || label?.textContent.trim().replace(/\s+/g, " ") || "追加した設定");
    const raw = fields.map(field => [field.value, field.type === "checkbox" || field.type === "radio" ? field.checked : null]);
    const values = fields.filter(field => !["checkbox", "radio"].includes(field.type) || field.checked).map(field => field.selectedOptions ? field.selectedOptions[0]?.textContent.trim() : field.value);
    let text = values.join("、") || "未設定";
    if (fields.length === 1 && fields[0].type === "checkbox") text = fields[0].checked ? "チェックあり" : "チェックなし";
    if (fields.length > 1 && fields.every(field => field.type === "checkbox")) text = `${values.length}項目を選択：${values.join("、")}`;
    snapshot.set(name, {title, raw:JSON.stringify(raw), text:text.length > 160 ? text.slice(0,160) + "…" : text});
  }
  return snapshot;
}

/** 編集開始時との違いを保存前に表示し、閉じた詳細内の入力エラーを開く。値や送信内容は変えない。 */
function enhanceSettingsReview(form) {
  const review = form.querySelector("[data-settings-review]");
  if (!review) return;
  const initial = settingsSnapshot(form);
  const count = review.querySelector("[data-settings-count]");
  const changes = review.querySelector("[data-settings-changes]");
  const list = review.querySelector("[data-settings-change-list]");
  function render() {
    const current = settingsSnapshot(form);
    const names = new Set([...initial.keys(), ...current.keys()]);
    const edited = [...names].filter(name => initial.get(name)?.raw !== current.get(name)?.raw);
    review.dataset.edited = String(edited.length > 0);
    count.textContent = edited.length ? `この画面で${edited.length}項目を編集しています。まだ保存されていません。` : "この画面を開いてから、まだ編集していません。";
    changes.hidden = edited.length === 0;
    list.replaceChildren();
    for (const name of edited) {
      const before = initial.get(name);
      const after = current.get(name);
      const item = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = (after || before).title + "：";
      item.append(title, document.createTextNode(`${before?.text || "未設定"} → ${after?.text || "削除"}`));
      list.append(item);
    }
  }
  form.addEventListener("input", render);
  form.addEventListener("change", render);
  // 回線行の追加・削除は入力イベントを発生しないため、行構造だけを観測する。
  const rows = form.querySelector("[data-network-rows]");
  if (rows) new MutationObserver(render).observe(rows, {childList:true});
  form.addEventListener("click", event => {
    if (event.target.closest("[data-network-remove]")) render();
  });
  form.addEventListener("invalid", event => {
    for (let node = event.target.parentElement; node && node !== form; node = node.parentElement) {
      if (node.tagName === "DETAILS") node.open = true;
    }
  }, true);
  review.hidden = false;
  render();
}
for (const form of document.querySelectorAll("[data-settings-form]")) enhanceSettingsReview(form);

/** 設定項目へのページ内リンクでは、対象の詳細欄も開く。通常のリンク動作は維持する。 */
for (const link of document.querySelectorAll('.settings-nav a[href^="#"]')) {
  link.addEventListener("click", () => {
    const target = document.getElementById(link.hash.slice(1));
    if (target?.tagName === "DETAILS") target.open = true;
  });
}

})();
