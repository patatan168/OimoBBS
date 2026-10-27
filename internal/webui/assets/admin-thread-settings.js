/* 終了レスのプレビューを設定画面だけで表示する。 */
"use strict";

(() => {
/** 有効な終了レスと連番をその場で確認する。表示には常にtextContentを使う。 */
function enhanceEndings(form) {
  const preview = document.createElement("section");
  preview.className = "ending-preview";
  preview.setAttribute("aria-label", "終了レスのプレビュー");
  form.querySelector('button[type="submit"]').before(preview);
  const value = (name) => form.elements.namedItem(name).value;
  function render() {
    const heading = document.createElement("h2");
    heading.textContent = "新規スレッドの終了レスプレビュー";
    preview.replaceChildren(heading);
    let number = Number(value("user_post_limit"));
    if (!Number.isInteger(number) || number < 1 || number > 10000) {
      const message = document.createElement("p");
      message.textContent = "レス数上限を1〜10000で入力してください。";
      preview.append(message);
      return;
    }
    let enabled = 0;
    for (const index of [1, 2]) {
      const prefix = `ending_${index}_`;
      if (value(prefix + "enabled") !== "true") continue;
      const article = document.createElement("article");
      const title = document.createElement("h2");
      const mail = document.createElement("p");
      const body = document.createElement("pre");
      title.textContent = `${++number}：${value(prefix + "name")}`;
      mail.textContent = value(prefix + "mail") || "メール欄なし";
      body.textContent = value(prefix + "body") || "（本文を入力してください）";
      article.append(title, mail, body);
      preview.append(article);
      enabled++;
    }
    if (!enabled) {
      const message = document.createElement("p");
      message.textContent = "終了レスは挿入せず、上限到達で書き込みを終了します。";
      preview.append(message);
    }
  }
  form.addEventListener("input", render);
  form.addEventListener("change", render);
  render();
}

for (const form of document.querySelectorAll("[data-ending-settings]")) enhanceEndings(form);


})();
