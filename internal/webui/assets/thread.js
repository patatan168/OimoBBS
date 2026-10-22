/* 公開スレッドのレス番号移動と返信リンクだけを補助する。 */
"use strict";

(() => {
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


})();
