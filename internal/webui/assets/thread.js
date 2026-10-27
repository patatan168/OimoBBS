/* 公開スレッドのレス番号移動と、本文中の返信・HTTP(S)リンクを補助する。 */
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

/** 文末記号と対応する開き括弧がない閉じ括弧をURL末尾から除く。 */
function trimURLPunctuation(text) {
  const pairs = { ")": "(", "]": "[", "}": "{" };
  const balance = { "(": 0, "[": 0, "{": 0 };
  for (const char of text) {
    if (Object.hasOwn(balance, char)) balance[char]++;
    else if (pairs[char]) balance[pairs[char]]--;
  }
  let end = text.length;
  while (end > 0) {
    const char = text[end - 1];
    if (/[.,!?;:]/.test(char)) end--;
    else if (pairs[char] && balance[pairs[char]] < 0) {
      balance[pairs[char]]++;
      end--;
    } else break;
  }
  return text.slice(0, end);
}

/** HTTP(S)の絶対URLだけを、新しいタブで安全に開くリンクとして作る。 */
function createURLLink(text) {
  const url = trimURLPunctuation(text);
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  } catch {
    return null;
  }
  const link = document.createElement("a");
  link.textContent = url;
  link.href = url;
  link.target = "_blank";
  link.rel = "nofollow noopener noreferrer ugc";
  return link;
}

/** 返信番号とURLを一度にリンク化する。投稿文字列をHTMLとして解釈しない。 */
function enhanceResponseLinks(main) {
  for (const body of main.querySelectorAll("[data-response-body]")) {
    const text = body.textContent;
    const fragment = document.createDocumentFragment();
    let offset = 0;
    for (const match of text.matchAll(/https?:\/\/[^\s<>"'\u0000-\u001f\u007f「」『』【】〈〉《》（）、。！？]+|>>([1-9][0-9]{0,4})(?![0-9])/gi)) {
      let link;
      if (match[1]) {
        link = document.createElement("a");
        link.textContent = match[0];
        link.href = document.getElementById(match[1]) ? "#" + match[1] : main.dataset.threadBase + match[1] + "n";
      } else {
        link = createURLLink(match[0]);
      }
      if (!link) continue;
      fragment.append(document.createTextNode(text.slice(offset, match.index)));
      fragment.append(link);
      offset = match.index + link.textContent.length;
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
