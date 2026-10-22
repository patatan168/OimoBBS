/* 国名の表示と検索索引を準備する。国を表示するページだけで使う。 */
"use strict";

(() => {
/** 国名を検索索引の作成前に補い、日本語名・英語名・コードで探せるようにする。JSなしではコードを表示する。 */
function enhanceCountryNames() {
  if (typeof Intl === "undefined" || typeof Intl.DisplayNames !== "function") return;
  const names = new Intl.DisplayNames(["ja"], {type:"region"});
  const english = new Intl.DisplayNames(["en"], {type:"region"});
  for (const label of document.querySelectorAll("[data-country-code]")) {
    const code = label.dataset.countryCode;
    const name = names.of(code) || code;
    label.textContent = name;
    const row = label.closest("[data-country-row]");
    if (row) row.dataset.filterText = [code, name, english.of(code) || code].join(" ");
  }
}
enhanceCountryNames();


})();
