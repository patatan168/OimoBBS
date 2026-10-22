/** 操作候補を画面内で検索し、選んだ操作名を閉じた状態にも表示する。 */
(() => {
  const picker = document.querySelector("[data-audit-action-picker]");
  if (!picker) return;
  const details = picker.querySelector("details");
  const summary = details.querySelector("summary");
  const selected = picker.querySelector("[data-audit-selected]");
  const search = picker.querySelector("[data-audit-search]");
  const status = picker.querySelector("[data-audit-search-status]");
  const choices = [...picker.querySelectorAll(".audit-action-option")].map(label => ({
    label, radio: label.querySelector("input"), title: label.querySelector("span").textContent,
  }));
  const normalize = value => value.normalize("NFKC").toLocaleLowerCase("ja").replaceAll("キャップ", "cap").trim();
  /** 入力した各語を含む候補だけを残し、候補件数を読み上げる。通信は行わない。 */
  function filterChoices() {
    const terms = normalize(search.value).split(/\s+/).filter(Boolean);
    let count = 0;
    for (const choice of choices) {
      const text = normalize(choice.title);
      choice.label.hidden = !terms.every(term => text.includes(term));
      if (!choice.label.hidden) count++;
    }
    status.textContent = count ? `${count}件の候補` : "該当する操作がありません。別の言葉で検索してください。";
  }
  /** 選択値と表示名を揃えて候補を閉じる。送信はフォームの確定操作に任せる。 */
  function choose(choice) {
    choice.radio.checked = true;
    selected.textContent = choice.title;
    details.open = false;
    summary.focus();
  }
  picker.querySelector("[data-audit-search-label]").hidden = false;
  search.addEventListener("input", filterChoices);
  for (const choice of choices) {
    choice.radio.addEventListener("change", () => choose(choice));
    choice.radio.addEventListener("click", () => choose(choice));
  }
  summary.addEventListener("click", () => {
    if (details.open) return;
    search.value = "";
    filterChoices();
  });
  details.addEventListener("toggle", () => {
    if (!details.open) return;
    if (document.activeElement === summary) search.focus();
  });
  search.addEventListener("keydown", event => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    const choice = choices.find(choice => !choice.label.hidden);
    if (choice) choose(choice);
  });
  details.addEventListener("keydown", event => {
    if (event.key !== "Escape") return;
    event.preventDefault();
    details.open = false;
    summary.focus();
  });
})();
