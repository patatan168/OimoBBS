/* 投稿規制の条件に合わせ、使う入力欄だけを表示する。 */
"use strict";

(() => {
/** 規制の条件に合わせて回線種別の選択欄を表示する。JSなしでもサーバ側で正規化する。 */
function enhanceRuleNetworkChoices(form) {
  function render() {
    for (const name of ["field", "extra_field"]) {
      const selector = form.elements.namedItem(name);
      if (!selector) continue;
      const line = selector.value === "line";
      const operator = form.elements.namedItem(name === "field" ? "operator" : "extra_operator");
      const allowed = ({auto:["exact"],ip:["exact"],network:["cidr"],token:["exact"],line:["exact"],host:["exact","suffix"],domain:["exact","suffix"],body:["exact","contains","compact_exact","regexp"]})[selector.value] || ["exact","contains","regexp"];
      if (operator) {
        for (const option of operator.options) option.disabled = !allowed.includes(option.value);
        if (!allowed.includes(operator.value)) operator.value = allowed[0];
      }
      if (name === "field") {
        const labels = {auto:"規制するIPアドレス / CIDR",host:"規制する投稿元ホスト名",ua:"規制するUser-Agent",token:"規制する匿名主体HMAC"};
        const hints = {auto:"例：192.0.2.10、192.0.2.0/24。CIDRは範囲の先頭IPを指定します。",host:"例：customer.example.jp。example.jpと配下全体ならサブドメインの照合を選択。ワイルドカード（*）やURLは不要です。",ua:"User-Agentの文字列をそのまま入力します。例：ExampleBrowser/1.0。変更可能なので補助規制として使用してください。",token:"匿名主体HMACの64桁の小文字16進数。公開ID・IPのHMACは使えません。レスの記録から選ぶと自動入力できます。"};
        const label = form.querySelector("[data-rule-target-label]");
        const hint = form.querySelector("[data-rule-target-hint]");
        if (label) label.textContent = labels[selector.value] || "規制する値";
        if (hint) hint.textContent = hints[selector.value] || "選んだ項目に一致させる文字列を入力してください。";
        const effect = form.elements.namedItem("effect");
        if (effect) {
          const denyOnly = ["host","line"].includes(selector.value) || ["host","line"].includes(form.elements.namedItem("extra_field")?.value);
          for (const option of effect.options) option.disabled = denyOnly && option.value !== "deny";
          if (effect.selectedOptions[0]?.disabled) effect.value = "deny";
          for (const field of ["refill_seconds","burst","window_limit"]) { const input = form.elements.namedItem(field); if (input) input.disabled = effect.value !== "rate_override"; }
          const allowedIDs = form.elements.namedItem("allow_rule_ids"); if (allowedIDs) allowedIDs.disabled = effect.value !== "allow_rule_ids";
        }
      }
      const textLabel = form.querySelector(`[data-rule-text="${name}"]`);
      const lineLabel = form.querySelector(`[data-rule-line="${name}"]`);
      if (!textLabel || !lineLabel) continue;
      textLabel.hidden = line;
      lineLabel.hidden = !line;
      textLabel.querySelector("input").required = !line && selector.value !== "none";
    }
  }
  form.addEventListener("change", render);
  render();
}
for (const form of new Set(Array.from(document.querySelectorAll("[data-rule-line]"), field => field.closest("form")))) enhanceRuleNetworkChoices(form);


})();
