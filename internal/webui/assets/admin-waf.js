/* WAF設定の有効範囲と、保存後の動作を表示する。 */
"use strict";

(() => {
/** 停止中のWAF上限を編集不可にし、送信時も未使用の設定値を保持する。JSなしでは通常フォームを使う。 */
function enhanceWAFLimits(form) {
  const waf = form.elements.namedItem("enabled");
  const traffic = form.elements.namedItem("traffic_enabled");
  const client = form.elements.namedItem("client_enabled");
  function render() {
    const enabled = waf.value === "true" && traffic.value === "true";
    const states = {inspection:waf.value === "true", global:enabled, client:enabled && client.value === "true"};
    for (const badge of form.querySelectorAll("[data-waf-result]")) {
      const active = states[badge.dataset.wafResult];
      badge.textContent = active ? "ON" : "OFF";
      badge.classList.toggle("admin-badge-on", active);
      badge.classList.toggle("admin-badge-off", !active);
    }
    const note = form.querySelector("[data-waf-result-note]");
    if (note) {
      const reason = waf.value !== "true" ? "WAFがOFFのため、アクセス上限も停止します。"
        : !enabled ? "大量アクセス制限がOFFのため、アクセス上限は停止します。"
        : client.value !== "true" ? "回線別の上限は停止し、全体の上限だけを使います。" : "すべての上限を使います。";
      note.textContent = reason + " 停止中の選択・数値も保持します。";
    }
    traffic.disabled = waf.value !== "true";
    client.disabled = !enabled;
    for (const group of form.querySelectorAll("[data-waf-limit]")) {
      const disabled = !enabled || group.dataset.wafLimit === "client" && client.value !== "true";
      group.setAttribute("aria-disabled", String(disabled));
      for (const input of group.querySelectorAll("input")) input.disabled = disabled;
    }
  }
  form.addEventListener("change", render);
  form.addEventListener("formdata", event => {
    for (const input of form.querySelectorAll("input:disabled, select:disabled")) {
      event.formData.append(input.name, input.value);
    }
  });
  render();
}
for (const form of document.querySelectorAll("#waf-settings")) enhanceWAFLimits(form);


})();
