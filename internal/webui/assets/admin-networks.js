/* 回線分類の取得設定と更新状況を表示する。 */
"use strict";

(() => {
/** 取得方法に応じて入力欄を絞り、未使用の値も通常フォームとして送る。 */
function enhanceNetworkSource(form) {
  const kind = form.querySelector("[data-network-source-kind]");
  if (!kind) return;
  function render() {
    for (const field of form.querySelectorAll("[data-network-source-field]")) {
      const type = field.dataset.networkSourceField;
      field.hidden = type === "asn" ? kind.value !== "asn" : type === "csv" ? kind.value !== "csv" : ["csv", "japan", "vpn", "countries"].includes(kind.value);
    }
  }
  kind.addEventListener("change", render);
  render();
}

/** 更新状況だけを有界に確認し、保存が終わったら版と編集フォームを一緒に読み直す。 */
async function watchNetworkUpdate(element) {
  const original = element.dataset.attempt;
  let seenRunning = false;
  for (let count = 0; count < 45; count++) {
    await new Promise(resolve => setTimeout(resolve, 2000));
    try {
      const response = await fetch(adminURL("/api/v1/networks"), { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) break;
      const { data } = await response.json();
      seenRunning ||= data.running;
      if ((String(data.attempt_ns) !== original || seenRunning) && !data.running) {
        location.replace(adminURL("/networks"));
        return;
      }
    } catch {
      break;
    }
  }
  element.textContent = "最新の状態を表示して、更新結果を確認してください。";
}
for (const form of document.querySelectorAll("[data-network-source-form]")) enhanceNetworkSource(form);
for (const status of document.querySelectorAll("[data-network-poll]")) watchNetworkUpdate(status);

/** 更新方式に必要な入力だけを表示・送信し、非表示の入力エラーで保存を妨げない。 */
function enhanceNetworkSchedule(form) {
  const mode = form.querySelector("[data-network-schedule-mode]");
  if (!mode) return;
  function render() {
    for (const field of form.querySelectorAll("[data-network-schedule-field]")) {
      const kind = field.dataset.networkScheduleField;
      const active = kind === "time" ? mode.value !== "interval" : mode.value === kind;
      field.hidden = !active;
      for (const input of field.querySelectorAll('input,select')) input.disabled = !active;
      for (const input of field.querySelectorAll('input[type="number"],input[type="time"]')) input.required = active;
    }
  }
  mode.addEventListener("change", render);
  render();
}
for (const form of document.querySelectorAll("[data-network-schedule-form]")) enhanceNetworkSchedule(form);
})();
