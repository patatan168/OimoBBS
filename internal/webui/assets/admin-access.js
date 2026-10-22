/* 管理者の役割・担当板・権限を選択して要約する。 */
"use strict";

(() => {
/** 役割・担当板・追加権限の選択を保存前に要約し、サイト管理者の全板範囲を示す。 */
function enhanceAdministratorAccess(form) {
  const role = form.elements.namedItem("role");
  const summary = form.querySelector("[data-admin-access-summary]");
  const boards = form.querySelectorAll('input[name="board_ids"]');
  const permissions = form.querySelectorAll('input[name="extra_permissions"]');
  for (const input of [...boards, ...permissions]) input.dataset.manualChecked = String(input.checked && !input.disabled);
  function render() {
    const site = role.value === "site_admin";
    const included = site || role.value === "board_admin";
    for (const [inputs, automatic] of [[boards, site], [permissions, included]]) {
      for (const input of inputs) {
        if (!input.disabled) input.dataset.manualChecked = String(input.checked);
        input.disabled = automatic;
        input.checked = automatic || input.dataset.manualChecked === "true";
      }
    }
    const count = Array.from(boards).filter(input => input.checked).length;
    const selected = Array.from(permissions).filter(input => input.checked).map(input => input.dataset.label);
    const scope = site ? "全板・サイト全体（追加した板も含む）" : `担当板 ${count} 件`;
    const enabled = form.elements.namedItem("enabled").value === "true";
    summary.textContent = `保存する設定：${role.selectedOptions[0].textContent} ／ ${scope} ／ ${enabled ? "有効" : "無効"}。${included ? "ロールに含まれる権限" : "追加権限"}：${selected.join("、") || "なし"}。`;
    if (!site && count === 0) summary.textContent += " 担当板がないため、板の閲覧・操作はできません。";
  }
  form.addEventListener("change", render);
  render();
}

for (const form of document.querySelectorAll("[data-admin-access]")) enhanceAdministratorAccess(form);


})();
