/* 板の回線上書きと表示コマンドの編集を補助する。 */
"use strict";

(() => {
/** 板の回線上書きを通常の入力行で追加する。既存の行と値は保持する。 */
function enhanceBoardNetworkRows(fieldset) {
  const rows = fieldset.querySelector("[data-network-rows]");
  const add = fieldset.querySelector("[data-network-add]");
  if (!rows || !add || !rows.firstElementChild) return;
  function clear(row) {
    for (const input of row.querySelectorAll("input")) input.value = "";
    row.querySelector("select").value = "unknown";
  }
  function allowRemoval(row) {
    const remove = row.querySelector("[data-network-remove]");
    if (!remove) return;
    remove.hidden = false;
    remove.addEventListener("click", () => {
      if (rows.children.length === 1) clear(row);
      else row.remove();
      add.disabled = rows.children.length >= 512;
    });
  }
  for (const row of rows.children) allowRemoval(row);
  add.hidden = false;
  add.disabled = rows.children.length >= 512;
  add.addEventListener("click", () => {
    if (rows.children.length >= 512) return;
    const row = rows.firstElementChild.cloneNode(true);
    clear(row);
    allowRemoval(row);
    rows.append(row);
    add.disabled = rows.children.length >= 512;
    row.querySelector("input").focus();
  });
}

for (const fieldset of document.querySelectorAll("[data-board-network-rows]")) enhanceBoardNetworkRows(fieldset);
/** 板の表示条件でコマンド候補を絞り、表示中のグループを一括で切り替える。保存前の変更にも追随する。 */
function enhanceDisplayCommands(root) {
  const form = root.closest("form");
  const id = form.querySelector('select[name="id_mode"]');
  const slip = form.querySelector('select[name="slip_mode"]');
  const options = [...root.querySelectorAll("[data-command-option]")];
  const modes = [...slip.options].map(option => option.value);
  function render() {
    for (const option of options) {
      const command = option.querySelector('input[name="display_commands"]').value.split(":");
      const extend = command[0] === "!extend";
      const target = command[0] === "!slip" ? command[1] : extend ? command[2] : "default";
      option.hidden = target !== "default" && modes.indexOf(target) < modes.indexOf(slip.value) || extend && command[1] === "none" && id.value === "required";
    }
    for (const group of root.querySelectorAll("[data-command-mode]")) {
      group.hidden = [...group.querySelectorAll("[data-command-option]")].every(option => option.hidden);
    }
  }
  for (const button of root.querySelectorAll("[data-command-bulk]")) {
    button.hidden = false;
    button.addEventListener("click", () => {
      const group = button.closest("[data-command-group]");
      for (const option of group.querySelectorAll("[data-command-option]")) {
        if (option.hidden) continue;
        const input = option.querySelector('input[name="display_commands"]');
        input.checked = button.dataset.commandBulk === "on";
        input.dispatchEvent(new Event("change", {bubbles:true}));
      }
    });
  }
  id.addEventListener("change", render);
  slip.addEventListener("change", render);
  render();
}
for (const root of document.querySelectorAll("[data-display-commands]")) enhanceDisplayCommands(root);


})();
