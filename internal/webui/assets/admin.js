/* 管理画面専用の入力・表示補助。通常の公開閲覧では読み込まない。 */
"use strict";

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

/** 管理画面のAPIと遷移先を設定された隠しパスに揃える。 */
function adminURL(path) {
  return (document.querySelector('meta[name="oimo-admin-base"]')?.content || "") + path;
}

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

/** 国の選択肢へブラウザの国名を添える。コードと通常フォームはJSなしでも使える。 */
function enhanceCountryNames() {
  if (typeof Intl.DisplayNames !== "function") return;
  const names = new Intl.DisplayNames(["ja"], { type: "region" });
  for (const label of document.querySelectorAll("[data-country-code]")) {
    const code = label.dataset.countryCode;
    label.textContent = code + " · " + names.of(code);
  }
}
enhanceCountryNames();

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
for (const fieldset of document.querySelectorAll("[data-board-network-rows]")) enhanceBoardNetworkRows(fieldset);
for (const form of new Set(Array.from(document.querySelectorAll("[data-rule-line]"), field => field.closest("form")))) enhanceRuleNetworkChoices(form);

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
