/** 日本時間のカレンダー入力と期間・期限の選択を補助する。送信と保存は利用者の確定操作に任せる。 */
(() => {
  "use strict";
  const DAY = 86400000;
  const JST = 9 * 3600000;
  const controls = new Map();
  const clocks = new WeakMap();

  /** サーバーが画面を作った時刻を基準に、クリックまでの経過時間を加える。端末時計は使わない。 */
  function currentTime(element) {
    if (!clocks.has(element)) {
      const anchor = Date.parse(element.dataset.dateNow);
      if (!Number.isFinite(anchor)) return null;
      clocks.set(element, {anchor, started: performance.now()});
    }
    const clock = clocks.get(element);
    return new Date(clock.anchor + performance.now() - clock.started);
  }

  /** 絶対時刻を、日本時間の秒単位のカレンダー値へ変換する。 */
  function localValue(date) {
    return new Date(date.getTime() + JST).toISOString().slice(0, 19);
  }

  /** タイムゾーン付き送信値は保持し、操作用カレンダーを別に表示する。未編集のns精度も維持する。 */
  function enhanceDateField(input) {
    const initial = input.value || input.getAttribute("value") || "";
    const format = input.dataset.dateFormat || "local";
    input.dataset.dateFormat = format;
    const control = document.createElement("input");
    control.type = "datetime-local";
    control.lang = "ja";
    control.step = "1";
    control.required = input.required;
    control.dataset.dateControl = input.name;
    for (const attribute of ["aria-describedby", "aria-label", "id"]) {
      if (input.hasAttribute(attribute)) control.setAttribute(attribute, input.getAttribute(attribute));
    }
    input.removeAttribute("id");
    const sync = () => {
      const parsed = Date.parse(input.value + (format === "local" && input.value ? "+09:00" : ""));
      control.value = input.value && Number.isFinite(parsed) ? localValue(new Date(parsed)) : "";
    };
    input.type = "hidden";
    input.value = initial;
    sync();
    input.after(control);
    input.addEventListener("change", sync);
    control.addEventListener("input", () => {
      if (control.validity.badInput) return;
      const parsed = control.value ? Date.parse(control.value + "+09:00") : 0;
      if (!Number.isFinite(parsed)) { control.setCustomValidity("有効な日付と時刻を指定してください。"); return; }
      control.setCustomValidity("");
      input.value = control.value ? (format === "rfc3339" ? new Date(parsed).toISOString() : control.value) : "";
      input.dispatchEvent(new Event("input", {bubbles: true}));
      input.dispatchEvent(new Event("change", {bubbles: true}));
    });
    controls.set(input, control);
  }

  /** 元の送信欄と表示欄を同時に更新し、他のフォーム補助にも変更を通知する。 */
  function setField(input, date) {
    input.value = date ? (input.dataset.dateFormat === "rfc3339" ? date.toISOString() : localValue(date)) : "";
    input.dispatchEvent(new Event("input", {bubbles: true}));
    input.dispatchEvent(new Event("change", {bubbles: true}));
  }

  /** 今日・昨日は日本時間の暦日、直近の日数は現在時刻からの経過期間として入力する。 */
  function enhanceRange(toolbar) {
    const form = toolbar.closest("form");
    const from = form?.elements.namedItem("from");
    const to = form?.elements.namedItem(toolbar.dataset.dateEnd);
    if (!(from instanceof HTMLInputElement) || !(to instanceof HTMLInputElement) || !currentTime(toolbar)) return;
    const buttons = [...toolbar.querySelectorAll("[data-date-period]")];
    const resetSelection = () => buttons.forEach(button => button.setAttribute("aria-pressed", "false"));
    for (const input of [from, to]) {
      input.addEventListener("input", resetSelection);
      controls.get(input)?.addEventListener("input", resetSelection);
    }
    for (const button of buttons) {
      const period = button.dataset.datePeriod;
      if (period === "clear" && (from.required || to.required)) { button.hidden = true; continue; }
      button.setAttribute("aria-pressed", "false");
      button.addEventListener("click", () => {
        const now = currentTime(toolbar);
        let start = null;
        let end = null;
        if (period !== "clear") {
          end = now;
          const local = new Date(now.getTime() + JST);
          const midnight = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate()) - JST;
          if (period === "today") start = new Date(midnight);
          else if (period === "yesterday") { start = new Date(midnight - DAY); end = new Date(midnight); }
          else start = new Date(end.getTime() - Number(period) * DAY);
        }
        setField(from, start);
        setField(to, end);
        button.setAttribute("aria-pressed", "true");
      });
    }
    toolbar.hidden = false;
  }

  /** 期限の候補だけを挿入し、必須欄を空にする操作や保全上限を越える延長候補は表示しない。 */
  function enhanceDeadline(input) {
    if (!currentTime(input)) return;
    const kind = input.dataset.dateKind;
    const toolbar = document.createElement("span");
    toolbar.className = "date-shortcuts";
    toolbar.setAttribute("role", "group");
    toolbar.setAttribute("aria-label", "期限の入力補助");
    const base = Date.parse(input.dataset.dateBase || "");
    const options = (kind === "hold" ? [7, 30, 90, 180] : [1, 7, 30, 365]).map(days => [days, `${days}日${Number.isFinite(base) ? "延長" : "後"}`]);
    if (!input.required) options.push([null, kind === "hold" ? "既定の30日" : "期限なし"]);
    const refresh = () => {
      const now = currentTime(input);
      for (const [button, days] of actions) {
        const at = new Date(Math.max(now.getTime(), Number.isFinite(base) ? base : 0) + (days || 0) * DAY);
        button.disabled = days !== null && input.dataset.dateMaxDays && at.getTime() > now.getTime() + Number(input.dataset.dateMaxDays) * DAY;
        if (button.disabled) button.title = `現在から${input.dataset.dateMaxDays}日以内で指定してください。`;
      }
    };
    const actions = options.map(([days, label]) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      button.addEventListener("click", () => {
        refresh();
        if (button.disabled) return;
        const now = currentTime(input);
        const date = days === null ? null : new Date(Math.max(now.getTime(), Number.isFinite(base) ? base : 0) + days * DAY);
        setField(input, date);
      });
      toolbar.append(button);
      return [button, days];
    });
    refresh();
    (input.closest("label") || input).after(toolbar);
    input.addEventListener("focus", refresh);
  }

  for (const input of document.querySelectorAll("input[data-date-format],input[data-date-kind]")) enhanceDateField(input);
  for (const toolbar of document.querySelectorAll("[data-date-range]")) enhanceRange(toolbar);
  for (const input of document.querySelectorAll("input[data-date-kind]")) enhanceDeadline(input);
  for (const hint of document.querySelectorAll("[data-date-guidance]")) hint.hidden = false;
})();
