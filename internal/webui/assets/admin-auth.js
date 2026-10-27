/* ログイン・再認証・認証設定だけでパスキーとOTPを扱う。 */
"use strict";

(() => {
/** WebAuthnのbase64url表現をブラウザAPI用のバイト列へ変換する。 */
function passkeyBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64), char => char.charCodeAt(0));
}

/** WebAuthn応答のバイト列をサーバーが検証するbase64urlへ変換する。 */
function passkeyBase64(value) {
  if (value == null) return null;
  return btoa(Array.from(new Uint8Array(value), byte => String.fromCharCode(byte)).join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 同一Originへだけ送信し、失敗時は認証データを表示せず固定の案内を返す。 */
async function passkeyRequest(path, csrf, body) {
  const response = await fetch(adminURL(`/api/v1/passkey/${path}`), {
    method: "POST", credentials: "same-origin", redirect: "error",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const failure = await response.json().catch(() => null);
    const code = failure?.error?.code;
    if (code === "REAUTHENTICATION_REQUIRED") {
      document.querySelector("[data-passkey-reauth-required]")?.removeAttribute("hidden");
      throw new Error("再認証の有効期限が切れました。「再認証して登録・削除へ進む」から本人確認してください。");
    }
    if (code === "CSRF_REJECTED") throw new Error("画面の認証情報が無効になりました。ページを再読み込みしてやり直してください。");
    if (code === "ORIGIN_REJECTED") throw new Error("管理画面の接続元を確認できませんでした。設定された管理画面のURLで開き直してください。");
    if (response.status === 403) throw new Error("パスキーの操作が拒否されました。管理画面のアクセス設定を確認してください。");
    if (response.status === 429) throw new Error("試行回数が多いため、1分以上待ってからやり直してください。");
    throw new Error("パスキーを確認できませんでした。ページを再読み込みしてやり直してください。");
  }
  return response.json();
}

/** 登録または認証を実行し、ブラウザの公開鍵応答を一度限りのチャレンジへ返す。 */
async function runPasskey(kind, csrf, input) {
  if (!window.isSecureContext || !window.PublicKeyCredential) throw new Error("このブラウザではパスキーを利用できません。HTTPSまたはlocalhostで開いてください。");
  const options = await passkeyRequest(`${kind}/begin`, csrf, input);
  const publicKey = options.publicKey;
  publicKey.challenge = passkeyBytes(publicKey.challenge);
  if (publicKey.user) publicKey.user.id = passkeyBytes(publicKey.user.id);
  for (const field of ["allowCredentials", "excludeCredentials"]) {
    for (const credential of publicKey[field] || []) credential.id = passkeyBytes(credential.id);
  }
  const credential = kind === "register"
    ? await navigator.credentials.create({ publicKey })
    : await navigator.credentials.get({ publicKey });
  const response = { clientDataJSON: passkeyBase64(credential.response.clientDataJSON) };
  if (kind === "register") {
    response.attestationObject = passkeyBase64(credential.response.attestationObject);
    response.transports = credential.response.getTransports?.() || [];
  } else {
    response.authenticatorData = passkeyBase64(credential.response.authenticatorData);
    response.signature = passkeyBase64(credential.response.signature);
    response.userHandle = passkeyBase64(credential.response.userHandle);
  }
  return passkeyRequest(`${kind}/finish`, csrf, {
    id: credential.id, rawId: passkeyBase64(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(), response,
  });
}

/** 二重送信を抑止し、認証キャンセルや失敗を画面の読み上げ領域へ通知する。 */
async function passkeyAction(button, action) {
  const status = document.querySelector("[data-passkey-status]");
  button.disabled = true;
  status.textContent = "端末でパスキーを確認してください。";
  try { await action(); }
  catch (error) { status.textContent = error.name === "NotAllowedError" ? "パスキーの操作がキャンセルされたか、時間切れになりました。" : error.message; }
  finally { button.disabled = false; }
}

for (const button of document.querySelectorAll("[data-passkey-login], [data-passkey-reauth]")) {
  button.addEventListener("click", () => passkeyAction(button, async () => {
    const login = button.hasAttribute("data-passkey-login");
    const result = await runPasskey(login ? "login" : "reauth", button.dataset.csrf, {});
    location.assign(adminURL(login ? result.redirect : button.dataset.return || "/"));
  }));
}
for (const manager of document.querySelectorAll("[data-passkey-manager]")) {
  const form = manager.querySelector("[data-passkey-register]");
  form?.addEventListener("submit", event => {
    event.preventDefault();
    passkeyAction(form.querySelector("button"), async () => {
      await runPasskey("register", manager.dataset.csrf, { name: form.elements.namedItem("name").value });
      location.reload();
    });
  });
  for (const button of manager.querySelectorAll("[data-passkey-remove]")) {
    button.addEventListener("click", () => passkeyAction(button, async () => {
      if (!window.confirm("このパスキーを削除すると、すべての端末でログアウトします。削除しますか？")) return;
      const result = await passkeyRequest("remove/finish", manager.dataset.csrf, { id: button.dataset.passkeyRemove });
      location.assign(adminURL(result.redirect));
    }));
  }
}

/** OTP専用APIへ同一Origin・CSRF付きで送信する。秘密・コードをエラーへ再掲しない。 */
async function otpRequest(path, csrf, body) {
  const response = await fetch(adminURL(`/api/v1/otp/${path}`), {
    method: "POST", credentials: "same-origin", redirect: "error",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify(body),
  });
  const result = await response.json().catch(() => null);
  if (!response.ok) {
    const code = result?.error?.code;
    if (code === "LAST_AUTHENTICATOR") throw new Error("最後の認証手段は解除できません。先に別の手段を登録してください。");
    if (code === "STRONG_REAUTHENTICATION_REQUIRED") throw new Error("パスキーまたはパスワードとOTPで再認証してください。");
    if (code === "REAUTHENTICATION_REQUIRED") throw new Error("再認証してからやり直してください。");
    if (code === "CSRF_REJECTED") throw new Error("画面を再読み込みしてやり直してください。");
    if (response.status === 429) throw new Error("試行回数が多いため、1分以上待ってからやり直してください。");
    throw new Error("パスワードまたはOTPの確認に失敗しました。コードが使用済み・期限切れの場合は次のコードを使ってください。登録は最初からやり直してください。");
  }
  return result;
}

/** パスワードとOTPを同じ要求で送り、成功後は入力欄の秘密を消去する。 */
async function submitOTPAuthentication(button) {
  const login = button.hasAttribute("data-otp-login");
  const code = document.querySelector("[data-otp-code]");
  const password = document.querySelector('input[name="password"]');
  const body = { password: password.value, code: code.value };
  if (login) body.login = document.querySelector('input[name="login"]').value;
  const result = await otpRequest(login ? "login" : "reauth", button.dataset.csrf, body);
  code.value = "";
  password.value = "";
  location.assign(adminURL(login ? result.redirect : button.dataset.return || "/"));
}
const loginForm = document.querySelector("[data-login-form]");
if (loginForm) {
  const code = loginForm.querySelector("[data-otp-code]");
  const submit = loginForm.querySelector('button[type="submit"]');
  code.addEventListener("input", () => {
    submit.textContent = code.value ? "パスワードとOTPでログイン" : "パスワードでログイン";
  });
  loginForm.addEventListener("submit", event => {
    if (!code.value) return;
    event.preventDefault();
    passkeyAction(submit, () => submitOTPAuthentication(loginForm.querySelector("[data-otp-login]")));
  });
}
const otpReauthForm = document.querySelector("[data-otp-auth-form]");
if (otpReauthForm) otpReauthForm.addEventListener("submit", event => {
  event.preventDefault();
  const submit = otpReauthForm.querySelector("[data-otp-reauth]");
  passkeyAction(submit, () => submitOTPAuthentication(submit));
});
for (const manager of document.querySelectorAll("[data-otp-manager]")) {
  const begin = manager.querySelector("[data-otp-begin]");
  begin?.addEventListener("click", () => passkeyAction(begin, async () => {
    const result = await otpRequest("register/begin", manager.dataset.csrf, {});
    manager.querySelector("[data-otp-secret]").textContent = result.secret;
    manager.querySelector("[data-otp-uri]").href = result.uri;
    manager.querySelector("[data-otp-qr]").src = adminURL(result.qr);
    manager.querySelector("[data-otp-setup]").hidden = false;
  }));
  const finish = manager.querySelector("[data-otp-finish]");
  finish?.addEventListener("submit", event => {
    event.preventDefault();
    passkeyAction(finish.querySelector("button"), async () => {
      const result = await otpRequest("register/finish", manager.dataset.csrf, { code: finish.elements.namedItem("code").value });
      manager.querySelector("[data-otp-secret]").textContent = "";
      location.assign(adminURL(result.redirect));
    });
  });
  const remove = manager.querySelector("[data-otp-remove]");
  remove?.addEventListener("click", () => passkeyAction(remove, async () => {
    if (!window.confirm("OTPを解除すると、すべての端末でログアウトします。解除しますか？")) return;
    const result = await otpRequest("remove", manager.dataset.csrf, {});
    location.assign(adminURL(result.redirect));
  }));
}
for (const manager of document.querySelectorAll("[data-auth-policy]")) {
  const form = manager.querySelector("[data-auth-policy-form]");
  form?.addEventListener("submit", event => {
    event.preventDefault();
    const button = form.querySelector("button");
    if (!button) return;
    passkeyAction(button, async () => {
      const result = await otpRequest("policy", manager.dataset.csrf, { password_disabled: form.elements.namedItem("password_disabled").checked });
      location.assign(adminURL(result.redirect));
    });
  });
}


})();
