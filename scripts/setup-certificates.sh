#!/usr/bin/env bash
# Linux直結HTTPS用の証明書を取得し、専用systemd timerで更新する。
set +x
set -euo pipefail
umask 077

certificate_root=/etc/oimobbs/certificates
certificate_units=/etc/systemd/system

certificate_usage() {
  cat <<'USAGE'
使い方: sudo bash scripts/setup-certificates.sh --domain bbs.example.com --email admin@example.com [--user USER]

Let’s Encryptの利用規約に同意して、証明書の取得と自動更新を設定します。
--user はOimoBBSの実行ユーザー。省略時はsudoを実行した一般ユーザーです。
Certbotがなければapt-getまたはdnfでインストールします。
公開DNSと外部からのTCP 80到達性が必要です。80番を使用中のサーバーは停止しません。
証明書・秘密鍵には、表示される同じserver.pemを指定してください。
USAGE
}

certificate_error() { echo "証明書セットアップ: $*" >&2; exit 1; }

# certificate_arguments はシェル・unitに埋め込む値を制限し、利用者を確定する。
certificate_arguments() {
  domain= email= certificate_user=${SUDO_USER:-}
  while (($#)); do
    case "$1" in
      --domain|--email|--user)
        (($# >= 2)) && [[ -n $2 ]] || certificate_error "$1 の値が必要です"
        case "$1" in
          --domain) domain=${2,,} ;;
          --email) email=$2 ;;
          --user) certificate_user=$2 ;;
        esac
        shift 2 ;;
      --help|-h) certificate_usage; exit 0 ;;
      *) certificate_error "不明なオプション: $1" ;;
    esac
  done
  [[ ${#domain} -le 200 && $domain == *.* && $domain != *[!a-z0-9.-]* ]] || certificate_error '公開DNS名を指定してください（最大200文字）'
  local label
  local -a labels
  IFS=. read -r -a labels <<< "$domain"
  [[ $domain != *. ]] || certificate_error 'ドメイン末尾のドットは省略してください'
  for label in "${labels[@]}"; do
    [[ ${#label} -le 63 && $label =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || certificate_error '不正なドメイン名です'
  done
  [[ ! $domain =~ ^[0-9.]+$ ]] || certificate_error 'IPアドレスではなく公開DNS名を指定してください'
  [[ $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || certificate_error '連絡用メールアドレスを指定してください'
  [[ -n $certificate_user && $certificate_user != -* ]] || certificate_error '--user で一般ユーザーを指定してください'
  certificate_uid=$(id -u -- "$certificate_user") || certificate_error 'ユーザーが存在しません'
  certificate_gid=$(id -g -- "$certificate_user")
  [[ $certificate_uid != 0 && $certificate_gid != 0 ]] || certificate_error 'root以外の実行ユーザーを指定してください'
  certificate_base=$certificate_root/$domain
  certificate_unit=oimobbs-cert-$domain
}

# certificate_safe_path はroot管理領域へのリンク迂回と第三者の書込みを拒否する。
certificate_safe_path() {
  local path=$1
  while [[ $path != / ]]; do
    [[ ! -L $path ]] || certificate_error "リンクは使用できません: $path"
    if [[ -e $path ]]; then
      [[ -d $path && $(stat -c %u -- "$path") == 0 ]] || certificate_error "root所有のディレクトリが必要です: $path"
      local mode
      mode=$(stat -c %a -- "$path")
      (( (8#$mode & 0022) == 0 )) || certificate_error "第三者が書込み可能です: $path"
    fi
    path=$(dirname -- "$path")
  done
}

certificate_platform() {
  [[ $(uname -s) == Linux && $EUID == 0 ]] || certificate_error 'Linuxでsudoを付けて実行してください'
  [[ -d /run/systemd/system ]] || certificate_error 'systemdが起動していません'
  command -v systemctl >/dev/null || certificate_error 'systemctlが必要です'
}

certificate_preflight() {
  certificate_platform
  certificate_safe_path "$certificate_root"
  certificate_safe_path "$certificate_units"
  certificate_safe_path "$certificate_base"
  local suffix state
  for suffix in service timer; do
    [[ ! -L $certificate_units/$certificate_unit.$suffix ]] || certificate_error '既存unitがリンクです'
    state=$(systemctl show --property=FragmentPath --value "$certificate_unit.$suffix")
    [[ -z $state || $state == "$certificate_units/$certificate_unit.$suffix" ]] || certificate_error "別のunitが登録済みです: $state"
  done
  # 自分の生成物だけ再利用する。途中失敗した場合も同じ引数で再開できる。
  if [[ -e $certificate_base/owner ]]; then
    [[ -f $certificate_base/owner && ! -L $certificate_base/owner && $(cat "$certificate_base/owner") == "$certificate_uid:$certificate_gid" ]] || certificate_error '配置済みの実行ユーザーと一致しません'
  elif [[ -e $certificate_base ]]; then
    certificate_error "既存ディレクトリは上書きしません: $certificate_base"
  fi
  for suffix in service timer; do
    if [[ -e $certificate_units/$certificate_unit.$suffix ]]; then
      [[ -f $certificate_base/owner ]] || certificate_error '既存unitは上書きしません'
      [[ $(head -n 1 "$certificate_units/$certificate_unit.$suffix") == '# Managed by OimoBBS setup-certificates.sh' ]] || certificate_error '既存unitは上書きしません'
    fi
  done
}

certificate_dependencies() {
  if ! command -v certbot >/dev/null; then
    if command -v apt-get >/dev/null; then
      apt-get update
      apt-get install -y certbot openssl
    elif command -v dnf >/dev/null; then
      dnf install -y certbot openssl
    else
      certificate_error 'CertbotとOpenSSLを導入してから再実行してください（自動導入はapt-get/dnf対応）'
    fi
  fi
  command -v openssl >/dev/null || certificate_error 'OpenSSLを導入してください'
  certificate_certbot=$(command -v certbot)
  [[ $certificate_certbot =~ ^/[a-zA-Z0-9/_.-]+$ ]] || certificate_error 'Certbotを空白・特殊文字のない絶対パスに配置してください'
}

# certificate_write はroot管理先へ一時ファイルを作り、完成した内容だけ公開する。
certificate_write() {
  local target=$1 mode=$2 temporary
  temporary=$(mktemp "${target}.XXXXXX")
  cat > "$temporary"
  chmod "$mode" "$temporary"
  mv -fT -- "$temporary" "$target"
}

# certificate_scripts は更新成功時だけ検証・権限設定・原子的なPEM差替えを行う。
certificate_scripts() {
  install -d -m 755 "$certificate_root" "$certificate_base"
  printf '%s:%s\n' "$certificate_uid" "$certificate_gid" | certificate_write "$certificate_base/owner" 600
  install -d -m 700 "$certificate_base/acme" "$certificate_base/work" "$certificate_base/logs"
  {
    printf '#!/usr/bin/env bash\n# 更新された証明書を検証し、OimoBBS向けに配置する。\nset -euo pipefail\numask 077\n'
    printf 'base=%q\ndomain=%q\nuid=%q\ngid=%q\n' "$certificate_base" "$domain" "$certificate_uid" "$certificate_gid"
    cat <<'HOOK'
[[ ${RENEWED_LINEAGE:-} == "$base/acme/live/$domain" ]] || { echo '想定外の証明書パスです' >&2; exit 1; }
openssl x509 -in "$RENEWED_LINEAGE/fullchain.pem" -noout -checkend 0
openssl verify -partial_chain -CAfile "$RENEWED_LINEAGE/fullchain.pem" \
  -purpose sslserver -verify_hostname "$domain" "$RENEWED_LINEAGE/fullchain.pem"
cert_public=$(openssl x509 -in "$RENEWED_LINEAGE/fullchain.pem" -pubkey -noout)
key_public=$(openssl pkey -in "$RENEWED_LINEAGE/privkey.pem" -pubout)
[[ $cert_public == "$key_public" ]] || { echo '証明書と秘密鍵が一致しません' >&2; exit 1; }
temporary=$(mktemp "$base/server.pem.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
cat "$RENEWED_LINEAGE/fullchain.pem" "$RENEWED_LINEAGE/privkey.pem" > "$temporary"
chmod 600 "$temporary"
chown "$uid:$gid" "$temporary"
sync -f "$temporary"
mv -fT -- "$temporary" "$base/server.pem"
sync -f "$base"
HOOK
  } | certificate_write "$certificate_base/deploy.sh" 700
  {
    printf '#!/usr/bin/env bash\n# 専用の管理領域だけを更新する。\nset -euo pipefail\n'
    printf '%q renew --non-interactive --config-dir %q --work-dir %q --logs-dir %q --deploy-hook %q\n' \
      "$certificate_certbot" "$certificate_base/acme" "$certificate_base/work" "$certificate_base/logs" "$certificate_base/deploy.sh"
    # 前回の取得成功後に配置だけ失敗しても、更新不要の周期で配置を再試行する。
    printf 'RENEWED_LINEAGE=%q %q\n' "$certificate_base/acme/live/$domain" "$certificate_base/deploy.sh"
  } | certificate_write "$certificate_base/renew.sh" 700
}

certificate_register_timer() {
  certificate_write "$certificate_units/$certificate_unit.service" 644 <<UNIT
# Managed by OimoBBS setup-certificates.sh
[Unit]
Description=OimoBBS certificate renewal ($domain)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
UMask=0077
ExecStart=$certificate_base/renew.sh
UNIT
  certificate_write "$certificate_units/$certificate_unit.timer" 644 <<UNIT
# Managed by OimoBBS setup-certificates.sh
[Unit]
Description=OimoBBS certificate renewal timer ($domain)

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1h
Persistent=true
Unit=$certificate_unit.service

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "$certificate_unit.timer"
  systemctl is-enabled --quiet "$certificate_unit.timer"
  systemctl is-active --quiet "$certificate_unit.timer"
}

certificate_main() {
  certificate_arguments "$@"
  certificate_preflight
  certificate_dependencies
  certificate_scripts
  "$certificate_certbot" certonly --standalone --non-interactive --agree-tos \
    --email "$email" --cert-name "$domain" -d "$domain" --keep-until-expiring \
    --config-dir "$certificate_base/acme" --work-dir "$certificate_base/work" \
    --logs-dir "$certificate_base/logs" --deploy-hook "$certificate_base/deploy.sh"
  # 既存証明書がまだ更新不要でも、配置と所有者を復元する。
  RENEWED_LINEAGE="$certificate_base/acme/live/$domain" "$certificate_base/deploy.sh"
  certificate_register_timer
  printf '\n証明書の取得・自動更新を設定しました。\n証明書・秘密鍵の両方に指定: %s/server.pem\n' "$certificate_base"
  printf '状態: systemctl status %s.timer --no-pager\n' "$certificate_unit"
  printf '更新試験: sudo %q renew --dry-run --run-deploy-hooks --config-dir %q --work-dir %q --logs-dir %q\n' \
    "$certificate_certbot" "$certificate_base/acme" "$certificate_base/work" "$certificate_base/logs"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  certificate_main "$@"
fi
