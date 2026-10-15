#!/usr/bin/env bash
# Dockerなしの初期登録をGoの検査器へ渡し、パスワードを非表示で入力する。
set +x
set -euo pipefail
umask 077
setup_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
setup_go=(go)
if ! command -v go >/dev/null || [[ $(go version 2>/dev/null) != 'go version go1.27.2 '* ]]; then
  if ! command -v mise >/dev/null; then
    echo 'Go1.27.2を用意してください。' >&2
    exit 1
  fi
  setup_go=(mise exec -- go)
fi
if [[ $(cd -- "$setup_root" && "${setup_go[@]}" version) != 'go version go1.27.2 '* ]]; then
  echo 'Go1.27.2を用意してください。mise利用時は mise install を実行します。' >&2
  exit 1
fi
setup_goroot=$(cd -- "$setup_root" && "${setup_go[@]}" env GOROOT)
export PATH="$setup_goroot/bin:$PATH"
setup_stdin=false
setup_help=false
for setup_arg in "$@"; do
  case "$setup_arg" in
    --password-stdin) setup_stdin=true ;;
    --help|-h|-help) setup_help=true ;;
  esac
done
setup_temp=$(mktemp -d)
# cleanup はこの実行が作成した一時バイナリだけを回収する。
cleanup() { rm -rf -- "$setup_temp"; }
trap cleanup EXIT
(cd -- "$setup_root" && CGO_ENABLED=0 "${setup_go[@]}" build -o "$setup_temp/setup" ./tools/setup)
if "$setup_help"; then
  "$setup_temp/setup" --source-root "$setup_root" "$@"
  exit 0
fi
if ! "$setup_stdin"; then
  if [[ ! -t 0 ]]; then
    echo '非対話実行では --password-stdin を指定してください。' >&2
    exit 1
  fi
  IFS= read -r -s -p '管理者パスワード: ' setup_secret
  printf '\n' >&2
  IFS= read -r -s -p '管理者パスワード（確認）: ' setup_confirmation
  printf '\n' >&2
  if [[ "$setup_secret" != "$setup_confirmation" ]]; then
    echo 'パスワードが一致しません。' >&2
    exit 1
  fi
  printf '%s\n' "$setup_secret" | "$setup_temp/setup" --source-root "$setup_root" "$@" &
  setup_pid=$!
  unset setup_secret setup_confirmation
else
  "$setup_temp/setup" --source-root "$setup_root" "$@" <&0 &
  setup_pid=$!
fi
# stop_setup は起動後のサーバーへ終了信号を転送し、停止完了まで待つ。
stop_setup() {
  kill -s "$1" "$setup_pid" 2>/dev/null || true
  wait "$setup_pid"
  exit "$?"
}
trap 'stop_setup TERM' TERM
trap 'stop_setup TERM' INT
wait "$setup_pid"
