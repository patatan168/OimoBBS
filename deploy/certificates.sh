#!/bin/sh
# 初回取得に成功するまで待ち、その後は12時間ごとに更新を確認する。
set -eu
trap 'exit 0' TERM INT
while ! certbot certonly --standalone --non-interactive --agree-tos \
  --register-unsafely-without-email --cert-name patatanmc.f5.si \
  -d patatanmc.f5.si --keep-until-expiring \
  --deploy-hook 'python3 /deploy/install-certificate.py'; do
  echo '証明書を取得できません。DNSとTCP 80の転送を確認してください。5分後に再試行します。' >&2
  sleep 300 & wait $!
done
# 既存証明書を再利用する起動でも、配信用volumeを復元できるようにする。
RENEWED_LINEAGE=/etc/letsencrypt/live/patatanmc.f5.si python3 /deploy/install-certificate.py
while :; do
  sleep 43200 & wait $!
  certbot renew --non-interactive --deploy-hook 'python3 /deploy/install-certificate.py' || echo '証明書更新に失敗しました。次回再試行します。' >&2
done
