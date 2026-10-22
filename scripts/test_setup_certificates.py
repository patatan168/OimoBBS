#!/usr/bin/env python3
"""ACMEとsystemdを置換し、実PEMで配置・更新・失敗時の保持を検査する。"""
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('setup-certificates.sh').resolve()


class CertificateSetupTests(unittest.TestCase):
    """ホスト設定や外部CAに触れずにセットアップと生成フックを実行する。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='oimo-certificate-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'certificates' / 'bbs.example.com'
        self.units = self.root / 'units'
        self.units.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}',
                        FIXTURE=str(self.root), COMMAND_LOG=str(self.root / 'commands'))
        self.create_certificate('bbs.example.com')
        self.mock('certbot', '''#!/bin/bash
set -eu
printf 'certbot %s\\n' "$*" >> "$COMMAND_LOG"
[[ ${FAIL_CERTBOT:-0} != 1 ]] || exit 1
[[ $1 == certonly ]] || exit 0
while (($#)); do
  case "$1" in
    --config-dir) config=$2; shift 2 ;;
    --cert-name) name=$2; shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$config/live/$name"
cp "$FIXTURE/fullchain.pem" "$FIXTURE/privkey.pem" "$config/live/$name/"
''')
        self.mock('systemctl', '''#!/bin/bash
set -eu
printf 'systemctl %s\\n' "$*" >> "$COMMAND_LOG"
[[ ${FAIL_SYSTEMCTL:-0} != 1 ]] || exit 1
# FragmentPathは未登録として返す。ローカルのunitは実ファイルで検査される。
''')

    def mock(self, name, content):
        """外部コマンドを試験専用PATHへ配置する。"""
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o700)

    def create_certificate(self, hostname):
        """ネットワークを使わず、実際の鍵と短期証明書を生成する。"""
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
                        '-keyout', str(self.root / 'privkey.pem'), '-out',
                        str(self.root / 'fullchain.pem'), '-subj', f'/CN={hostname}',
                        '-addext', f'subjectAltName=DNS:{hostname}'],
                       check=True, capture_output=True)

    def invoke(self, *arguments):
        """root・起動済みsystemdの検査だけ置換し、本体を隔離先で実行する。"""
        script = f'''source {shlex.quote(str(SCRIPT))}
certificate_root={shlex.quote(str(self.root / 'certificates'))}
certificate_units={shlex.quote(str(self.units))}
certificate_platform() {{ :; }}
certificate_safe_path() {{ [[ ! -L $1 ]]; }}
certificate_main "$@"
'''
        return subprocess.run(['bash', '-c', script, 'test', '--domain', 'bbs.example.com',
                               '--email', 'admin@example.com', '--user', str(os.getuid()),
                               *arguments], env=self.env, text=True, capture_output=True)

    def hook(self):
        """Certbotから更新成功を通知する条件で、生成フックを実行する。"""
        return subprocess.run([str(self.base / 'deploy.sh')],
                              env=dict(self.env, RENEWED_LINEAGE=str(self.base / 'acme/live/bbs.example.com')),
                              text=True, capture_output=True)

    def fingerprint(self):
        return hashlib.sha256((self.base / 'server.pem').read_bytes()).hexdigest()

    def test_setup_and_renewal(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        pem = self.base / 'server.pem'
        self.assertEqual(pem.stat().st_mode & 0o777, 0o600)
        self.assertEqual(pem.stat().st_uid, os.getuid())
        self.assertFalse(pem.is_symlink())
        self.assertEqual(pem.stat().st_nlink, 1)
        old = self.fingerprint()
        self.create_certificate('bbs.example.com')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.fingerprint(), old)
        timer = self.units / 'oimobbs-cert-bbs.example.com.timer'
        self.assertIn('Persistent=true', timer.read_text())
        self.assertIn('OnCalendar=*-*-* 00,12:00:00', timer.read_text())
        self.assertIn('is-active --quiet', (self.root / 'commands').read_text())
        subprocess.run(['bash', '-n', str(self.base / 'renew.sh')], check=True)
        subprocess.run(['bash', '-n', str(self.base / 'deploy.sh')], check=True)
        # 生成PEMを実TLS実装にも読み込ませ、証明書と秘密鍵の組を確認する。
        import ssl
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(pem, pem)

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd-analyzeが必要です')
    def test_generated_systemd_units(self):
        self.assertEqual(self.invoke().returncode, 0)
        result = subprocess.run(['systemd-analyze', 'verify',
                                 str(self.units / 'oimobbs-cert-bbs.example.com.service'),
                                 str(self.units / 'oimobbs-cert-bbs.example.com.timer')],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_renewal_retries_failed_publication_without_reissuing(self):
        self.assertEqual(self.invoke().returncode, 0)
        pem = self.base / 'server.pem'
        old = self.fingerprint()
        pem.unlink()
        result = subprocess.run([str(self.base / 'renew.sh')], env=self.env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.fingerprint(), old)

    def test_wrong_host_and_key_keep_existing_pem(self):
        self.assertEqual(self.invoke().returncode, 0)
        old = self.fingerprint()
        lineage = self.base / 'acme/live/bbs.example.com'
        self.create_certificate('other.example.com')
        for name in ('fullchain.pem', 'privkey.pem'):
            (lineage / name).write_bytes((self.root / name).read_bytes())
        self.assertNotEqual(self.hook().returncode, 0)
        self.assertEqual(self.fingerprint(), old)
        self.create_certificate('bbs.example.com')
        (lineage / 'fullchain.pem').write_bytes((self.root / 'fullchain.pem').read_bytes())
        self.assertNotEqual(self.hook().returncode, 0)
        self.assertEqual(self.fingerprint(), old)

    def test_failed_acme_does_not_enable_timer(self):
        self.env['FAIL_CERTBOT'] = '1'
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse((self.base / 'server.pem').exists())
        self.assertFalse(list(self.units.iterdir()))
        self.env.pop('FAIL_CERTBOT')
        self.assertEqual(self.invoke().returncode, 0)

    def test_failed_systemd_is_reported(self):
        # showを成功させ、登録段階だけ失敗させる。
        self.mock('systemctl', '#!/bin/bash\n[[ $1 == show ]]\n')
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('設定しました', result.stdout)
        self.assertTrue((self.base / 'server.pem').exists())

    def test_rejects_foreign_unit_and_symlink(self):
        unit = self.units / 'oimobbs-cert-bbs.example.com.service'
        unit.write_text('existing unit')
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(unit.read_text(), 'existing unit')
        unit.unlink()
        unit.symlink_to(self.root / 'missing')
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertTrue(unit.is_symlink())
        self.assertFalse((self.base / 'owner').exists())

    def test_rejects_changed_user(self):
        self.assertEqual(self.invoke().returncode, 0)
        (self.base / 'owner').write_text('12345:12345')
        old = self.fingerprint()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(self.fingerprint(), old)

    def test_rejects_invalid_arguments_before_changes(self):
        for domain in ('-bad.example.com', 'bbs..com', '../example.com', 'example.com.',
                       '*.example.com', '127.0.0.1', 'example.com;id'):
            with self.subTest(domain=domain):
                self.assertNotEqual(self.invoke('--domain', domain).returncode, 0)
        self.assertNotEqual(self.invoke('--email', 'bad;email').returncode, 0)
        self.assertNotEqual(self.invoke('--user', 'root').returncode, 0)
        self.assertFalse(self.base.exists())

    def test_real_path_guard_rejects_symlink_and_writable_ancestor(self):
        link = self.root / 'link'
        link.symlink_to('/etc')
        for path in (link, self.root):
            result = subprocess.run(['bash', '-c',
                                     'source "$1"; certificate_safe_path "$2"',
                                     'test', str(SCRIPT), str(path)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
