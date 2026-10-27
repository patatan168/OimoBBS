"""リンク検査が見出し変更・削除・コード例・日本語アンカーを区別することを確認する。"""
from pathlib import Path
import tempfile
import unittest

from doclinks import check_links, heading_ids, local_links


class DocumentLinkTests(unittest.TestCase):
    def test_japanese_headings_and_duplicate_suffixes(self):
        self.assertEqual(heading_ids('# どこで設定し、いつ反映するか\n## `ID` と **名前**\n## 同名\n## 同名\n## 同名-1'),
                         {'どこで設定しいつ反映するか', 'id-と-名前', '同名', '同名-1', '同名-1-1'})

    def test_code_examples_do_not_create_headings_or_links(self):
        text = '```md\n# 架空\n[例](missing.md)\n```\n`[例](missing.md)`\n[実際](real.md)\n'
        self.assertEqual(heading_ids(text), set())
        self.assertEqual(list(local_links(text)), [(6, 'real.md')])

    def test_html_anchors_and_links(self):
        self.assertEqual(heading_ids('<a id="explicit"></a>\n<h2 id="html-title">見出し</h2>'), {'explicit', 'html-title'})
        self.assertEqual(list(local_links('<a href="#explicit">読む</a>')), [(1, '#explicit')])

    def test_files_fragments_and_encoded_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            page = root / 'README.md'
            target = root / '操作 手順.md'
            target.write_text('# 本人確認\n## 確認\n## 確認\n')
            page.write_text('[読む](操作%20手順.md#本人確認)\n[再度](<操作 手順.md#確認-1>)\n[欠落](none.md)\n[古い見出し](操作%20手順.md#old)\n[外部](https://example.com/#remote)\n')
            count, errors = check_links([page, target])
            self.assertEqual(count, 4)
            self.assertEqual(len(errors), 2)
            self.assertIn('missing link none.md', errors[0])
            self.assertIn('missing heading 操作%20手順.md#old', errors[1])

    def test_same_repository_absolute_urls_are_not_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'docs').mkdir()
            target = root / 'docs/setup.md'
            target.write_text('# 起動手順\n')
            page = root / 'README.md'
            page.write_text('[正常](https://github.com/patatan168/OimoBBS/blob/main/docs/setup.md#起動手順)\n'
                            '[不正](https://github.com/patatan168/OimoBBS/blob/main/setup.md)\n'
                            '[見出し](https://github.com/patatan168/OimoBBS/blob/main/docs/setup.md#古い見出し)\n'
                            '[他](https://github.com/another/project/blob/main/setup.md)\n')
            count, errors = check_links([page], root=root)
            self.assertEqual(count, 3)
            self.assertEqual(len(errors), 2)
            self.assertIn('missing link', errors[0])
            self.assertIn('missing heading', errors[1])

    def test_security_policy_checks_actual_render_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'docs').mkdir()
            (root / 'docs/setup.md').write_text('# 起動手順\n')
            page = root / 'docs/security.md'
            page.write_text('# 本文\n[目次](#本文)\n[通常の起動](setup.md)\n')
            count, errors = check_links([page], root=root)
            self.assertEqual(count, 2)
            self.assertEqual(len(errors), 1)
            self.assertIn('Security policy resolves this relative link from the repository root', errors[0])
            # ルートに案内を分離すると、どちらの表示経路でも相対リンクを維持できる。
            policy = root / 'SECURITY.md'
            policy.write_text('# セキュリティ\n[通常の起動](docs/setup.md)\n[運用](docs/security.md)\n')
            self.assertEqual(check_links([page, policy], root=root), (4, []))



if __name__ == '__main__':
    unittest.main()
