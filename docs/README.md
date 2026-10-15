# OimoBBSの文書

| 文書 | 内容 |
| --- | --- |
| [確定仕様](specification.md) | 機能、用語、初期値、許可条件、保持期限 |
| [セットアップ](setup.md) | Dockerなしの初回起動とHTTPS公開 |
| [Dockerセットアップ](../deploy/README.md) | Composeの初回起動と更新 |
| [設定一覧](configuration.md) | 起動JSON、設定の優先順位、管理API |
| [管理者の権限](admin-permissions.md) | ロールの比較、追加権限、担当板、付与手順、メニュー表示 |
| [運用手順](operations.md) | 管理、停止・再開、バックアップ、復旧 |
| [セキュリティ運用](security.md) | 公開入口、認証監視、暗号化バックアップ |
| [内部設計](architecture.md) | 投稿確定、保存形式、配信、削除 |
| [回線カタログ](networks.md) | 標準取得元と分類の範囲 |
| [検証方法](testing/README.md) | 自動検査、HTTP・UI・障害・性能の確認 |

初回起動はセットアップ、権限の設定は管理者の権限、日常の管理は運用手順、開発は確定仕様と内部設計から読み進めます。
