# Fork scope / このフォークについて

This repository is a fork of **[tenhkspark/secbrief](https://github.com/tenhkspark/secbrief)**, not a separate upstream project. The original authors' work and MIT license are retained. Fork-specific changes are on [`shin902/secbrief:feat/secbrief-extra`](https://github.com/shin902/secbrief/tree/feat/secbrief-extra); these additions are not claims about features available in upstream or its main branch.

このリポジトリは **tenhkspark/secbrief のフォーク**です。元の軽量・決定論的な照合を土台に、棚卸しと証拠出力を補完しています。独自のエージェント基盤、定期実行サービス、通知サービスを作るものではありません。

## What comes from upstream / 元の機能

- Python環境、設定したSSH先Debian/Ubuntu、指定Homebrew formulaの棚卸し・変更確認。
- OSVとCISA KEVによる既知脆弱性の照合・分類、ローカルのブリーフィングと差分状態。
- LLMを版比較・影響判定の代わりに使わない方針。

Homebrewの更新遅れはCVE判定とは別です。KEV未収載は「悪用されていない」の証明ではありません。

## Fork additions / 追加機能

| 機能 | 実装・範囲 |
|---|---|
| プロジェクトの自動発見 | 明示したルートを再帰探索。Java/Gradle、JS/TS、Python、PHP、Go、Rust、Ruby、.NETの識別ファイルを記録。monorepoの子も対象。名前による候補発見であり、本文の妥当性や全依存の解決ではない |
| 既存解析への連携 | 発見したpackage-lock.json（npm v2/v3）とcomposer.lockを単発cycleの既存パーサーへ渡す。他の形式も未対応として一覧に残す |
| Electron解析 | ASAR、unpacked、アプリディレクトリの依存メタデータ。ネイティブ/JS部品の候補。明示許可とrunAsNode fuse確認後だけランタイム版probe |
| ホスト・コンテナ棚卸し | 指定したNode/PHP/Bun、Python環境、dpkg/pacman/rpm、Docker一覧と許可した版probe。棚卸しとCVE照合の対応範囲は別 |
| 一次情報・製品版の対応 | PHP/Electron/Bunの公式GHSA、Node公式core DBの対応表記を照合。Electron公式リリースから部品版を対応付け。出典・取得時刻・ハッシュを保存 |
| 単発の統合実行 | JSON/Markdownとchanged/nochange/failedを出力。失敗を正常無変更として処理しない |
| 承認付き修正 | 運用者定義の計画に対する正確なhash承認、単回実行、更新→必要な再起動→版/状態/readiness検証。定期実行やエージェント出力は承認にならない |
| エージェント向け手順 | 調査依頼のエクスポート、imozuru等による原文追跡の分担、ホスト標準の定期実行・通知への引継ぎ |

主な実装は `extras/`。個別コマンドと設定は [運用手順](extras/OPERATIONS.ja.md)、パーサーとElectronの詳細は [extras README](extras/README.md)、情報源と比較範囲は [一次情報の説明](extras/PRIMARY-SOURCES.ja.md) を参照。

## Core fixes in this fork / 既存本体への修正

補完ツールだけでなく `secbrief.py` 本体も修正しています。clean件数、詳細キャッシュの鮮度、アドバイザリ更新の差分、取得失敗時のdegraded表示・終了コード・成功状態の保護、貼り付け時の匿名化を改善。一般的なapt更新候補をCVE修正版の根拠として扱わないようにしています。これらも上流への取り込み済みという意味ではありません。

## Outside this repository / 実行元に任せること

- **定期実行・通知**：Hermes/OpenClawのcron、macOSのlaunchd、Linuxのsystemd timer/cron等を、その場のエージェントが設定する。このフォークはtimer生成・登録、Discord送信、通知用outboxを提供しない。ローカルレポートや差分ファイルは通知送達ではない。
- **探索的な情報収集**：脆弱性報告サイトを入口に、imozuru等で公式アドバイザリ・修正コミット・製品リリースへ辿る。imozuruや専用エージェントランタイムを内蔵・自動導入しない。固定カタログは補助であり網羅性の保証ではない。
- **実環境への導入**：対象、周期、通知先、外部送信許可、初回送達、実サービスの更新後確認は実行元で決める。cloneやテスト成功だけで運用は開始しない。

## Not implemented or not guaranteed / 未対応・保証しないこと

- Java/Maven/Gradle等を含む全言語の解決済み依存グラフの取得。Javaは発見に対応するが依存解決には未対応。発見段階でビルドやインストールは実行しない。
- PC全体・すべてのプロジェクトの完全な発見。指定ルートと対応識別ファイルが対象。除外ディレクトリ・シンボリックリンク・権限・深さ/件数上限をcoverageに記録する。
- pacman/rpm一覧を取得しただけでのCVE照合完了、未知脆弱性の検出、侵入・悪用の有無の断定。
- 静的リンクやメタデータを失ったバンドルの完全な版復元、非公開バックポートの確定。上流Nodeの修正版だけでElectronアプリの修正取り込みを断定しない。
- 全プロセスやネットワーク公開範囲の自動特定。今回の棚卸し・製品版照合に必須とはしない。
- 未対応の版範囲表記、PHP拡張の有効化条件、未掲載・遅延した情報を推測で確定すること。不明はunknownとして残す。
- 人間の承認なしの更新・再起動・デプロイ。承認ゲートはこのCLIの手順制御であり、同一ユーザー権限の別プログラムを拘束するOSサンドボックスではない。

## Data and verification / データと検証

- オンライン照合は明示許可。OSVへパッケージ名・版・エコシステムが送信される。詳細は [SECURITY.md](SECURITY.md)。ローカルのパスや構成を含むレポートは機微情報として扱う。
- 正常無変更と失敗を分ける。単発cycleは結果JSONを毎回出し、実行元がnochangeの通知を抑制する。inventory_onlyはCVE照合の完了ではない。
- 実行可能なローカル検証：

```sh
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s extras -v
```

テスト合格は、全対象の網羅、本番通知送達、実環境の修正成功を証明しません。
