# このフォークの運用入口

監視・照合・変更検出・通知と、承認された修正の実行を分離する。**cycle・timer・アドバイザリ・エージェントは更新や再起動を実行しない。**

## 1. 対象を指定

`automation.example.json` と `sources.example.json` をリポジトリ外へコピーし、監視したい実行ファイル、Python環境、OSパッケージ管理ツール、ASAR、Dockerを明示する。パスは絶対パスを推奨。automationの相対パスは設定ファイルのある場所を基準に解決する。runnerにはこのフォークの `extras/secbrief_extra.py` を指定する。

- `inventory_sources_config`: 棚卸し・一次情報の設定ファイル。
- `inventory_sources_probe_runtimes`: 明示したNode/PHP/Bunの版取得、指定したコンテナ内の版取得を許可する。
- `inventory_sources_online`: 公式情報源の取得と、対応するパッケージのOSV照合を許可する。
- `online`: ASAR/npm/ComposerのOSV照合とKEV取得を許可する。送信内容はパッケージ名・版・エコシステム。
- `core_config`: 任意。従来のPython/SSH Debian/Homebrew監視を同一cycleで実行する。coreは通信するため `online=true` が必要。個別coreの警報ファイルを読み、未通知分を追跡する。

OSVが対応しないpacman/rpmの一覧を取得しただけでは、CVE照合済みにはならない。coverageに未照合範囲を記録する。Node/PHP/アプリへの修正取り込みは、公式資料のハッシュと原文を確認した版対応ルールがなければunknown。最新版の存在をCVE修正の証明にしない。

## 2. 一回の実行と差分

```sh
python3 extras/automation.py cycle --config /absolute/path/operator-config.json
```

JSON/Markdownにインベントリと照合結果、一次情報の取得時刻・ハッシュを保存する。`receipts.jsonl` は各cycleの成否、`outbox.jsonl` は変更・失敗の通知記録。取得失敗時は終了コード2。正常無変更は標準出力・通知なし。情報源の取得時刻だけの変化では通知しない。

Discordは任意。Webhookをリポジトリ外の秘密ファイルか環境変数で指定する。送信後にmessage IDと本文をGETで確認し、不明な送信を自動再送しない。ローカルoutboxは必ず残す。通知送達失敗は監視の成功とは別に記録し終了コード2とする。

## 3. 定期実行

```sh
python3 extras/automation.py timer --config /absolute/path/operator-config.json --output ./generated-units
```

毎日 **日本時間0時** のsystemd user timerを生成する。生成だけでは導入・起動しない。`--install`を明示した場合だけunitを配置する。有効化は運用者が `systemctl --user daemon-reload` と `systemctl --user enable --now secbrief-automation.timer` を実行する。実機への導入・通知先設定は別の操作であり、このリポジトリを取得しただけで開始しない。

## 4. エージェントによる調査と修正案

```sh
python3 extras/automation.py agent-plan --config /absolute/path/operator-config.json --output review-request.json
```

証拠と読み取り専用調査の依頼をエクスポートする。`skills/secbrief-operations/SKILL.md`に従うエージェントがCVE・対象・修正方法・ロールバックを調べる。任意のエージェントCLIを「HOMEを変えたから読み取り専用」と称して自動起動しない。エージェントの提案は承認ではない。

## 5. 計画ごとの承認と実行

運用者が `remediation_plans` に更新argv、cwd、固定環境変数、必要な再起動argv、正確なversion/statusを返す検証argv、readiness検査を定義する。コマンドはshell文字列でなく配列。アドバイザリ本文から実行しない。

```sh
python3 extras/automation.py plan --config /absolute/path/operator-config.json --name chosen-plan --output plan.json
# 人間が計画全体を読み、承認した場合のみ:
python3 extras/automation.py execute --plan plan.json --approve REVIEWED_SHA256
```

hashが違う・計画を書き換えた・承認なしの場合は実行しない。同じ承認の再利用も禁止。中断・失敗は対象を再調査し、新しい計画として再承認する。更新→必要な再起動→版・状態・readiness検証の順で実行し、検証一致時だけverified。環境変数は計画内の固定値だけを渡し、実行時の環境を暗黙継承しない。

## 検証範囲

```sh
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s extras -v
```

fixtureの修正→検証、承認拒否・改変拒否、通知不明時の再送禁止、差分静穏、情報源の失敗をテストする。ローカル試験が本番通知の送達や実サービスの更新成功を証明するわけではない。すべてのソフトウェアの版復元、未知CVEの検知、静的リンク部品の完全特定は保証しない。
