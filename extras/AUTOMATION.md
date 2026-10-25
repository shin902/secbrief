# Secbrief automation

運用手順・設定項目・承認境界は [OPERATIONS.ja.md](OPERATIONS.ja.md) を参照。

- `cycle --config FILE`: 明示した対象の棚卸し・照合・一次情報追跡・差分通知。修正は呼ばない。
- `timer --config FILE --output DIR [--install]`: 日本時間0時のsystemd user timer生成。インストールは明示時のみ。有効化は別操作。
- `agent-plan --config FILE --output FILE`: エージェント向けの証拠付き読み取り専用調査依頼をエクスポート。任意エージェントsubprocessは起動しない。
- `plan --config FILE --name NAME --output FILE`: 運用者定義のargv、cwd、固定環境変数、再起動、版・応答検証をhash付き計画にする。
- `execute --plan FILE --approve HASH`: **人間が承認した正確な計画のみ一回実行**。更新→必要な再起動→版・状態・readiness確認。失敗・中断した承認は再使用しない。

Discord秘密はリポジトリ外に置く。POST後message IDと本文をGETで確認する。送信結果unknownは自動再送しない。通常無変更は静穏、監視失敗と通知送達失敗は別に記録する。ローカルoutboxは配信ではなくローカル記録。

```sh
python3 -m unittest discover -s extras -v
```
