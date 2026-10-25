# 一次情報の継続取得と製品版の照合

`primary_source_catalog: true` とオンライン許可を指定すると、同梱 `primary_sources.json` の取得先を毎回取得する。固定されたPHPアドバイザリ2件だけを監視する方式から、公式リポジトリの公開アドバイザリ一覧へ変更した。OSVとKEVは従来どおり別途使用する。

## 情報源と用途

| 情報源 | 用途 |
|---|---|
| PHP php-src公式GHSA一覧 | PHP本体・拡張の影響範囲と修正版 |
| Node公式security-wg core/index.json | Node本体の影響範囲と修正版。公式ブログRSSも変更監視 |
| Electron公式GHSA一覧 | Electronとして公開された影響範囲と修正版 |
| Electron公式releases.json | Electron版→Node/Chromium/V8/OpenSSL等の部品版の厳密対応 |
| Bun公式GHSA一覧 | Bunの影響範囲と修正版 |
| CPython/Brotli公式GHSA一覧 | 情報取得・変更監視。一覧が空でも安全や網羅性を意味しない |
| curl公式vuln.json | 脆弱性情報の取得・変更監視。今回curl実体の自動棚卸しは追加しない |

GitHub APIの正しいパスは `/repos/OWNER/REPO/security-advisories`。Webページの `/security/advisories` とは異なる。誤ったAPIパスで得た404を情報非公開と解釈しない。GitHub一覧のLinkページングを追跡し、他ホストへのページ遷移・ループ・取得上限・不正応答は失敗とする。

## 判定

一次情報の構造化された影響範囲・修正版と観測版をコードで比較する。出典URL・取得時刻・ハッシュ・影響範囲・修正版を結果に残す。未対応の範囲表記はunknownであり、LLMに推測させない。PHPは同じmajor/minor、Node/Electron等は同じmajorの修正版を選び、別系列の修正版を誤って勧めない。PHP拡張は有効化まで今回調べないため、拡張条件を満たすか不明な候補を本体の確定影響と混ぜない。

Electron公式リリースの部品版は対応表であって、CVEの修正取り込みの証拠ではない。Node上流修正版だけからElectronや個別アプリのバックポート有無を断定しない。公式Electronアドバイザリに該当版の記録があれば、それを直接照合する。

公式DBにも掲載遅延・空一覧・未登録案件がある。NodeのDBと最新ブログの時点が異なりうるため、新しい記事がDBに反映される前は追加調査が必要。この違いは未実装のプロセス特定とは別問題。今回はプロセス追跡・修正権限変更・実サービスの更新は追加しない。
