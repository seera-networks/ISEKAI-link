---
title: portal-server を Gateway として動かす — agent_access 段階 2
status: draft
related: agent_access_spec_draft.md（ISEKAI-link-server 側）, ISEKAI-identity p2p_connect_spec.md §8.9 / §8.10
---

# portal-server を Gateway として動かす

`agent_access_spec_draft.md` の**段階 2**:

> **Gateway：NDJSON 購読 + 操作カタログ（§3.5）+ 属性スキーマ（§3.1.0）+ PEP +
> Grant 作成（順序規則つき）**

Gateway に相当するのは `portal-server` である。本書はそこに **Gateway モード**を
足す計画で、**PEP の強制は後回し**とする（§0.3）。

> 以下、`§n` は本書の節。設計書を指すときは「**draft §n**」、Identity の仕様を
> 指すときは「**identity §n**」、Proxy の仕様は「**proxy §n**」と書く。

---

## 0. 結論を先に

### 0.1 上流は揃っている。こちらが唯一の欠けている部品である

段階 1（Identity にエンタイトルメント・`decision_id`・配布ストリーム）は
**実装済み**である。identity §8.9 と §8.10、`/v1/policies` と
`/v1/policies/stream` のハンドラが入っている。

**つまり段階 2 は「上流を待つ」話ではない。** 配る側は既に配っており、
**受け取る側が居ない**。

### 0.2 仕様が受け取る側に課している義務は、素直に書くと必ず破る

identity §8.10 は Gateway の責務を明示的に列挙している。そのうち 4 つは
「言われなければそう書かない」種類である。

| 義務 | 素直に書くとどうなるか |
| --- | --- |
| **空の一覧は「全部落とせ」という指示**。「読めなかった」をそれで代用しない | エラー時に空を返す実装にすると、**一時的な失敗で全 Grant を消す** |
| **期限切れはストリームに流れない。** 沈黙は「まだ有効」ではない | ストリームだけ見ていると、**切れたリースを永久に保持する** |
| 照合が正しさの担保。ストリームは速い経路 | ストリームを信頼すると、取りこぼしが恒久化する |
| **ストリームはトークンの期限で必ず終わる**（サーバが切る） | 「切れた＝異常」と扱うと、**15 分ごとに異常ログが出る** |

**この 4 つは設計ではなく仕様である。** 実装の自由はそこに無い。

### 0.3 PEP を後回しにしても、順序規則は先に要る

identity §8.10.4 が処理順を固定している。

1. 属性を検証する（値域外なら**その行は適用しない** = fail-closed）
2. **強制点の表に書く**
3. Grant を作る

> 逆にすると、**届くけれど scope が無い窓**が開く。

**PEP の強制が後回しでも、この順序は今決める。** あとから 2 を差し込むとき、
「Grant を先に作る」実装になっていれば**順序を直す改修**になる。
表は作って保持し、**強制だけをしない。**

---

## 1. 上流の形（実装から読んだ）

**仕様書とハンドラの両方を読んだ。** ISEKAI-identity#35 の教訓である。

### 1.1 2 つの口

| 口 | 役割 |
| --- | --- |
| `GET /v1/policies` | いま有効なもの**全件**と `cursor`。**再接続時の照合** |
| `GET /v1/policies/stream?after=<cursor>` | NDJSON。変化を流し続ける |

認証は **Endpoint Token + PoP**。**permission は要らない** — 名乗った Endpoint に
紐づくものだけが流れるので、名乗り以外に認可することが無い。
`portal-server` は Proxy 用に既に鍵とトークンを持っている。

### 1.2 流れてくるもの

```jsonc
{"type":"policy.granted","access_lease_id":"al_7f2c9d1b","decision_id":"dec_9f1e2d3c",
 "version":4,"allowed_endpoint":"ep:1197c4…","protocol":"pg-sales-ro-v1",
 "ttl":1800,"expires_at":"2026-09-17T09:30:00Z","attributes":{"region":"kanto"},
 "constraints":{"grant_ttl":3600,"max_concurrent":2,"window":"business_hours"}}

{"type":"policy.revoked","access_lease_id":"al_7f2c9d1b","decision_id":"dec_9f1e2d3c",
 "version":5,"allowed_endpoint":"ep:1197c4…","protocol":"pg-sales-ro-v1",
 "reason":"entitlement-removed"}

{"type":"keepalive"}
```

- `reason` は `policy.revoked` に**必ず載る**（`lease-expired` /
  `entitlement-removed` / `endpoint-revoked`）
- `keepalive` は 15 秒ごと。**接続直後に必ず 1 行**流れるので、張れたことの確認になる
- 超過は `503 policy-stream-capacity`

### 1.3 ストリームはトークンの期限で終わる

> **ストリームは、名乗りに使ったトークンの期限で必ず終わる。**

これは**サーバ側の仕様**である。Gateway は 1 トークン寿命（≤15 分）ごとに戻って
照合し、取りこぼしの上限がそこで決まる。PoP はストリームを開く 1 要求にしか
掛からないので、**認証の再検査もこれで満たされる。**

> `relay_lease.rs` でトークンセルを共有することにしたのと**裏表**である。
> あちらは長生きするループが新しいトークンを**見る**必要があり、こちらは
> 長生きするストリームが新しいトークンで**張り直される**必要がある。
> そして今回は、サーバがそれを強制してくれる。

**「切れた」を異常として扱わないこと。** 正常な終わり方である。

---

## 2. 期限切れは自分の時計で落とす

identity §8.10.4 の、いちばん見落としやすい一行。

> **そして、期限切れはストリームに流れない。**（中略）
> **「ストリームに何も来ない」は「まだ有効だ」を意味しない。**

`policy.granted` は `ttl` と `expires_at` を持っているので、**Gateway は自分の時計で
落とせる。それが期限切れの唯一の検出手段**であり、取りこぼしは照合が拾う。

**内容の変更と明示的な失効は必ず流れる**（デバウンスの対象外）。つまり
「流れてこない」で判断してよいのは期限だけで、それ以外は流れる。

**Grant の TTL は `ttl` より短く取る。** 強制点のほうが先に落ちるようにして
fail-closed 側へ倒す（identity §8.10.4）。

---

## 3. Gateway モードとは何か

```
portal-server --gateway
  ├─ 操作カタログを読む      （どの protocol クラスで何が許されるか、draft §3.5）
  ├─ 属性スキーマを読む      （中央から来てよい値の範囲、draft §3.1.0）
  └─ /v1/policies を照合 → /v1/policies/stream を購読
       → 属性を検証 → 強制点の表に書く → Grant を作る
```

**既存の動作を置き換えない。** `--gateway` を渡さなければ今までどおりで、手で作った
Grant もそのまま効く。増えるのは**「Grant を自動で作る主体」**である。

### 3.1 自分が作った Grant に印を付ける

Gateway モードは**自分で Grant を作り、消す**。手で運用している配備に混ざると、
**運用者が作った Grant を Gateway が消す**事故が起きうる。

- Gateway が作った Grant に印を付ける（`label` に `access_lease_id` を入れる）
- **印のあるものだけを消す**

`portal-client --revoke-endpoint` で「自分が登録した Endpoint だけを失効させる」ために
`by_us` を入れたのと同じ判断である。

**そして照合がこれを要求する**（§5）。印が無ければ「ポリシーに無い Grant」を
安全に消せない。

---

## 4. 操作カタログと属性スキーマ

どちらも**顧客側の設定ファイル**であり、中央には出ない（draft §3.1）。

```toml
# 属性スキーマ — 中央から来る値の受け入れ範囲（draft §3.1.0）
[protocols."pg-sales-ro-v1".attributes]
region = { type = "enum", allowed = ["kanto", "kansai", "kyushu"] }

# 操作カタログ — 許す操作（draft §3.5）
[[protocols."pg-sales-ro-v1".operations]]
name     = "query_sales"
sql      = "SELECT id, region, amount FROM sales WHERE region = $1 AND month = $2"
bind     = ["{{region}}", "$month"]
max_rows = 1000
[protocols."pg-sales-ro-v1".operations.params]
month = { type = "string", pattern = '^\d{4}-\d{2}$' }
```

**段階 2 では読んで検証するところまで作る。実行しない**（PEP 後回し）。
それでも価値がある理由は 2 つ。

1. **属性スキーマは段階 2 で効く。** 値域の検証は Grant 作成の前段であり、PEP とは
   独立に動く。**「中央を侵害されても envelope を超えられない」**という draft §3.1.0 の
   主張は、ここが動いて初めて成り立つ。段階 2 の**安全上の中身はこれである**
2. カタログの構文エラーを起動時に見つけられる

### 4.1 自由 SQL を受け取る口は、作らない

draft §3.5 は「任意 SQL を検査して通す形にしてはならない」と書いている。
**段階 2 で作らないだけでなく、後から足せる形にもしない。** `operations` は名前で引く
表であって、テンプレートの外から SQL が入る経路を持たない。

---

## 5. 照合が正しさの担保である

```
起動 / 再接続
  → GET /v1/policies            （全件 + cursor）
  → 表を「ここに無いものは落とす」で作り直す
  → 印のある Grant で、ポリシーに無いものを消す
  → GET /v1/policies/stream?after=<cursor>
```

### 5.1 「読めなかった」を「空」と書いてはならない

identity §8.10.3 が名指しで警告している。

> **空の一覧は「手元の行を全部落とせ」という指示**なので、「読めなかった」をそれで
> 代用してはならない。

実装上は、照合の結果を `Result<Vec<Policy>>` のまま扱い、**`Err` で表に触らない**。
`unwrap_or_default()` は**この一点で禁止**である。

> `--revoke-endpoint` で `duplicate_key` の読み取りを `Result` のまま持ったのと
> 同じ形である。**読めなかったことと、無かったことは違う。**

### 5.2 巻き戻し防止

`version` が既知より古ければ捨てる。`access_lease_id` ごとに最後に見た `version` を
持つ。**再接続後の再送でも要る**（identity §5.4.3）。

---

## 6. 接続を知る

draft §6.4 で Gateway は `peer.connect.created` を受け、`initiator_endpoint` を
表と照合し、`max_concurrent` を見て bind する。

**この購読は proxy §8.11 として存在し、クライアントも実装済みである**
（`ListenerSession::subscribe`）。`portal-server` は今これを使っておらず、
`poll_signaling` の経路で動いている。

段階 2 では**受け取って記録するところまで**作る。

- `initiator_endpoint` が表にあるか（**記録するだけ、落とさない**）
- `max_concurrent` を超えていないか（**記録するだけ**）

**落とさないのは PEP 後回しの一部であり、意図的である。** ただし
**「照合して、落とさなかった」を必ずログに残す。** 強制を入れる前に、
**本番の配備で何件落ちることになるかが分かる**ようにしておく。

---

## 7. 段取り

| # | やること | 出口 |
| --- | --- | --- |
| **P0** | 操作カタログと属性スキーマの型・パーサ。起動時に検証 | 設定が壊れていれば起動時に分かる |
| **P1** | `GET /v1/policies` の型とクライアント。**照合して表を作るだけ**、Grant は作らない | **上流と繋がる。** 何が配られているかが見える |
| **P2** | ストリーム購読（`after` 付き）。**トークン期限での終了を正常系として扱う**（§1.3）。期限切れは自分の時計で落とす（§2） | 変化に追随する |
| **P3** | 属性検証 → 表 → Grant 作成（§0.3 の順序）。**印を付ける**（§3.1） | Gateway が Grant を配る |
| **P4** | `policy.revoked`（PEP 先、draft §7.2）と、照合での消しすぎ防止（§5） | 消し忘れと消しすぎの両方が起きない |
| **P5** | `peer.connect.created` の購読と**記録**（§6） | 強制を入れる前に影響が見える |
| **P6** | PEP の強制（別計画） | — |

**P1 で一度、上流と繋がったことが確認できる。** Grant を作らないので、
**間違っていても配備に影響しない** — 何が配られているかを先に見る。

---

## 8. 確かめていないこと

1. **`ProxyClient::listener_events` の NDJSON 読みを Identity に向けられるか。**
   形は揃えてあると仕様が書いているが、認証（PoP の path 束縛）とベース URL が違う。
   **`IdentityClient` 側に同じ実装が要るかもしれない**
2. **`portal-server` が `subscribe()` に移れるか。** いまは `poll_signaling` で
   動いており、proxy §8.11 の「ポーリングは廃止しない」を踏まえてどちらを主にするか
   決めていない
3. **エンタイトルメントを誰がどう登録するか。** identity §8.9 にあるはずだが、
   Gateway の登録（「`ep:R1` が pg-sales の Gateway である」）を運用でどう回すかは
   本書の外である
4. **`503 policy-stream-capacity` の後退の仕方。** 仕様は「後で通る」としか
   言っていない

## 9. この計画で解かないもの

1. **PEP の強制**（P6、別計画）。操作の実行、行フィルタの束縛、`max_concurrent` の
   enforcement
2. **scope の提示**（draft §6.4.1）。エージェントに操作一覧を見せる口は PEP と同じ層
3. **マルチテナント**（draft §3.1.2）。Identity 側
4. **Gateway の登録**（§8-3）
