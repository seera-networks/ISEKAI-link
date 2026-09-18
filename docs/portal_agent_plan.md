---
title: portal-client を Agent Runtime として動かす — agent_access 段階 3
status: draft
related: agent_access_spec_draft.md（ISEKAI-link-server 側）, portal_gateway_plan.md
---

# portal-client を Agent Runtime として動かす

`agent_access_spec_draft.md` の**段階 3**:

> **Runtime：タスク単位の Endpoint と、絞ったトークンの発行（§3.4.1）**

Agent Runtime に相当するのは `portal-client` である。本書はそこに
**agent モード**を足す計画。

> 以下、`§n` は本書の節。設計書を指すときは「**draft §n**」、Identity の仕様は
> 「**identity §n**」と書く。

---

## 0. 結論を先に

### 0.1 上流も、こちらの片側も、既に揃っている

| 要るもの | 状態 |
| --- | --- |
| `requested_protocols`（発行） | Identity 実装済み |
| `requested_protocols`（更新でも絞りを保つ、段階 0-b） | **Identity 実装済み** — 更新は `Bound::Narrowed` |
| `requested_gateways`（リースの selector） | Identity 実装済み |
| 発行がリース配布の引き金になる（draft §6.2.1） | Identity 実装済み |
| Gateway 側の受け取り（段階 2） | **`portal-server` 実装済み**（P0〜P5） |
| クライアントの `refresh_token` に `requested_protocols` | **ある** |
| クライアントの `requested_gateways` | **無い** |
| **タスク単位の Endpoint** | **無い** |

**段階 3 で本当に無いのは 2 つだけである。** 残りは既にある部品を繋ぐ仕事になる。

### 0.2 難しいのは絞りではなく、鍵の寿命

`portal-client` の鍵は `--key`（既定 `portal-client.pem`）で、**ファイルとして
残り続ける**。doc コメントが「新しい鍵は新しい Endpoint ID で、発行済みの
capability が意味を失う」と警告しているとおり、**鍵が残ることが前提の設計**である。

タスク単位の Endpoint はその逆を要求する。

```
タスク開始 → 鍵生成 → Identity に登録 → ep:A7-task1
タスク終了 → Endpoint を失効 → その名義の到達性はすべて消える
```

**鍵はタスクより長生きしてはならない。** 残れば、次のタスクが前のタスクの認可を
継ぐ経路になる — draft §3.4 が「トークンを絞るだけでは分離にならない」と書いている、
まさにその形である。

### 0.3 なぜ「トークンを絞る」だけでは足りないのか

draft §3.4 の中心。**Proxy が区別できるのは
`(owner_endpoint, allowed_endpoint, protocol)` までで、どのタスクかは見えない。**

```
タスク 1: ep:A7 / pg-sales-ro-v1 / R1 への Grant（TTL 1h）
タスク 1 終了
タスク 2: ep:A7 / pg-sales-ro-v1 / R2 を使う
   → タスク 1 の R1 Grant がまだ TTL 内なら、タスク 2 からも R1 に届く
```

**並行していなくても、Grant の TTL が重なれば起きる。** だから Endpoint を分ける。
本来の解（Grant のキーに `access_lease_id` を入れる）は Proxy の変更を要し、
段階 6 である。

---

## 1. agent モードとは何か

```
portal-client --agent --task <name> --protocol pg-sales-ro-v1 --gateway ep:R1 --map 5432:db
  ├─ タスク用の鍵を作る（ファイルに残さない）
  ├─ Identity に登録し、protocol と gateway を絞ってトークンを発行
  │    → その発行自体が Gateway へのリース配布の引き金になる（draft §6.2.1）
  ├─ Grant ができるのを待って接続し、転送する
  └─ 終了時に Endpoint を失効させる
```

**既存の動作を置き換えない。** `--agent` を渡さなければ今までどおりで、`--key` の
鍵も pairing も ticket もそのまま効く。

### 1.1 `--enroll` との違い

`portal-client --enroll`（CI 用）と形が似ているので、違いを明記する。

| | `--enroll`（CI） | `--agent`（本書） |
| --- | --- | --- |
| 誰が認証するか | Enrollment Key ＋ workload identity（人は居ない） | **Auth0 の人**（draft §6.2: 「A が Auth0 で認証した状態で」） |
| 鍵 | ファイル（`--key`）。枠を返して失効 | **メモリだけ**（§2.1） |
| 認可の出どころ | Provisioning Key の引き換え | **エンタイトルメント → リース → Grant** |
| 終了時 | 枠を返す（`release_enrollment`） | **Endpoint を失効させる** |

**失効の仕組みは共有できる。** `--enroll` は既に「終了時に自分を失効させる」経路
（`portal_core::ci::release_the_slot`、SIGTERM も含む）を持っている。agent モードは
その理由が違うだけで、やることは同じである。

---

## 2. タスク単位の鍵

### 2.1 ファイルに残さない

**鍵はプロセスのメモリにだけ置く。** `--key` のようにファイルへ書くと、

- 次の起動が同じ Endpoint を名乗り、前タスクの Grant を継ぐ
- 失効させても**ファイルは残る**ので、「失効済み Endpoint の鍵」が転がる

`load_or_generate_key` は「無ければ作ってファイルに書く」なので、agent モードは
**それを呼ばない**。`EndpointKey` を生成して持つだけにする。

> **`--key` と併せて渡されたら拒否する。** 「タスク単位の鍵」と「保存された鍵」は
> 両立しない要求であり、黙ってどちらかを選ぶと、選ばれなかったほうを期待していた
> 運用者が**分離されているつもりで分離されていない**状態になる。

### 2.2 失効は最後にやること、かつ必ずやること

draft §4.3: **失効の単位が Endpoint である**ことがタスク単位に寄せる理由でもある。
Grant の失効は「次の connect から」だが、Endpoint 失効は認証層で全要求を弾く。

- 正常終了でも異常終了でも失効させる
- **SIGTERM でも**。`--enroll` が同じ理由で `hard_exit_on_second_signal` と
  組み合わせている
- 失効に失敗しても**タスクの結果は失敗にしない**。§8.8.8 の掃引が後ろに居る
  （`--enroll` の「Best-effort at the end of a job」と同じ判断）

> **ただし黙って諦めない。** 失効できなかったことは、掃引が来るまで Endpoint が
> 生きているという意味であり、運用者が知るべき事実である。

### 2.3 リースは放っておけば切れる

draft §6.2.1: **「タスクが終わった」を誰かが伝える必要は無い。** トークンの更新が
リースの時計なので、プロセスが消えれば 1 リース TTL 以内に Grant も消える。

**失効はそれを待たないための手段**であって、代わりではない。両方ある。

---

## 3. 絞ったトークン

### 3.1 要求する 2 つ

```jsonc
POST /v1/tokens/endpoint
{ "endpoint_id": "ep:A7-task1",
  "requested_protocols": ["pg-sales-ro-v1"],
  "requested_gateways": ["ep:R1"],
  "ttl": 900 }
```

- **`requested_protocols`** はトークンの claim になる。天井
  （ユーザーごとの protocol 集合）を超えては広がらない
- **`requested_gateways`** は claim ではない。**どのエンタイトルメントのリースを
  起こすか**の selector である（draft §6.2）

> **`requested_gateways` を既定の運用にする。** 省略するとそのクラスの全 Gateway に
> リースが起き、Grant が不要に広がる。**指定を必須**にはしないが、省略したときは
> 何が起きるかをログに出す。

### 3.2 クライアントに無いのは `requested_gateways` だけ

`IdentityClient::issue_token` / `refresh_token` は既に `requested_protocols` を
送れる。**`requested_gateways` を足す。** 発行と更新の両方に要る — 更新もリースの
引き金だからである（draft §6.2.1 の表）。

### 3.3 絞りは更新をまたいで保たれる

Identity 側（段階 0-b）が `Bound::Narrowed` で実装済みなので、**クライアントは
毎回同じ絞りを送るだけでよい**。送らなければ Endpoint レコードから再計算される
——それが天井いっぱいに戻る経路なので、**更新でも必ず送る。**

---

## 4. Grant を待つ

### 4.1 発行してすぐ繋いでも、まだ Grant は無い

draft §6.2.1 の経路は **Identity → Gateway → Proxy** で、非同期である。

```
トークン発行 → Identity が policy.granted を流す
             → Gateway が受け取り、属性を検証し、表に書き、Grant を作る
             → ようやく connect が通る
```

**発行の直後に `connect` すると `grant-invalid` になる。** これは失敗ではなく
**早すぎる**だけなので、そう扱う。

- 短い間隔で再試行し、上限を設ける
- 上限に達したら**理由を言って終わる**。「Gateway が受け取っていない」「属性が
  値域外で拒否された」「そもそも entitle されていない」の区別は**こちらからは
  つかない** — Gateway 側のログにしかない。だから**何を見ればよいかを言う**

> **待つ時間の目安は、Gateway のストリーム遅延である。** 通常は秒の単位だが、
> Gateway が落ちていれば再接続時の照合（identity §8.10.2）までかかる。
> **数十秒で諦め、待ち続けない。**

### 4.2 `protocol-not-allowed` は待っても直らない

トークン発行の時点で天井を超えていれば、その場で拒否される。**これは再試行の
対象ではない** — エンタイトルメントを足す以外に変わりようがない。

`grant-invalid`（まだ配られていない）と `protocol-not-allowed`（配られることが
ない）を**同じ再試行に入れない**。

---

## 5. 段取り

| # | やること | 出口 |
| --- | --- | --- |
| **P0** | `requested_gateways` をクライアントの発行・更新に足す | 上流の selector が使える |
| **P1** | `--agent` の引数と、**メモリだけの鍵**。`--key` との併用を拒否 | タスク単位の Endpoint ができる |
| **P2** | 絞ったトークンの発行と更新（毎回同じ絞りを送る） | リースが起き、延びる |
| **P3** | Grant を待つ（§4）。`grant-invalid` と `protocol-not-allowed` を分ける | 早すぎる接続で失敗しない |
| **P4** | 終了時の失効（正常・異常・SIGTERM）。失敗は報告するが致命にしない | タスクの到達性が残らない |
| **P5** | 実配備で端から端まで — エンタイトルメントを 1 行入れ、agent が繋ぎ、終了で消える | **段階 2 と 3 が噛み合う** |

**P0 は単独で入る。** 既存の呼び出し側は `None` を渡せばよく、挙動は変わらない。

**P5 が本当の検収である。** ここまでの段階はどれも片側だけの確認で、
「エンタイトルメントを 1 行足すと agent が繋がり、タスクが終わると消える」を
通して見るまでは、段階 2 と 3 が噛み合っているとは言えない。

---

## 6. 確かめていないこと

1. **エンタイトルメントを誰がどう登録するか。** identity §8.9 に API はあるが、
   運用の段取り（誰が `ep:R1` を Gateway として登録し、誰が A に
   `pg-sales-ro-v1` を与えるか）は本書の外である。**P5 はこれが要る**
2. **Grant が配られるまでの実測。** §4.1 の「秒の単位」は設計からの推測で、
   測っていない。P3 で数字を出す
3. **タスク単位 Endpoint が天井のクォータに当たるか。** Endpoint の登録数や
   `max_live_endpoints` に上限があるなら、タスクごとに作る運用はそこに当たる。
   `--enroll` の枠と同じ問題が、違う規模で出うる
4. **同じ人の複数タスクが並行したとき。** 天井はユーザー単位なので共有される
   （draft §6.2 の注）。分離は Endpoint 分割で行う、というのが第一版の答えだが、
   **クォータと衝突しないかは 3 番目と同じ話である**

## 7. この計画で解かないもの

1. **PEP の強制**（Gateway 側の別計画）。agent が操作を実行する話はその先
2. **エージェント単位 Endpoint に戻すこと**（draft §3.4.2、段階 6）。Proxy に
   `access_lease_id` を通す変更が要る
3. **scope の提示**（draft §6.4.1）。Gateway が操作一覧を見せる口
4. **オーケストレータとの関係。** 本書が決めるのは 1 タスクを走らせる形だけで、
   タスクを並べる仕組みは別である
