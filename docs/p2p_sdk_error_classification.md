# 8 種の失敗は、下層のどの値から判定できるか

- status: 確定作業（§9 Q2 の下敷き）。分類の型は提案していない
- version: 0.1
- 対象: `f8a7285`（`main`）
- 前提:
  - `docs/p2p_sdk_api_review.md` §5.4 — エラーが編成層と FFI 境界で失われること
  - `docs/p2p_sdk_surface_from_portal.md` §9 — portal の機能が区別せざるを得ない
    失敗 **8 種**の一覧

## 1. 結論

分類の型を先に決めると、プロキシが実際に返す値と噛み合わない型になる。
そこで 8 種それぞれを、今のコードのどの値から判定できるかコードで確かめた。

**8 種のうち 5 種は今の値で判定でき、3 種はできない。**
できない 3 種の理由がそれぞれ違い、そこが Q2 の形を決める:

- **#1（期限切れか取り消しか）は、プロトコルが意図的に拒んでいる**（§3）。
  できないのではなく、**してはいけない**。分類の型でこれを露出させると
  列挙オラクルを作り直すことになる。
- **#5（upsert）は材料が消えている**（§6.1）。成功時に HTTP status が
  捨てられるため、`200`（既存）と `201`（新規）が呼び出し側に届かない。
- **#8（締め切り超過）は材料が捨てられている**（§6.2）。制御プレーンの
  *トランスポート*に要求タイムアウトが無いのは事実だが、**呼び出し側は
  その上で締め切りを課している**ので超過は今日も起きる。起きた結果が
  debug ログに落とされるか、不透明な `Transport` に畳まれる。

そしてプロトコル自身が別の線を引いていた（§3）。「期限切れ／取り消し」ではなく
**「拒否された」か「要求が成立しなかった」か**で、
分類の型はその線に沿うべきである。

## 2. 判定に使える材料

### 2.1 `ProxyError`（`proxy.rs:152`）

```
Transport(anyhow::Error)          // トランスポート失敗。中身は不透明
Decode(serde_json::Error)         // 本文が読めない
Problem { status: u16, problem: Option<Problem>, retry_after: Option<Duration> }
```

アクセサが 2 つ用意されている:
`ProxyError::retry_after()`（`:182`）と `ProxyError::kind()`（`:196`）。

- `Problem`（`:133`）は RFC 9457 の形: `type_uri`, `title`, `status`, `detail`。
  `Problem::kind()`（`:145`）は **type URI の最後のパス要素**を返す
  （`type_uri.rsplit('/').next()`）。
- **`problem: None` には意味がある。** 構築は
  `problem: serde_json::from_slice(&resp.body).ok()`（`problem_error`, `:2514`）
  なので、RFC 9457 本文でなければ `None` になり **status だけが残る**。
  `relay_lease` はこれを判定に使っている（§4.2）。
- `retry_after` は **`Retry-After` ヘッダ由来**（`proxy.rs:54`）。

### 2.2 `IdentityError`（`identity.rs:42`）

```
Transport(anyhow::Error)
Api { status: u16, body: String, retry_after: Option<Duration> }
Time
```

アクセサは `retry_after()`（`:65`）、`status()`（`:79`）、`kind()`（`:94`）。

**`ProxyError` と形が違う。** `Api` は本文を**文字列のまま**持ち、
`kind()` は呼ばれるたびに JSON を再パースして `Option<String>` を返す。
`ProxyError::Problem` がパース済みの `Problem` を持ち `&str` を返すのと非対称で、
横断する分類を作るならここを橋渡しする必要がある。

**`Decode` に相当する腕が無い。** 本文のデコード失敗は
`Api { status: resp.status, body: format!("invalid response JSON: {e}"), .. }`
に畳まれる（`identity.rs:1737`）。この `status` は **2xx**（成功）なので、
`status()` は成功コードを返し、`kind()` は `None` を返す。
`ProxyError` には `Decode` 腕があるのに対し、Identity 側では
**デコード失敗が「要求は成功した」に見える**。

`retry_after` を落とす経路が 2 つあり、どちらも理由つき:

- `policy_stream`（`identity.rs:1346`）— `open_stream` トレイトがヘッダを
  見られないため、`503 policy-stream-capacity` の `Retry-After` が**読めない**。
  「トレイトを広げるのが直し方」と明記されている。
- 本文のデコード失敗（`:1742`）— 読めない本文は待って再試行する話ではない。

### 2.3 成功時に捨てられるもの

`request_json_with`（`proxy.rs:2480`）:

```rust
if (200..300).contains(&resp.status) {
    serde_json::from_slice(&resp.body).map_err(ProxyError::Decode)
} else {
    Err(problem_error(&resp))
}
```

**成功した瞬間に status が消える。** `201`（新規作成）と `200`（既存）の区別は、
`request_json` を通る**すべての**メソッドで呼び出し側に届かない。
これが §6.1 の原因である。

## 3. プロトコルが引いている線 — 一様化は意図的

ここが本調査で最も重要な発見で、Q2 の型を決める制約である。

**認可の拒否は、わざと一つの答えに潰されている。** 仕様の 3 箇所が同じことを
言っていて、コード側にそのまま書かれている。

| 仕様 | 一様化されるもの | 書かれている場所 |
| --- | --- | --- |
| §8.8.4 | `403 enrollment-key-invalid` が unknown / expired / revoked / revoked-owner を 1 つにまとめる | `identity.rs:74`, `config.rs:736` |
| §8.12.4 | `403 ticket-invalid` が unknown / expired / 使用済み / malformed / 所有者の Endpoint が revoked を 1 つにまとめる | `proxy.rs:1928` |
| §8.13.6 | `provisioning-key-invalid` が unknown / expired / revoked / malformed を 1 つにまとめる | `proxy.rs:191` |

理由も書かれている —— 鍵を持っていることが、それがどの状態なのかを
攻撃者に教えないため。`config.rs:736` の表現:

> unknown, expired, revoked and revoked-owner are one reply, so that holding a
> key tells an attacker nothing about which.

### 3.1 `kind()` は「説明」のためで、「分岐」のためではない

`IdentityError::kind()` の doc（`identity.rs:88`）が明示している:

> **For saying more about a refusal, not for telling refusals apart.**
> The uniformity above is deliberate and this does not undo it: a caller that
> branches on these has rebuilt the oracle.

正当な用途として挙げられているのは、
**原因がこちら側にあるメッセージを認識して説明すること**。doc が名指しする実例は
`pop-signature-invalid`（サーバーが署名不正と Endpoint が見つからないの
両方に同じ答えを返すため）で、実装は `config::explain_pop_failure`
（`config.rs:719`）。同じ形がもう一つあり、
`config.rs:734` の「`enrollment-key-invalid` が何を含むのかを、サーバーが
言わないので代わりに言う」——4 つの原因を、期限切れを先頭にして並べる
（7 日既定・最長 30 日で、カウントダウンが無いため期限切れが最も多い）。

### 3.2 分岐してよいのはどこか

一様化の**例外**として仕様が名指ししているものだけ。

- **容量と可用性**: `IdentityError::status()` の doc（`identity.rs:77`）—
  「分岐の根拠になる少数は `429` と `503` で、これらは認可ではなく
  容量と可用性の話である」。
- **要求が成立しなかった場合**: `ProxyError::kind()` の doc（`proxy.rs:193`）—
  「分岐してよいのは §8.13.6 が挙げる例外で、それらは
  *拒否された* ではなく *要求が成立しなかった* と言っている」。
  `redeem_ticket` の doc（`proxy.rs:1930`）が 3 つを具体的に挙げる:
  `400`、`403 protocol-not-allowed`、`429 grant-quota-exceeded` ——
  いずれも **Ticket を未使用のまま残す**。

そして **status のクラスで分岐する実装が既にある。**
`config::is_permanent`（`config.rs:856`）は

```rust
e.status() == Some(403) || e.kind().as_deref() == Some("pop-signature-invalid")
```

で永続的な拒否と一時的な失敗を分ける。doc が理由を書いている ——
`403` は `protocol-not-allowed` / `insufficient-permission` /
`endpoint-revoked` のいずれであれ「ここから呼び出し側にできることは無い」、
それ以外は再試行可能（`429`/`503` は戻る時刻を言い、`401` は
差し替え直前のトークンが多く、transport はネットワーク）。

**これが一様化を壊さずに分類している唯一の既存実装である** ——
*どの*拒否かではなく *status のクラス*で分岐しているから。
§8-1 の答えはここにある。

**つまりプロトコルの線は「期限切れ／取り消し」ではなく、
「拒否された」対「要求が成立しなかった（＝状態が動いていない）」である。**
後者は呼び出し側が直して再試行できるもので、前者はできないもの。
分類の型はこの線に沿うのが筋で、
`p2p_sdk_surface_from_portal.md` §9 が挙げた #1 のような
「期限切れか取り消しか」を型にすると、仕様が否定しているものを作ることになる。

## 4. すでにある分類器 — 少なくとも 7 つ

Q2 は白紙ではない。production で動いているものが少なくとも 7 つある。
下で詳しく見るのは判定の幅が広い 3 つだが、残り 4 つが
**未知の kind の既定で食い違っている**（§4.4）。

### 4.1 `initiator::renewal_verdict`（`initiator.rs:255`）

```
connection-closed | connection-not-found | invalid-request → Over
endpoint-revoked                                           → Refused
それ以外（token-expired, insufficient-permission を含む）    → Retry
Problem でない（＝ Transport）                              → Retry
```

`token-expired` と `insufficient-permission` を `Retry` に落とす理由が
書かれている: どちらもトークンの話で、トークンを差し替えるループと
共有されているから次の試行は新しいものを持つ。

### 4.2 `relay_lease::verdict`（`relay_lease.rs:141`）

```
connection-closed | grant-invalid | endpoint-revoked → Refused
connection-not-found                                 → LegGone
relay-elsewhere                                      → Elsewhere
problem なし かつ status == 404                       → NotLeased
それ以外                                              → Retry
Problem でない                                        → Retry
```

**2 つは `connection-not-found` で意図的に食い違う。** `renewal_verdict` は
`Over`（接続は終わり）、`verdict` は `LegGone`（レグだけ消えた）。
プロキシはこの 1 つの kind を「接続が終わった」と「リレーの縁をもう
持っていない」の両方に使い、区別できない。データプレーンの事実で
直結へ移った session を終わらせてはならないから、接続の寿命は
接続自身のリースが決める、という判断。

**同じ kind が文脈によって別の意味を持つことが既に起きている。**
横断的な分類を 1 つ作るなら、この食い違いを潰してはいけない。

### 4.3 `config::membership_advice`（`config.rs:796`）

Identity 側。`membership-expired` / `membership-revoked` は kind で一意
（メンバーシップは §3 の一様化の対象外）。ただし

```rust
Some("insufficient-permission") if error.to_string().contains("guests cannot") =>
```

**`insufficient-permission` だけは kind では足りない。**
「サーバーがゲストの話だと言ったときに限る」とコメントが明記している。

ただし読んでいるのは `detail` フィールド**ではない**。
`IdentityError::Api` の `Display` は
`"Identity API returned {status}: {body}"`（`identity.rs:45`）なので、
これは **status と本文全体（type URI・title・detail をまとめて）に対する
部分文字列走査**である。Identity 側にはパース済みの `detail` が
そもそも存在しない（§2.2）。`Problem.detail` だけを露出させる SDK では
今の挙動を再現できない。

### 4.4 残りの 4 つ — 未知の既定が逆を向いている

| 分類器 | 判定 | 未知の kind のとき |
| --- | --- | --- |
| `config::is_permanent`（`config.rs:856`） | status クラスで永続／一時 | 一時（再試行） |
| `endpoint_cert` の `retryable`（`endpoint_cert.rs:265`） | `certificate-unavailable` のみ再試行 | **`return Err(error)`** — 再試行しない |
| `is_already_gone`（`portal-server/src/main.rs:1082`） | `grant-not-found` / `not-found` なら「もう無い」 | `false` — 削除を再試行し続ける |
| `is_listener_not_found`（`public.rs:239`） | `listener-not-found` なら作り直す | `false` — 作り直さない |

**未知の扱いに 2 つの流派がある。** §4.1 と §4.2 は `_ => Retry` で
安全側に倒すが、`endpoint_cert` は許可リスト方式で、知らない kind は
即座に失敗させる。どちらも「安全側」と呼べるが向きが逆で、
§8-5 はこの食い違いの上で決める必要がある。

## 5. 8 種の確定表

| # | 区別したい失敗 | 判定材料（確定） | 判定 | 根拠 |
| --- | --- | --- | --- | --- |
| 1 | 資格情報が期限切れか取り消しか | 資格情報の引き換えでは **1 つの kind に潰されている**（`enrollment-key-invalid` / `ticket-invalid`(§7.2) / `provisioning-key-invalid`） | **意図的に不可**（§3） | §8.8.4, §8.12.4, §8.13.6 |
| 1b | （同）「使えない」ことだけ | 上の kind の存在そのもの。Endpoint とメンバーシップは例外で `endpoint-revoked`, `membership-expired`, `membership-revoked` が一意 | **可** | §4.1, §4.3 |
| 2 | 相手が拒否した | `kind()`: `capability-invalid`, `grant-invalid` / narrowing は Identity の `insufficient-permission`（`403`） | **可**。`insufficient-permission` は **本文の走査が必要**（§4.3） | §4.3, `config.rs:856` |
| 2b | 相手の状態が思っていたものと違った（拒否ではない） | `kind()`: `grant-not-found` / `not-found`（TTL で自然に消えた）、`listener-not-found`（作り直せばよい） | **可**。§3.2 の「要求が成立しなかった」側 | `portal-server/src/main.rs:1082`, `public.rs:239` |
| 3 | 枠が尽きた | `status == 429` ＋ `provisioning-slots-exhausted` ＋ `retry_after`。`grant-quota-exceeded` は **§7.2（コメントのみ）** なので材料に数えない | **可**（§3.2 が明示的に許す） | `tests/provisioning_flow.rs:418` |
| 4 | 一時的に落ちている | `status == 503` ＋ `provisioning-unavailable` ＋ `retry_after` | **可**。ただし `policy-stream-capacity` は `retry_after` が**読めない**（§2.2） | 同上 |
| 5 | 作ろうとしたものが既にあった（upsert） | `created_at` の経過時間のみ。**status は成功時に消える**（§2.3） | **不可** — 30 秒窓の推定（§6.1） | `grants.rs:59` |
| 6 | 認証のやり直しが必要 | `kind()`: `pop-signature-invalid` ＋ `IdentityError::status()` | **可**。ただし「鍵が無効」の内訳は §3 の一様化対象 | `config.rs:720`, `:751`, `:871` |
| 7 | ネットワークが死んでいる | `ProxyError::Transport` / `IdentityError::Transport` という**列挙の腕** | **可**（腕としては）。中身は `anyhow::Error` で**不透明** | §4.1, §4.2 の else 腕 |
| 8 | 締め切り超過 | **なし** | **不可**（§6.2） | FFI の `APP_PAIR_DEADLINE` / `APP_CONNECT_DEADLINE` |

#1 を 2 行に割った。「期限切れか取り消しか」は仕様が拒むが、
「この資格情報はもう使えない」は判定できる —— SDK が出せるのは後者だけ。

## 6. 判定できない 2 種（一様化とは別の理由で）

### 6.1 upsert（#5）

`create_grant`（`proxy.rs:1813`）は `Result<Grant, ProxyError>` を返す。
プロキシは既存の Grant を `200` ＋ 既存 id で返し `created_at` を据え置くが、
**`request_json_with` が成功時に status を捨てる**ため（§2.3）、
`200` と `201` の区別は届かない。

残る材料は `created_at` だけで、だから
`portal_core::gateway::grants::already_existed`（`grants.rs:59`）は

```rust
OffsetDateTime::now_utc() - at > ExistedBefore::WINDOW   // WINDOW = 30 秒
```

という**推定**になっている。30 秒より古ければ前からあった、という判定で、
事実ではない。

**同じことが `redeem_ticket` にも当たる。** その doc（`proxy.rs:1936`）が
「2 度引き換えても何かが更新されるわけではない: 既存の生きた Grant が
`200` で日付そのままに返り、Ticket は同じように消費される」と書いている。
つまり upsert は Grant 作成だけの話ではない。

### 6.2 締め切り超過（#8）— 材料は「無い」のではなく「捨てられている」

`p2p_sdk_api_review.md` §5.3 の引用は、**ペアリング／接続の 1 本の呼び出し鎖**
について言ったもので（`issue_endpoint_token` / `PeerDirectory::open` / `pair` /
`ProxyClient::request_json` / `send` を読み下した結論）、
下層全体の話に広げてはいけなかった。確定させた姿はこうである。

**制御プレーンのトランスポートに要求タイムアウトが無いのは事実。**
`relay_rtt.rs:951` のコメントがそう明言している ——
「The control-plane transport has no request timeout of its own, so an
unanswered read here is bounded only by QUIC's 30-second idle timeout」。

**しかし呼び出し側はその上で締め切りを課している。**

| 場所 | 締め切り | 対象 |
| --- | --- | --- |
| `relay_rtt.rs:954` | `opts.budget / 2` | **制御プレーン呼び出し**（`list_relays`） |
| `auth0.rs:1050`, `:1051` | 15 秒 / 接続 10 秒 | Auth0 のトークン取得（`reqwest`） |
| `oidc.rs:58` | 20 秒 | ワークロード ID トークンの発行 |
| `listener.rs:47`, `initiator.rs:275`, `:480`, `bind.rs:407`, `transport.rs:606` | 3〜10 秒 | 終了処理の各段 |

**つまり超過は今日も起きている。** 問題は起きた後で:

- `relay_rtt.rs:965` は `Err(_)` を **debug ログ 1 行に落として捨て**、
  計測なしで接続を続ける。呼び出し側にはエラーとして届かない。
- `auth0` / `oidc` 側の超過は `reqwest` のエラーから `anyhow` を経て
  不透明な `Transport` 腕に入り、**ネットワークが死んでいる場合と区別できない**（#7）。

したがって #8 が判定不可なのは「失敗が存在しないから」ではなく
**「存在する失敗の情報が破棄されているから」**。
面の問題（§9 Q3）**と** 分類の問題の両方であり、
`Transport` に腕を足す話（§8-7）と地続きである。

## 7. kind 語彙 — 出典つき

**プロキシの語彙の全体ではない。** 制御プレーンは別リポジトリにあり、
ここに挙げるのはこのワークスペースに現れるものだけ。
**コードで判定・検証されているもの**と、**doc コメントで名前だけ挙がっているもの**
を分けた（後者を分類の対象にしてはいけない）。

### 7.1 コードが判定するか、テストが値を固定しているもの（22）

| 系統 | kind |
| --- | --- |
| 接続の寿命 | `connection-closed`, `connection-not-found`, `invalid-request` |
| リレーのレグ | `relay-elsewhere`, `relay-ticket-invalid`（テストが `Retry` に固定、`relay_lease.rs:665`） |
| 資格情報 | `grant-invalid`, `grant-not-found`, `not-found`, `capability-invalid`, `listener-not-found` |
| Endpoint・トークン | `endpoint-revoked`, `token-expired`, `insufficient-permission`, `pop-signature-invalid` |
| Enrollment | `enrollment-key-invalid` |
| Provisioning | `provisioning-key-invalid`, `provisioning-binding-invalid`, `provisioning-slots-exhausted`, `provisioning-unavailable` |
| メンバーシップ | `membership-expired`, `membership-revoked` |
| 証明書 | `certificate-unavailable` |

### 7.2 doc コメントで名前だけ挙がっているもの（5）

`enrollment-unavailable`（`identity.rs:55` の `retry_after` の説明）、
`policy-stream-capacity`（`:1342`）、
`protocol-not-allowed` と `grant-quota-exceeded`（`proxy.rs:1930` の 3 つの例外）、
そして **`ticket-invalid` 自身**（`proxy.rs:1928`）。

**5 つとも、コード中に文字列として存在しない。** 仕様に基づいて
コメントが名指ししているだけで、このワークスペースのどの判定も通っていない。

`ticket-invalid` がここに入るのは示唆的である: §3 の一様化の中心にある
kind が、**このワークスペースでは一度も判定されていない**。
一様化が効いているので判定する必要がない、というのが素直な読みで、
§8-1 の「潰した型にする」側の論拠になる。

## 8. 型を決める前に答えるべきこと

材料は確定した。残るのは設計判断だけで、うち 1 と 2 は §3 から来た新しいもの。

1. **一様化をどう型で守るか**（§3）。分類の型に
   「期限切れ」「取り消し済み」を別の値として持たせると、
   仕様が否定しているものを API が約束してしまう。
   **`config::is_permanent`（§3.2）が答えの形を示している** —— *どの*拒否かでは
   なく *status のクラス*で分岐する。ただしこれは、潰した型が
   **status クラスを保持しなければならない**ことも意味する:
   `403` を隠すと `is_permanent` は拒否と `401`/`429`/`503` を
   区別できなくなり、その誤分類は「プロセスの寿命のあいだ数分おきに
   同じ警告を出し直す」と doc に書かれている状態を招く（`config.rs:866`）。
2. **`kind()` の正当な用途（説明）を型でどう残すか**（§3.1）。
   分岐には使わせず、しかし人に見せる文を作るには要る。
   分類とは別に「説明用の文字列」を併走させるのが近い形になる。
3. **文脈依存をどう表すか**（§4.2）。同じ `connection-not-found` が
   `Over` と `LegGone` に分かれる。1 つの分類 enum に潰すとこれが消える。
4. **detail をどう扱うか**（§4.3）。`insufficient-permission` は
   kind だけでは意味が決まらない。しかも今の実装は `detail` フィールドでは
   なく **Display 文字列全体の走査**で、Identity 側にはパース済みの
   `detail` が存在しない。`Problem.detail` を露出させるだけでは
   現状の挙動を再現できない。
5. **未知の kind をどう置くか**（§4.4）。制御プレーンは別リポジトリで
   語彙は増える。**既存の先例が 2 つに割れている**: §4.1/§4.2 は
   `_ => Retry` で倒し、`endpoint_cert.rs:265` は許可リスト方式で
   知らない kind を即座に失敗させる。どちらも「安全側」だが向きが逆。
6. **2 層の形の非対称を埋めるか**（§2.2）。横断の分類を作るなら
   `IdentityError` 側も `Problem` を持つのが素直だが、
   **それだけでは足りない**: `IdentityError` には `Decode` に当たる腕が無く、
   デコード失敗が `status` 2xx の `Api` に畳まれるため、
   今は「要求は成功した」に見える。足りないのは payload ではなく**腕**。
7. **`Transport` の中身を開けるか**（#7、§6.2）。今は「名前が引けない」と
   「繋がらない」と「TLS が拒否された」を区別できず、
   **呼び出し側が課した締め切りの超過も同じ腕に入る**。
8. **upsert を直すなら成功時の status をどう残すか**（§6.1）。
   `request_json_with` の戻りを変えるのは全メソッドに波及する。

## 9. 参照

- `docs/p2p_sdk_api_review.md` §5.4（エラーの型）、§5.3（タイムアウト不在）
- `docs/p2p_sdk_surface_from_portal.md` §9（8 種の由来）、§4.2（upsert の意味論）
- `rust/isekai-p2p-core/src/proxy.rs` — `Problem`(`:133`), `ProxyError`(`:152`),
  `kind()`(`:196`), `problem_error`(`:2514`), `request_json_with`(`:2480`),
  `redeem_ticket` の doc(`:1930`)
- `rust/isekai-p2p-core/src/identity.rs` — `IdentityError`(`:42`),
  `status()`(`:79`), `kind()`(`:94`)
- `rust/isekai-p2p/src/initiator.rs:255`, `rust/isekai-p2p/src/relay_lease.rs:141`,
  `rust/isekai-p2p/src/config.rs:796` — 既存の 3 つの分類器
