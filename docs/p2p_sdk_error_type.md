# SDK 境界のエラー型（§9 Q2 の答え）

- status: 実装済み（v0.4）。§3.4 の 2 点は実装して設計を正した — 下記
- version: 0.4（実装: `isekai-p2p-core::outcome`。設計の 2 点を訂正）

## 0. 実装で正した設計の 2 点

1. **`Unreachable::Transport` は `anyhow::Error` を持たない。** §2 はそう書いて
   いたが、既存の分類器はすべてエラーを**参照**で受ける述語である
   （`is_permanent`, `is_already_gone`, `is_listener_not_found`,
   `endpoint_cert` の `retryable`）。所有する型は噛み合わない。
   `Outcome` は答えの*読み*で、原因を所有する必要がない ——
   呼び出し側は元の `ProxyError` を持ったままである。
   `Transport { explain: String }` にしたことで入口が借用になり、
   §8-3 で諦めると書いた `PartialEq` も導出できるようになった。
2. **`Missing::NotDeployed` は到達不能なので落とした。** §3.4 に挙げていたが、
   `list_relays` は `404` をエラーが作られる前に `Ok(None)` へ変えるので
   `outcome()` が見ることはない。
- 対象: `e6ac864`（`main`）。§7.1 の実装は #345
- 前提: `docs/p2p_sdk_error_classification.md` — 8 種の失敗の判定材料。
  本文書はその確定結果に型を与える

## 1. 軸は「何が起きたか」ではなく「呼び出し側に何ができるか」

材料を確定させたとき、**既存の先例が独立に同じ軸を選んでいた**ことが分かった。

| 先例 | 軸 | 腕 |
| --- | --- | --- |
| `auth0::RefreshError`（`auth0.rs:801`） | 「再試行が助けになるか」 | `SignInRequired(String)` / `Transient(anyhow::Error)` |
| `config::is_permanent`（`config.rs:856`） | 「**ここから**呼び出し側にできることがあるか」 | `403` クラス → 永続 / その他 → 一時 |
| `relay_lease::verdict`（`relay_lease.rs:141`） | 「このレグをどうするか」 | `Refused` / `LegGone` / `Elsewhere` / `NotLeased` / `Retry` |

`RefreshError` の doc が軸をそのまま言っている ——
「Why a refresh failed, **and whether trying again can help**. The distinction
is the difference between backing off and giving up.」

そして `SignInRequired(String)` が「spent, revoked or expired」を**1 つの腕と
1 本の文字列に潰している**。これは偶然ではなく、一様化
（`p2p_sdk_error_classification.md` §3）を守る唯一の形である。

**だから型の腕は「呼び出し側の行動」で切る。**

## 2. 提案する型

`isekai-p2p-core` に、`ProxyError` / `IdentityError` の隣に置く。
両者を潰すのではなく、**その上に載せる**（§4）。

```rust
/// なぜ要求どおりにならなかったのか、そして呼び出し側に何ができるのか。
///
/// 腕は**行動**で切ってある。失敗の種類で切ると、仕様が意図的に
/// 潰している区別（§8.8.4 / §8.12.4 / §8.13.6）を型が約束することになる。
#[derive(Debug, thiserror::Error)]
pub enum Outcome {
    /// 消そうとしたものが既に無かった。**失敗ではない。**
    #[error("already gone: {explain}")]
    AlreadyGone { explain: String },

    /// 認可が拒んだ。この資格情報で再試行しても変わらない。
    ///
    /// **腕が 1 つなのは意図的。** unknown / expired / revoked / malformed は
    /// 仕様が 1 つの答えに潰しており、分けると列挙オラクルを作り直す。
    /// どれだったかは `explain` に文として入るだけで、値にはならない。
    #[error("refused: {explain}")]
    Refused { explain: String },

    /// 新しい資格情報が要る（サインインし直す、トークンを取り直す）。
    #[error("needs new credentials: {explain}")]
    Reauthenticate { explain: String },

    /// 要求が成立しなかった。**状態は動いていない**ので、直して出し直せる。
    /// 仕様が分岐を許している例外（`400`、`protocol-not-allowed`、
    /// `grant-quota-exceeded`）がここに来る（§3.2）。
    #[error("rejected: {explain}")]
    Rejected { explain: String },

    /// 容量または可用性。`after` が言う時刻まで待つ。
    #[error("busy: {explain}")]
    Busy {
        after: Option<Duration>,
        explain: String,
    },

    /// 名指したものが消えた、または別の場所にある。
    ///
    /// **何をすべきかは呼び出し側しか知らない**（§3.1）。ここは事実だけ言う。
    #[error("no longer there: {explain}")]
    Vanished { explain: String },

    /// 答えが返らなかった。ネットワーク、名前解決、TLS、
    /// あるいはこちらが課した締め切り。
    #[error(transparent)]
    Unreachable(Unreachable),

    /// 答えが解釈できなかった。こちら側かサーバー側の不整合。
    #[error("malformed answer: {explain}")]
    Malformed { explain: String },
}

/// 答えが返らなかった理由。`anyhow` 1 本に畳まない。
#[derive(Debug, thiserror::Error)]
pub enum Unreachable {
    /// こちらが課した締め切りを超えた（§3.4-8）。
    #[error("no answer within {waited:?}")]
    Deadline { waited: Duration },
    /// それ以外。中身は当面 `anyhow`。
    #[error("transport: {0}")]
    Transport(anyhow::Error),
}
```

この定義と §3.4 の `Missing` / `Reading` は、**併せてそのままコンパイルが
通る**（87 行、依存は `anyhow` / `thiserror` / `std::time::Duration` のみ）。
未検証の擬似コードではない。

### 2.1 `Err` 位置に置く型である

`Outcome` は `Result<_, Outcome>` の `Err` 側に置く。したがって
`AlreadyGone` も `?` で伝播する —— **`AlreadyGone` を読む呼び出し側は
`?` ではなく `match` しなければならない**。今 `is_already_gone`
（`portal-server/src/main.rs:1082`）と `not_found`
（`portal-core/agent.rs:278`）がやっているのと同じ形である。

**成功側の 2 つはここに入れない。** v0.1 は `Settled::AlreadyThere` と
`Settled::NotDeployed` を腕にしていたが、どちらも**成功した呼び出しの結末**
なのでエラー型に居場所がない:

- upsert で既にあった → `create_grant` の**成功**応答（`200` 対 `201`）。
  戻り値側で `Created::{New, Existing}` のように表すもの。
- その配備に機能が無い → `list_relays` は既に `Ok(None)` を返している
  （`proxy.rs:2236`）。エラーではないと doc が明記している。

### 2.2 `explain` が文字列である理由

`kind()` の doc（`identity.rs:88`）が用途を限定している ——
「**For saying more about a refusal, not for telling refusals apart.**」

だから `kind` は**拒否を見分けるための値としては露出させない**。`explain` は
`kind` と `detail` と status から組み立てた**人に見せる文**である。
`config::explain_key_refused`（`config.rs:750`）と
`explain_pop_failure`（`:719`）が今やっていること —— サーバーが言わない
「`enrollment-key-invalid` が何を含むのか」を代わりに言う —— は
`explain` の中身を作る仕事として残る。

**ただし「kind を一切値にしない」は言い過ぎである**（§3.2）。

### 2.3 `detail` に型を与えない

v0.1 は `Vanished { at: Option<String> }` として `409 relay-elsewhere` の
移転先ホストを型に出そうとしていた。**消費者がいないので取り下げた。**

- `Verdict::Elsewhere` は **unit variant**（`relay_lease.rs:131`）。
- その doc が明言している ——「Nothing here dials that host — this crate does
  not carry a way to re-home a live `MasqueH3Transport`」（`:122`）。
  消費側 2 箇所（`:313`, `:399`）は `warn!` して止めるだけ。
- ワークスペース全体で `Problem.detail` を**構造的に読む箇所は 0**
  （`grep '\.detail'` が `ProxyError` の `Display` 以外に何も返さない）。

`detail` は `explain` に溶ける。ただし**溶かす先が必要**なのは確かで、
`ProxyError` の doc（`proxy.rs:157`）が理由を書いている ——
`certificate-unavailable` だけでは「注文が進行中」と「CA が拒否した」を
区別できない。`membership_advice`（`config.rs:796`）は
`error.to_string()` 全体を走査しており、これは `detail` だけでは再現できない
（`p2p_sdk_error_classification.md` §4.3）。

## 3. 今の値からの対応 — 純粋な関数にはできない

**v0.1 の中心的な誤りがここだった。** status クラスだけで腕が決まると書いたが、
決まらない。文脈が 3 系統必要である。

### 3.1 文脈 1 — `404` と `409` はルートが読む

同じ status が、ルートによって別の意味を持つ。

| 今の実装 | status | 読み方 |
| --- | --- | --- |
| `proxy.rs:2236`（`list_relays`） | `404` | `Ok(None)` ——「その配備にリレー登録が無い」。エラーではない |
| `relay_lease.rs:168` | `404` ＋ **problem 本文なし** | `NotLeased` ——「そのルートが無い」 |
| `relay_lease.rs:162` | `404 connection-not-found` | `LegGone` ——「レグだけ消えた」。接続は終わっていない |
| `initiator.rs:261` | `404 connection-not-found` | `Over` ——「接続は終わり」 |
| `is_already_gone`（`portal-server/src/main.rs:1082`） | `404 grant-not-found` / `not-found` | `AlreadyGone` —— TTL で自然に消えた |
| `is_listener_not_found`（`public.rs:239`） | `404 listener-not-found` | **作り直す**（`public.rs:216`、Listener を 1 行消費する） |
| `already_registered`（`config.rs:538`） | `409` | 登録済み、issue に進む |
| `not_found`（`portal-core/agent.rs:278`） | `404` | 取り消しは既に済んでいる |

**`404 connection-not-found` が 2 箇所で逆の意味になっている**のが決定的で、
1 つの enum に潰せない。

### 3.2 文脈 2 — 仕様が分岐を許した kind がある

§2.2 の「kind を値にしない」には**仕様が名指しした例外**がある。
`ProxyError::kind()` の doc（`proxy.rs:189`）がそう書いている ——
「The ones that do are the exceptions §8.13.6 lists, which say the request
**did not stand up** rather than that it was refused.」

具体的には `redeem_ticket` の 3 つ（`proxy.rs:1930`）: `400`、
`403 protocol-not-allowed`、`429 grant-quota-exceeded`。これらは
**Ticket を未使用のまま残す**。

**だから `403` を一律 `Refused` にしてはいけない。**
`403 protocol-not-allowed` は `Rejected`（protocol を直して出し直せる、
Ticket はまだ使える）であり、`Refused`（諦める）に潰すと
**まだ使える Ticket を捨てさせる**。

同じ構造が `endpoint_cert` にもある。許可リストが
`certificate-unavailable` **のみ**で、doc が理由を書いている（`:251`）——
「Nothing else is retried. `certificate-rate-limited` clears in days, not
seconds, and `csr-invalid` is a fault on this side」。
`Busy` を status で決めると `certificate-rate-limited`（おそらく `429`）が
再試行対象に入り、**日単位で待つべきものを秒で叩く**。

### 3.3 文脈 3 — トークンが数分で差し替わるかどうか

**`403` の意味が経路で変わる。** `is_permanent` の doc が
「none of those turns on anything the caller can do **from here**」と
書いているとおり、「from here」が効いている。

`is_permanent` はトークンを**取る**経路にいるので `403` は永続。
しかし接続のリースを**更新する**経路では違う。
`initiator.rs:248` が明言している:

> **Only `endpoint-revoked` ends the session.** `insufficient-permission` is
> refused against the permissions on the *current Endpoint Token*, and this
> process replaces that token every few minutes — so it can be a token minted
> before a permission existed rather than an Endpoint that may not do this.
> Retrying costs a warning a minute and recovers on its own; treating it as
> terminal would tear down **every live session** the day the proxy starts
> requiring a permission on this route.

`relay_lease.rs:169` も同じ理由で `token-expired` と
`insufficient-permission` を `Retry` に落とし、テストが
`verdict(problem(401, "token-expired")) == Retry` を固定している（`:661`）。

**v0.1 の `403 → Refused` / `401 → Reauthenticate` をこの経路に当てると、
`initiator.rs:248` が警告しているまさにその障害を起こす。**

### 3.4 したがって変換はこうなる

純粋な `From` ではなく、**呼び出し箇所の読み方を受け取る関数**にする。

```rust
/// この呼び出し箇所が `404` / `409` をどう読むか（§3.1）。
pub enum Missing {
    /// もう無い、で済む（`is_already_gone`, `not_found`）。
    Done,
    /// 名指したものが消えた。呼び出し側が次を決める
    /// （`is_listener_not_found`, `relay_lease`）。
    Vanished,
    /// この配備にその機能が無い。**エラーにしない**（`list_relays`、§2.1）。
    NotDeployed,
}

/// この呼び出し箇所が応答をどう読むか。
pub struct Reading {
    /// `404` / `409` をどう読むか（§3.1）。
    pub missing: Missing,
    /// このトークンは数分で差し替わるか（§3.3）。
    /// `true` なら `401`/`403 insufficient-permission` は `Busy` に落ちる。
    pub token_self_replacing: bool,
    /// 仕様が分岐を許した kind のうち、この経路で再試行してよいもの（§3.2）。
    pub retryable_kinds: &'static [&'static str],
}

pub fn outcome(error: ProxyError, reading: &Reading) -> Outcome;
```

`Reading` が無ければ決まる部分だけを表にすると:

| 入力 | 腕 |
| --- | --- |
| `400`, `422` | `Rejected` |
| `403`（`token_self_replacing` が偽） | `Refused` |
| `403`（真、かつ kind が `endpoint-revoked` でない） | `Busy` |
| `401 pop-signature-invalid` | `Refused`（`config.rs:871`、鍵がテナントに無い） |
| `401`（その他、`token_self_replacing` が偽） | `Reauthenticate` |
| `429`, `503`, その他 5xx | `Busy { after: retry_after }` |
| `404`, `409` | `Reading::missing` が決める（§3.1） |
| `retryable_kinds` にある kind | `Busy` |
| `ProxyError::Decode` / Identity の本文解釈失敗 | `Malformed` |
| `ProxyError::Transport` / `IdentityError::Transport` | `Unreachable::Transport` |
| `IdentityError::Time` | `Malformed`（こちら側の不整合） |

**§9 Q5（未知の kind の既定）は消えない。** v0.1 は「status が決めるから
既定は要らない」と書いたが、§3.2 のとおり kind の例外が残る以上、
`retryable_kinds` に無い kind をどう扱うかは決める必要がある。
既存の 2 流派（`_ => Retry` と許可リスト）のうち、
**許可リスト側が正しい** —— `endpoint_cert` が示すように、
知らない kind を再試行に落とすと日単位の待ちを秒で叩く。

## 4. 既存の分類器との関係

### 4.1 `Outcome` に畳めるもの

| 分類器 | `Outcome` 導入後 |
| --- | --- |
| `config::is_permanent`（`config.rs:856`） | `matches!(o, Refused { .. })`、`Reading { token_self_replacing: false, .. }` |
| `auth0::RefreshError`（`auth0.rs:801`） | `SignInRequired` → `Reauthenticate`、`Transient` → `Busy`/`Unreachable` |
| `is_already_gone`（`portal-server/src/main.rs:1082`） | `matches!(o, AlreadyGone { .. })`、`Reading::missing` で指定 |
| `already_registered`（`config.rs:538`） | 成功側（§2.1） |
| `not_found`（`portal-core/agent.rs:278`） | `matches!(o, AlreadyGone { .. })` |

### 4.2 `Outcome` に畳めないもの — `ProxyError` を読み続ける

**v0.1 はこれを「`Outcome` の上の判断」と書いたが、上に載せられない。**
どれも `Outcome` が意図的に落とす kind の区別を必要とする。

| 分類器 | 必要な区別 | `Outcome` では |
| --- | --- | --- |
| `relay_lease::verdict` | `NotLeased`（裸の `404`）と `LegGone`（`404 connection-not-found`） | どちらも `Vanished` |
| `renewal_verdict` | `invalid-request` → `Over` と他の kind | `Rejected` と区別できない |
| `endpoint_cert` の `retryable` | `certificate-unavailable` のみ（§3.2） | `Busy` が広すぎる |
| `is_listener_not_found` | kind `listener-not-found` のみ。他の `404` で作り直すと Listener を 1 行無駄にする（`public.rs:216`） | `Vanished` が広すぎる |
| `config::membership_advice` | `to_string()` 全体の走査（§2.3） | `explain` から復元できない |

**この 5 つは `ProxyError` / `IdentityError` を直接読む形で残る。**
`Outcome` は SDK 境界の語彙であって、クレート内部の判断を置き換えない。

これは縮退ではなく、`Outcome` が何であるかの定義である ——
**「呼び出し側が取れる行動」を名付ける型**で、
細かい文脈判断のための型ではない。

## 5. 既存の型は残す

```
ProxyError   ─┐
IdentityError ─┼─→ Outcome   （+ 呼び出し箇所の Reading）
RefreshError  ─┘
```

`ProxyError` と `IdentityError` を消すと
`status` / `problem.kind` / `detail` / `retry_after` という材料が消え、
`explain` を組み立てられず、§4.2 の 5 つも書けなくなる。

## 6. §9 の 8 種との対応

| # | 区別 | 腕 | 備考 |
| --- | --- | --- | --- |
| 1 | 資格情報が使えない | `Refused` | 「期限切れか取り消しか」は**値にしない**（§2） |
| 2 | 相手が拒否した | `Refused` / `Rejected` | 仕様の例外は `Rejected`（§3.2） |
| 2b | 相手の状態が違った | `AlreadyGone` / `Vanished` | `Reading::missing` が決める |
| 3 | 枠が尽きた | `Busy { after }` | |
| 4 | 一時的に落ちている | `Busy { after }` | #3 と同じ腕。**行動が同じ**なので分けない |
| 5 | upsert で既にあった | **成功側**（§2.1） | 材料が要る（§7） |
| 6 | 認証のやり直し | `Reauthenticate` | `pop-signature-invalid` は `Refused` |
| 7 | ネットワークが死んでいる | `Unreachable::Transport` | |
| 8 | 締め切り超過 | `Unreachable::Deadline` | 材料が要る（§7） |

## 7. 型の前に要る 2 つの材料

`Unreachable::Deadline` と upsert の成功側表現は、**今の下層に材料が無い**
（`p2p_sdk_error_classification.md` §6）。型だけ作っても埋まらない。

### 7.1 成功時の status — **入れた**

`request_json_with` が `(200..300)` の判定の後に status を捨てるので、
`200`（既存）と `201`（新規）が届かなかった。

`request_json_status_with` を 1 本足し、`request_json_with` をその上に
載せ替えた（2xx の判定は 1 箇所のまま）。`create_grant` は
`Result<(Grant, Made), ProxyError>` を返し、`Made` は
`Fresh`（`201`）/ `Existing`（`200`）/ `Unknown`（その他の成功）。

**ただし 2 つの読みを同等に信用してはいけない**、というのが実装して分かった
ことである。upsert が `200` だというのは文書化されているが、
**新規作成が `201` だという根拠はこのワークスペース自身の記述しかない**。
もしプロキシが新規にも `200` を返すなら、`Existing` を信じると
この処理が作る**すべての** Grant が `theirs` に落ち、
そこは `settle_grants` が何もしない区分なので、
自分の create が書いた 60 秒の TTL で枯れる。

そこで判断を 1 箇所（`portal_core::gateway::grants::existed_before`）に集め、
**非対称**にした:

- `Fresh`（`201`）は**信じる**。`201` が「既にあった」を意味することは
  考えにくく、信じることで年齢が危険な向きに外す例が直る ——
  往復が遅くて古く見える、こちらが作ったばかりの Grant。
- `Existing`（`200`）は**信じない**。年齢に委ねる（＝status を保持する前の挙動）。
- `Unknown` も同じ理由で委ねる。

`Existing` を信用に昇格させるには、制御プレーンの新規作成 status を
先に確認する必要がある。

### 7.2 締め切り — **半分だけ入れた。自分の主張を訂正する**

v0.1/v0.2 は「どちらも型と独立に先に入れられる」と書いたが、
**締め切りについてはそうではなかった。** `Unreachable::Deadline` という腕の
消費者は `Outcome` 自身だけで、今それを作るのは使われない型を先に置くことになる。

一方で**型と無関係に直せる半分があった**: 超過が既定のログレベルから
見えないこと。本番で超過が黙って消える箇所は 1 つだけで
（`relay_rtt.rs` の `measure_for_connect`。他の `timeout` は probe ごとの
期待された失効か、終了処理で、どれも別の腕で扱われている）、
そこは `debug!` だった —— **リレー選択が静かに止まっても、
リレーが無い配備と見分けがつかない**。`warn!` に上げ、`waited` を添えた。
この経路の欠陥がこれまで毎回テストではなく本番で見つかっているのは、
ここが静かだからである。

**腕そのものは `Outcome` と一緒に入れる。**

## 8. 残る判断

1. **`Outcome` をどの層に置くか。** `isekai-p2p-core` だと
   `isekai-p2p` の 91 の `anyhow::Result` を順に置き換えていける
   （両クレート合わせて 117。`p2p_sdk_api_review.md` の 117 は 2 クレート合計）。
2. **`anyhow` をいつ外すか。** 一度に全部は要らない。
   `Outcome` は `thiserror::Error` を実装するので `anyhow` 側から `?` で
   受けられ、片方向の移行ができる。逆向き（`Outcome` を返す関数が
   `anyhow` を `?` する）は明示的な変換が要る。
3. **`PartialEq` を諦めるか。** `Unreachable::Transport(anyhow::Error)` が
   あるため導出できない。既存の分類器テストは
   `assert_eq!(verdict(..), ..)` を使っているが、§4.2 のとおりそれらは
   `ProxyError` を読み続けるので影響しない。`Outcome` 自身のテストは
   `matches!` で書く。
4. **`Reading` を誰が持つか**（§3.4）。呼び出し箇所ごとの定数にするのが
   素直だが、SDK の利用者に見せる型になるなら名前と既定を決める必要がある。
5. **知らない kind の既定**（§3.3 末尾）。許可リスト側に倒すと決めたが、
   それは「知らない kind は再試行しない」= 失敗を早く返すという意味になる。
6. **FFI 境界でどう表すか。** uniffi の enum に出せるが
   `Unreachable::Transport(anyhow::Error)` は出せず、`explain` だけになる。
   既存の `PortalError` / `ClientError` は呼び出し箇所（`Pair` / `Connect`）で
   切ってあるので腕の意味が変わる（§9 Q7 の FFI 統合と同じ話）。

## 9. 参照

- `docs/p2p_sdk_error_classification.md` — 8 種の判定材料、一様化の制約
- `docs/p2p_sdk_api_review.md` §5.4 — エラーが失われる 2 層
- `docs/p2p_sdk_surface_from_portal.md` §9 — 8 種の由来
- `rust/isekai-p2p/src/auth0.rs:801` — `RefreshError`、軸の先例
- `rust/isekai-p2p/src/config.rs:856` — `is_permanent`、status クラスの先例
- `rust/isekai-p2p/src/initiator.rs:248` — `403` を終端扱いしてはいけない理由
- `rust/isekai-p2p-core/src/proxy.rs:189`, `:1930` — kind の分岐が許される範囲
- `rust/isekai-p2p/src/endpoint_cert.rs:251` — 許可リストにする理由
