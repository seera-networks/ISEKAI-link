# SDK 境界のエラー型（§9 Q2 の答え）

- status: 設計。実装はまだ無い
- version: 0.1
- 対象: `4d12141`（`main`）
- 前提: `docs/p2p_sdk_error_classification.md` — 8 種の失敗の判定材料。
  本文書はその確定結果に型を与える

## 1. 軸は「何が起きたか」ではなく「呼び出し側に何ができるか」

材料を確定させたとき、**既存の 3 つの先例が独立に同じ軸を選んでいた**ことが
分かった。これが設計の出発点である。

| 先例 | 軸 | 腕 |
| --- | --- | --- |
| `auth0::RefreshError`（`auth0.rs:801`） | 「再試行が助けになるか」 | `SignInRequired(String)` / `Transient(anyhow::Error)` |
| `config::is_permanent`（`config.rs:856`） | 「ここから呼び出し側にできることがあるか」 | `403` クラス → 永続 / その他 → 一時 |
| `relay_lease::verdict`（`relay_lease.rs:141`） | 「このレグをどうするか」 | `Refused` / `LegGone` / `Elsewhere` / `NotLeased` / `Retry` |

`RefreshError` の doc が軸をそのまま言っている ——
「Why a refresh failed, **and whether trying again can help**. The distinction
is the difference between backing off and giving up.」

そして `SignInRequired(String)` が「spent, revoked or expired」を**1 つの腕と
1 本の文字列に潰している**。これは偶然ではなく、一様化
（`p2p_sdk_error_classification.md` §3）を守る唯一の形である。

**だから型の腕は「呼び出し側の行動」で切る。** 失敗の種類で切ると、
仕様が潰している区別を型が約束してしまう。

## 2. 提案する型

`isekai-p2p-core` に、`ProxyError` / `IdentityError` の隣に置く。
両者を潰すのではなく、**その上に載せる**（§5）。

```rust
/// なぜ要求どおりにならなかったのか、そして呼び出し側に何ができるのか。
///
/// 腕は**行動**で切ってある。失敗の種類で切ると、仕様が意図的に
/// 潰している区別（§8.8.4 / §8.12.4 / §8.13.6）を型が約束することになる。
pub enum Outcome {
    /// **失敗ではない。** world が既に求められた状態にあるか、
    /// 名指したものがそこに無い。
    Settled(Settled),

    /// 認可が拒んだ。この資格情報で再試行しても変わらない。
    ///
    /// **腕が 1 つなのは意図的。** unknown / expired / revoked / malformed は
    /// 仕様が 1 つの答えに潰しており、分けると列挙オラクルを作り直す。
    /// どれだったかは `explain` に文として入るだけで、値にはならない。
    Refused { explain: String },

    /// 新しい資格情報が要る（サインインし直す、トークンを取り直す）。
    Reauthenticate { explain: String },

    /// 要求が成立しなかった。**状態は動いていない**ので、直して出し直せる。
    Rejected { explain: String },

    /// 容量または可用性。`after` が言う時刻まで待つ。
    Busy { after: Option<Duration>, explain: String },

    /// 名指したものが消えた、または別の場所にある。
    ///
    /// **何をすべきかは呼び出し側しか知らない**（§3.2）。ここは事実だけ言う。
    Vanished { at: Option<String>, explain: String },

    /// 答えが返らなかった。ネットワーク、名前解決、TLS、
    /// あるいはこちらが課した締め切り。
    Unreachable(Unreachable),

    /// 答えが解釈できなかった。こちら側かサーバー側の不整合。
    Malformed { explain: String },
}

/// 失敗ではない結末。呼び出し側は「もう済んでいる」と読む。
pub enum Settled {
    /// 作ろうとしたものが既にあった（upsert）。
    AlreadyThere,
    /// 消そうとしたものが既に無かった。
    AlreadyGone,
    /// その配備にその機能が無い（`list_relays` の `404` など）。
    NotDeployed,
}

/// 答えが返らなかった理由。`anyhow` 1 本に畳まない。
pub enum Unreachable {
    /// こちらが課した締め切りを超えた（§4-8）。
    Deadline { waited: Duration },
    /// それ以外。中身は当面 `anyhow`。
    Transport(anyhow::Error),
}
```

この定義は**そのままコンパイルが通る**（`anyhow` と
`std::time::Duration` だけに依存、56 行）。型として成立していることは
確認済みで、未検証の擬似コードではない。

### 2.1 `explain` が文字列である理由

`kind()` の doc（`identity.rs:88`）が用途を限定している ——
「**For saying more about a refusal, not for telling refusals apart.**」

だから `kind` は**値として露出させない**。`explain` は
`kind` と `detail` と status から組み立てた**人に見せる文**で、
分岐の材料ではない。`RefreshError::SignInRequired(String)` と同じ扱いである。

`config::explain_key_refused`（`config.rs:750`）と
`explain_pop_failure`（`:719`）が今やっていること —— サーバーが言わない
「`enrollment-key-invalid` が何を含むのか」を代わりに言う —— は
`explain` の中身を作る仕事として残る。

### 2.2 `Vanished { at }` が detail を持つ理由

`detail` は通常 `explain` に溶ける。**1 箇所だけ例外がある**:
`409 relay-elsewhere` は `detail` に移転先のホストを入れて返す
（`relay_lease.rs:163` のコメント: 「The proxy answers 409 with the new host
in `detail`（"renew this session at https://…"）」）。

これは説明ではなく**データ**なので、`at: Option<String>` として
型に出す。`relay_lease::Verdict::Elsewhere` がこれを使っている。

## 3. 今の値からの対応表

### 3.1 status クラスで決まるもの

**写像の主軸は status であって kind ではない。** これが §9 Q5
（未知の kind をどう置くか）を解消する: 知らない kind は、
その status が言うところへ行くだけで、既定を決める必要がない。

| status | 腕 | 根拠 |
| --- | --- | --- |
| `400`, `422`, その他 4xx | `Rejected` | §3.2 の「要求が成立しなかった」 |
| `401` | `Reauthenticate` | `is_permanent` が `401` を一時側に置く理由（差し替え直前のトークン） |
| `403` | `Refused` | `is_permanent`（`config.rs:861`）がこのクラスで永続と判定 |
| `429`, `503` | `Busy { after: retry_after }` | `status()` の doc が明示的に許す分岐（`identity.rs:77`） |
| その他 5xx | `Busy { after: None }` | 同上の延長 |
| `ProxyError::Decode` | `Malformed` | — |
| `ProxyError::Transport` / `IdentityError::Transport` | `Unreachable::Transport` | — |

**例外が 2 つある。** `401 pop-signature-invalid` は
`is_permanent` が永続側に入れている（`config.rs:871`）—— 鍵が
トークンの指すテナントに登録されていない、という「聞き直しても変わらない」
答えだから。これは `Refused` に行く。もう 1 つは §3.2。

### 3.2 status だけでは決まらないもの — `404` と `409`

ここは**一般に分類できない**。同じ status が、ルートによって別の意味を持つ。

| 今の実装 | status | 読み方 |
| --- | --- | --- |
| `proxy.rs:2236`（`list_relays`） | `404` | `Ok(None)` ——「その配備にリレー登録が無い」。エラーではない |
| `relay_lease.rs:168` | `404` ＋ **problem 本文なし** | `NotLeased` ——「そのルートが無い」 |
| `relay_lease.rs:162` | `404 connection-not-found` | `LegGone` ——「レグだけ消えた」。接続は終わっていない |
| `initiator.rs:260` | `404 connection-not-found` | `Over` ——「接続は終わり」 |
| `is_already_gone`（`portal-server/src/main.rs:1082`） | `404 grant-not-found` / `not-found` | `AlreadyGone` —— TTL で自然に消えた |
| `is_listener_not_found`（`public.rs:239`） | `404 listener-not-found` | 作り直して再試行 |
| `already_registered`（`config.rs:538`） | `409` | `AlreadyThere` ——「もう登録済み、issue に進め」 |
| `not_found`（`portal-core/agent.rs:278`） | `404` | 取り消しは既に済んでいる |

**`404 connection-not-found` が 2 箇所で逆の意味になっている**のが決定的で
（`p2p_sdk_error_classification.md` §4.2）、1 つの enum に潰せない。

**だから型は決めない。** `404`/`409` は `Settled` か `Vanished` に行くが、
**どちらかはルートごとの知識で決める**。`From<ProxyError>` では決められない
ので、§5 の変換はそこだけルートから受け取る。

これは妥協ではなく、既にそうなっている事実の写しである。

## 4. §9 の 8 種との対応

| # | 区別 | 腕 | 備考 |
| --- | --- | --- | --- |
| 1 | 資格情報が使えない | `Refused` | 「期限切れか取り消しか」は**値にしない**（§2） |
| 2 | 相手が拒否した | `Refused` | |
| 2b | 相手の状態が違った | `Settled::AlreadyGone` / `Vanished` | ルートが決める（§3.2） |
| 3 | 枠が尽きた | `Busy { after }` | |
| 4 | 一時的に落ちている | `Busy { after }` | #3 と同じ腕。**区別する必要が無い** —— どちらも「`after` まで待つ」 |
| 5 | upsert で既にあった | `Settled::AlreadyThere` | **材料が要る**（§6） |
| 6 | 認証のやり直し | `Reauthenticate` | `pop-signature-invalid` は `Refused`（§3.1） |
| 7 | ネットワークが死んでいる | `Unreachable::Transport` | |
| 8 | 締め切り超過 | `Unreachable::Deadline` | **材料が要る**（§6） |

#3 と #4 が同じ腕になるのは設計判断である。§9 は 2 種として挙げたが、
**呼び出し側の行動が同じ**（`after` まで待つ）なので腕を分ける理由がない。
分けたい診断は `explain` に入る。

## 5. 既存の型との関係 — 潰さず、上に載せる

`ProxyError` と `IdentityError` は**残す**。消すと
`status` / `problem.kind` / `detail` / `retry_after` という
材料そのものが消え、`explain` を組み立てられなくなる。

```
ProxyError   ─┐
IdentityError ─┼─→ Outcome   （+ ルートからの 404/409 の読み方）
RefreshError  ─┘
```

変換は `From` ではなく、ルートの知識を受け取る関数にする:

```rust
// ルートが `404`/`409` をどう読むかだけを渡す。
pub fn outcome(error: ProxyError, idempotent: Idempotent) -> Outcome;
```

既存の 7 つの分類器は `Outcome` の読み手になる:

| 分類器 | `Outcome` 導入後 |
| --- | --- |
| `config::is_permanent` | `matches!(o, Refused { .. })` |
| `auth0::RefreshError` | `SignInRequired` → `Reauthenticate`、`Transient` → `Busy`/`Unreachable` |
| `endpoint_cert` の `retryable` | `matches!(o, Busy { .. })` |
| `is_already_gone` | `matches!(o, Settled(AlreadyGone))` |
| `is_listener_not_found` | `matches!(o, Vanished { .. })` |
| `already_registered` | `matches!(o, Settled(AlreadyThere))` |
| `renewal_verdict` / `relay_lease::verdict` | **残す。** `Outcome` の上の、文脈つきの判断（§3.2） |

最後の 2 つを残すのが肝である。`Outcome` は「何ができるか」までしか言わず、
「このレグを畳むか、接続を終わらせるか」は呼び出し側の判断に残る。

## 6. 型の前に要る 2 つの材料

`Settled::AlreadyThere` と `Unreachable::Deadline` は、**今の下層に材料が無い**
（`p2p_sdk_error_classification.md` §6）。型だけ作っても埋まらない。

1. **成功時の status を残す。** `request_json_with`（`proxy.rs:2480`）が
   `(200..300)` の判定の後に status を捨てるので、`200`（既存）と
   `201`（新規）が届かない。これを変えるのは `request_json` を通る
   全メソッドに波及するので、戻り値を変えるより
   「作成系だけ status を返す内部経路を分ける」のが小さい。
2. **締め切りを `Unreachable::Deadline` に落とす。** 超過は今日も起きていて
   （`relay_rtt.rs:954` ほか 4 箇所）、`relay_rtt.rs:965` は debug ログに
   捨て、auth0/oidc 側は不透明な `Transport` に畳む。
   `tokio::time::timeout` の `Err` を腕に変える配線が要る。

**どちらも型と独立に先に入れられる。** 順序としてはこの 2 つが先で、
`Outcome` は材料が揃ってから入れるのが手戻りが無い。

## 7. 残る判断

1. **`Outcome` をどの層に置くか。** `isekai-p2p-core` だと
   `isekai-p2p` の 117 の `anyhow::Result` を順に置き換えていける。
   `isekai-p2p` 側に置くと core を触らずに済むが、
   `ProxyError` / `IdentityError` の両方を跨ぐので上の層になりすぎる。
2. **`anyhow` をいつ外すか。** 一度に 117 箇所は要らない。
   呼び出し側が実際に分岐しているところ（§5 の 7 分類器）から
   `Outcome` を返すように変え、残りは `anyhow` のままでよい。
3. **FFI 境界でどう表すか。** uniffi の enum にそのまま出せるが、
   `Unreachable::Transport(anyhow::Error)` は出せない。
   `explain` だけを渡す形になる。既存の `PortalError` / `ClientError` は
   呼び出し箇所（`Pair` / `Connect`）で切ってあるので、
   **腕の意味が変わる**（§9 Q7 の FFI 統合と同じ話）。
4. **`Rejected` の既定が妥当か。** 知らない 4xx を `Rejected`
   （＝直して出し直せる）に落とすのは、実際には拒否だった場合に
   呼び出し側を無駄に再試行させる。`Refused` 側に倒す選択もある。

## 8. 参照

- `docs/p2p_sdk_error_classification.md` — 8 種の判定材料、一様化の制約
- `docs/p2p_sdk_api_review.md` §5.4 — エラーが失われる 2 層
- `docs/p2p_sdk_surface_from_portal.md` §9 — 8 種の由来
- `rust/isekai-p2p/src/auth0.rs:801` — `RefreshError`、軸の先例
- `rust/isekai-p2p/src/config.rs:856` — `is_permanent`、status クラスの先例
- `rust/isekai-p2p/src/relay_lease.rs:141`, `rust/isekai-p2p/src/initiator.rs:255`
  — 文脈つきの判断として残すもの
