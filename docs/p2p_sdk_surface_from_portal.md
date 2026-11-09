# SDK の面を portal の機能から逆算する

- status: 整理（§9 Q1 の下敷き）。面の確定も API の提案もしていない
- version: 0.1
- 対象: `1412264`（`main`）
- 前提: `docs/p2p_sdk_api_review.md` — 現状の API 設計。本文書はその §9 Q1
  「提示する面の広さ」を、**portal が実際に持っている機能から逆算**して詰める

## 1. なぜ逆算が必要か

現状調査（`p2p_sdk_api_review.md` §3.3）は、FFI 2 本が独立に同じ 4 概念
——**鍵を作る / ペアリング / 接続 / ローカルポートを得て切る**——に収斂していること
を見つけ、それを「SDK の形をすでに示している」と書いた。

**この 4 概念では足りない。** FFI は phone アプリが必要とする分だけを切り出した面で、
portal に後から入った機能はそこに入っていない。したがって面の広さは FFI からではなく、
**portal が今できること**から逆算するのが正しい。

本文書はそれを機械的にやる: portal-server / portal-client の CLI フラグを機能に
束ね、各機能が要求する API を特定し、それが今どの層にあるかを突き合わせる。

## 2. portal の機能一覧

`portal-server` の 49 フラグと `portal-client` の 52 フラグ
（`#[argh(option|switch)]` の数。positional は両者 0）を 9 クラスタに束ねた。

| # | クラスタ | 代表フラグ |
| --- | --- | --- |
| A | 身元・サインイン | `--login`, `--device-code`, `--organization`, `--register`, `--device-name`, `--key`, `--enroll`, `--enrollment-key-file`, `--oidc`, `--oidc-token-file` |
| B | Endpoint の管理 | `--endpoints`, `--endpoint-status`, `--revoke-endpoint`, `--reason`, `--note`, `--whoami` |
| C | Enrollment Key の管理 | `--issue-enrollment-key`, `--enrollment-keys`, `--enrollment-key-enrollments`, `--revoke-enrollment-key`, `--enrollment-protocols`, `--permissions`, `--max-live-endpoints`, `--endpoint-idle-ttl`, `--binding-*` |
| D | アクセス付与 — ペアリング | `--pair`, `--pairing-ttl` / `--pair <code>`, `--redeem`, `--label` |
| E | アクセス付与 — Grant 直接 | `--grant`, `--grant-label`, `--grant-expires-in`, `--grants`, `--revoke`, `--allow`, `--capability-ttl` |
| F | アクセス付与 — Ticket | `--ticket`, `--ticket-ttl`, `--grant-ttl`, `--ticket-label`, `--tickets`, `--revoke-ticket` |
| G | アクセス付与 — Provisioning Key | `--provisioning-key`, `--provisioning-ttl`, `--max-live-grants`, `--provisioning-label`, `--provisioning-keys`, `--provisioning-redemptions`, `--revoke-provisioning-key`, `--binding-oidc`, `--binding-subject` |
| H | 接続と転送 | `--peer`, `--listener`, `--capability`, `--map`, `--bind`, `--relay-only`, `--gateway`, `--task`, `--config`, `--gateway-config` |
| I | 観測・同意 | `--relays`, `--accept-privacy-policy`, `--show-privacy-policy`, `--withdraw-privacy-consent`, `--version` |

FFI の 4 概念が覆っているのは **A の鍵の部分、D の受け取り側、H の一部**、
および `isekai-client-ffi` だけが持つ **I の同意**（`privacy_policy()`,
`lib.rs:245`）。A の鍵生成は両 FFI にある
（`portal-client-ffi/src/lib.rs:81`, `:88`; `isekai-client-ffi/src/lib.rs:737`, `:746`）。

## 3. 各クラスタが要求する API と、その所在

所在は 3 段階で記す:
**[p2p]** `isekai-p2p` に面がある / **[raw]** `isekai-p2p-core::proxy` または
`::identity` を portal が直叩き / **[app]** portal 側の自前実装。

| クラスタ | 要求する API | 所在 |
| --- | --- | --- |
| A | `Credential`, `P2pConfig`, `issue_endpoint_token`, `load_or_generate_key`, `auth0`/`oidc`, `Auth0TokenSource` | **[p2p]** |
| B | `endpoints::{list, get, revoke}`, `membership::{me, describe}` | **[p2p]** |
| C | `enrollment::{Identity::new, issue, list, enrollments, revoke}` | **[p2p]** |
| D | 発行側 `create_pairing_code` → `ListenerSession::show_pairing_code` **[p2p]** / 受け取り側 `pair_with_code` → `PeerDirectory` **[p2p]** |
| E | `create_grant` **[raw]**, `list_grants` **[p2p+raw]**, `revoke_grant` **[p2p+raw]**, `issue_capability` **[p2p]**, upsert の判定 `already_existed` と台帳 `Ledger` **[p2p]**（#350 で移した。方針からの調停 `plan` は **[app]** のまま） |
| F | `create_ticket` **[raw]**, `list_tickets` **[raw]**, `revoke_ticket` **[raw]**, `redeem_ticket` **[p2p]** |
| G | `create_provisioning_key` **[raw]**, `list_provisioning_keys` **[raw]**, `provisioning_redemptions` **[raw]**, `revoke_provisioning_key` **[raw]**, `redeem_provisioning_key` **[p2p]** |
| H | `ListenerSession`, `InitiatorSession`, `RelayOptions`, `listener::run`, `direct_path`, `legs()`, `observed_address()`, `Narrowing`（`--gateway`）, `device_name`（`--task`） | **[p2p]** + 転送・ルーティングは **[app]** |
| I | `relay_rtt::{measure, observe_families}` **[p2p]** + `list_relays` **[raw]** / 同意は **[app]** |

## 4. 逆算で出てきた構造 — 「発行側」の面がない

資格情報のライフサイクル 14 メソッドを層ごとに並べると、きれいに割れる。

| メソッド | `isekai-p2p` の面 | portal の直叩き |
| --- | --- | --- |
| `create_grant` | **なし** | `portal-server/src/main.rs` |
| `list_grants` | `listener.rs` | `portal-server/src/main.rs` |
| `revoke_grant` | `listener.rs` | `portal-server/src/main.rs` |
| `create_pairing_code` | `listener.rs` | `portal-server/src/main.rs` |
| `pair_with_code` | `initiator.rs` | — |
| `create_ticket` | **なし** | `portal-server/src/main.rs` |
| `list_tickets` | **なし** | `portal-server/src/main.rs` |
| `revoke_ticket` | **なし** | `portal-server/src/main.rs` |
| `redeem_ticket` | `initiator.rs` (`PeerDirectory`) | — |
| `create_provisioning_key` | **なし** | `portal-server/src/main.rs` |
| `list_provisioning_keys` | **なし** | `portal-server/src/main.rs` |
| `provisioning_redemptions` | **なし** | `portal-server/src/main.rs` |
| `revoke_provisioning_key` | **なし** | `portal-server/src/main.rs` |
| `redeem_provisioning_key` | `initiator.rs` (`PeerDirectory`) | — |

**`isekai-p2p` が包んでいるのは「引き換える側」と、Grant の「読む／取り消す」だけ。
資格情報を発行・一覧する面は 8 メソッド分まるごと無く**、portal-server は
`isekai_p2p::agent::ProxyClient` という**再輸出された生クライアント**を受け取って
自分で叩いている（`main.rs:39`）。つまり `isekai-p2p` はこの領域に対して
抽象を持たず、素通しの窓だけを開けている。

これは「ペアリングだけでは足りず Grant を作る API 全体が必要」という見立ての、
コード上の裏付けである。しかも Grant 単体ではなく、**Ticket と
Provisioning Key を含む発行側すべて**が同じ穴に落ちている。

### 4.0 ただし「面が無い」は言い過ぎだった（#351 で確認）

この節の `[raw]` は「`portal-server` が `ProxyClient` のメソッドを直接呼んで
いる」という**形**の記述で、**届かない**という意味ではなかった。実際には:

- 発行側が使う型 10 個はすべて `isekai_p2p::agent` から再輸出されている ——
  戻り値（`Grant`, `Made`, `Ticket`, `TicketRecord`, `ProvisioningKey`,
  `ProvisioningKeyRecord`, `ProvisioningRedemption`）、入力
  （`ProvisioningBinding`）、戻り値の中の型（`TicketRedemption`）、
  引き換え側の `TicketTransfer`。
- `portal-server` は **`isekai-p2p-core` に一度も依存していない**
  （`Cargo.toml` に記載が 0）。にもかかわらず 8 メソッドすべてを呼べている。
  これが「`isekai-p2p` だけで届く」ことの証明である。

つまり面はある。形がモジュール関数ではなく、再輸出されたクライアントの
メソッド、というだけだった。

**ただし 1 つ欠けている**: `ControlPlaneTransport` が `agent` から再輸出されて
いない（出現 0）。`ProxyClient<T>` はこのトレイトにジェネリックなので、
外から「トランスポートに対してジェネリックな関数」を書こうとすると
**境界を名指せない**。`p2p_sdk_api_review.md` §6-10 が
「`ControlPlaneTransport` という継ぎ目は既にあるのに使われていない」と
書いているのと同じ話で、名指せないことがその一因である。#351 で再輸出した。

### 4.1 先例は同じクレートの中にある

Identity 側の管理（クラスタ B・C）は**すでに包まれている**:
`isekai_p2p::endpoints::{list, get, revoke}`、
`isekai_p2p::enrollment::{Identity::new, issue, list, enrollments, revoke}`、
`isekai_p2p::membership::{me, describe}`。portal-client はこれを使っている
（`main.rs:1537`, `:1559`, `:1605`, `:1682`, `:1721`, `:1754`, `:1021`）。

さらに、**資格情報の操作でも包みは既に機能している**: 引き換え 2 件は
portal のどこからも生クライアントで呼ばれず、`isekai_p2p::PeerDirectory` 経由
（`portal-client/src/main.rs:1240`, `:1291`, `portal-core/src/grant.rs:101`）。
`issue_capability` も `portal_core::session::Session`（`session.rs:107`）が
`ListenerCommand::IssueCapability` を `listener::run` に送る形で、
**portal が完全に包み越しで届いている唯一の資格情報メソッド**
（`portal-server/src/main.rs:1940`）。発行側だけが素通しなのは、
包めないからではない。

形は「クライアントとトークンを取る薄いモジュール関数」。

**ただしこの先例の値打ちは、proxy 側にはそのままの形では移らない（#351）。**
`endpoints`/`enrollment` が存在する一番の理由は `enrollment.rs` の
`on_transport!` マクロが示している —— Identity API は HTTP/1.1+2 と H3 の
2 系統があり、**どちらで喋るかを呼び出し側から隠す**のが包みの仕事である。
加えて `IdentityError` を `anyhow` に変え、`endpoints::revoke` のように
`RevokeAuth` を組み立てる（`endpoints.rs:75`。`enrollment.rs` ではない）。

proxy 側で対応するのは、**実務上は**トランスポートの選択が無いことである:
`proxy_client(cfg, &token)` は `ProxyClient<MasqueH3Transport>` を具体型で返し、
呼び出し側はそれを持っている。

**「常に 1 つ」は型の上では誤り。** `ControlPlaneTransport` は
`MasqueH3Transport` と `HttpsTransport`（`https.rs:97`）の 2 つが実装していて、
Identity 側と同じ二択が型としては存在する。違うのは、
`ProxyClient<HttpsTransport>` を組む production のコードが 1 つも無いことで、
だから隠すべき選択が今はない。Identity 側との非対称は歴史でも
問題の違いでもなく、**同じ継ぎ目が使われていない**というだけである。

### 4.2 発行側には「素通しでは足りない」意味論がある

生クライアントを渡すだけでは済まない根拠が、すでに portal 側に溜まっている。

- **`create_grant` は upsert**。プロキシは既存 id を `200` で返し `created_at` を
  据え置く。新規作成と再作成の区別は `created_at` の経過時間を
  30 秒の窓（`ExistedBefore::WINDOW`）と比べて推定するしかなく、その判定は
  `already_existed` として実装された（当時はアプリ側の
  `portal-core`。#350 で `isekai_p2p::grants` に移した）。
- **Gateway は Grant を方針から調停する**。`portal-core` の `Ledger` が
  `Wanted` / `Changes` を計画し（`gateway/grants.rs`）、
  `portal-server` の `settle_grants`（`main.rs:982`）が
  `create_grant` / `revoke_grant` を実行し、`note_existing_grants`（`:1093`）が
  既存分を台帳に取り込む。
- **期限の意味が 3 通りある**: `--grant-expires-in`（プロキシが決める失効）、
  `--grant-ttl`（Ticket が作る Grant の寿命）、`None`（取り消されるまで）。
  `grant_lifetime_lines`（`:401`）はプロキシが返した `expires_at` を読み、
  無視された要求を注記し、upsert を見分けて報告する。

**これらはすべて「Grant を作る」という 1 行の API の外側に積まれた知識**で、
SDK がその API を出すなら一緒に出す対象になる。

### 4.3 素通しは足さない。ただし足す価値のあるものが 2 つある（#351）

**8 メソッドのうち 7 つ**（`create_grant` を除く —— それは下記）を
`portal-server` で読むと、**すべてが同じ形**だった:

```rust
proxy.method(args...).await.context("…")?
```

に続いて `println!`。呼び出しの直前後に持ち上げられるロジックは無く、
その 7 つに素通しの関数を足して得られるのは `anyhow::Result` への変換と
2 つ目の名前だけである。それは #350 で `already_existed` を portal-core から
再輸出しないと決めた理由 ——「そのクレートが呼ばない関数への 2 本目の経路は、
同期を取り続ける名前が増えるだけ」—— に正面から反する。

**除いた 1 つが反例である。** `create_grant` の周りには実際にロジックがあり、
それは `settle_grants`（`main.rs:982`）、`note_existing_grants`（`:1093`）、
`grant_lifetime_lines`（`:401`）、そして `DELETING` の読み（`:1194`）として
すでに別の形で入っている。だから結論は「発行側に何も足さない」ではなく
**「素通しは足さない」**である。

**§4.2 が挙げた意味論のうち 3 つは入り、1 つはアプリ側に残った:**

| 意味論 | どこに入ったか |
| --- | --- |
| upsert を新規作成と見分ける | `Made`（#345）。成功時も status を残す内部経路つき |
| 自分が作ったものだけ消す台帳 | `isekai_p2p::grants::Ledger`（#350） |
| 3 通りの「期限」を運用者に説明する | `grant_lifetime_lines`（#337） |
| 答えを呼び出し側の行動に翻訳する | `Outcome` と `Reading`（#347, #349） |
| **方針から Grant を調停する** | **入っていない**。`Wanted` / `Changes` / `plan` / `plan_now` は `portal-core` に残る（#350 の分割点。§9-2 のとおり意図的） |

#### 足す価値があるもの 1 — ルートの `Reading`

3 つの revoke が**同じ形の答えを別に扱っている**。`is_already_gone` は
grant の delete を `Outcome::of_proxy(e, &DELETING)` で読むのに
（`main.rs:1194`）、`revoke_ticket`（`:1531`）と
`revoke_provisioning_key`（`:1613`）は `?` で落とすだけで、
`ProxyError` は非 2xx を一律 `Err` にする。
`--revoke-ticket` のコメント自身が「the id may never have existed」を
受け入れられる結末として挙げているのに、それが届いたら run は失敗する。

**到達可能性は確かめられていない**（プロキシが存在しない id に `204` を返すなら
そもそも起きない。コメントの「`204` says almost nothing」はそう読める）。
それでも 3 経路が食い違っていること自体は限界として記録に値する。

#### 足す価値があるもの 2 — 一覧の行の読み方（#352 で入れた）

これは**すでに重複していた**。binding 種別の分類が
`portal-server/src/main.rs` と `portal-client/src/main.rs` に**逐語で同じもの**
として存在し、client 側のコメントが「the same as on the server's side」と
書いていた:

```rust
Some("none") | Some("") | None => "UNBOUND".to_owned(),
```

**2 つの record が同じ型を持っていた**のが決め手である:
proxy 側の `ProvisioningKeyRecord.binding` と Identity 側の
`EnrollmentKeyRecord.binding` はどちらも `Option<BindingView>`。
だから読み方は `BindingView` の隣の 1 箇所に置ける ——
`Bound` と `bound_to(Option<&BindingView>)`。

**分類だけを持ち上げ、表示は残した。** どの入力が「素の bearer secret」を
意味するか（不在・空文字・`"none"` の 3 つ）は 1 箇所に集め、
未知の種別を `Other` として報告する。一方で表示は 2 つで違っていて
正しい —— server は subject を出し、client は出さない。

危険な向きは両方テストで固定した: 空文字を `Other` に落とすと素の secret を
「束縛済み」と言い、未知の種別を `Nothing` に落とすと束縛済みを素と言う。
どちらの改変でも対応するテストが落ちる。

残っている重複は**枠の表示**（`(Some(live), Some(max)) => "{live}/{max} slots"`）
だが、こちらはフィールド名も予備語も違う（`live_grants`/`live_endpoints`、
`"grants"`/`"live"`）ので、同じ形をした別のコードである。持ち上げるなら
記録の型ごとのメソッドになる。

### 4.4 API の形の問題 — `ttl` がメソッドを跨いで意味を変える

```rust
create_grant(allowed_endpoint, protocol, ttl, label)
create_ticket(protocol, ttl, grant_ttl, label)
create_provisioning_key(protocol, ttl, grant_ttl, max_live_grants, binding, label)
```

`create_grant` の `ttl` は **Grant** の寿命である（`main.rs:1463` が
`args.grant_expires_in` を渡している）。`create_ticket` の `ttl` は
**券**の寿命で、Grant の寿命は隣の `grant_ttl`。つまり
**同じ名前が隣接するメソッドで別のものを指す**。
さらに `create_provisioning_key` は `Option<u64>` を **3 つ**並べる
（`ttl` / `grant_ttl` / `max_live_grants`）。

`p2p_sdk_api_review.md` §6-6（enum であるべきものが `Option<&str>`）と
同じ種類の摩擦で、直し方も同じ: 名前のある型にする。ただしそれは
`isekai-p2p-core` の署名を変える話で、**2 本目の経路を足すのとは逆方向**である。

**CLI 側の混同はこれとは別の話。** `check_grant_options`（`main.rs:441`）が
守っているのは `--grant-ttl` と `--grant-expires-in` という**2 つのフラグ**の
取り違えで、位置引数の転置ではない。ただし根は同じ —— `--grant-ttl` が
どの寿命なのかが名前から決まらないこと —— で、「`--grant` と一緒に渡すと
**日付のない Grant を作って何も言わなかった**」という代償が記録されている。

## 5. リレー計測について — 必要なのは「駆動」ではなく「点検」

「接続もリレーの RTT などを計測する API が必要」という点は、確認したところ
**計測そのものは既に自動**だった。

- **掛け側**: `InitiatorSession` の接続経路が内部で
  `relay_rtt::measure_for_connect` を呼び（`initiator.rs:1049`）、
  その結果で `peer_connect_measured` / `peer_connect_with_grant_measured` を
  叩く（`:1058`, `:1070`）。呼び出し側は何もしない。
- **受け側**: `ListenerSession` が `RelayRttReporter` を持ち、
  session 作成時に `spawn` する（`listener.rs:85`, `:429`）。
  即座に 1 回、以後 `REPORT_INTERVAL` ごとに報告する。

したがって発行側（§4）とは事情が違い、**面が無いのではなく、面を出す必要がない**。
一方で portal が実際に API として使っているのは**点検の面**だった:
`--relays` が `relay_rtt::{measure, observe_families}` と `list_relays` を直接呼び、
RTT とアドレスファミリの観測を表に出す（`portal-client/src/main.rs:1075`, `:1085`）。

SDK に要るのはこちら側 —— **何が観測されたかを読む面と、`ProbeOptions` を
調整する面**。自動の経路を呼び出し側に駆動させる面は要らない。

## 6. FFI の 4 概念で足りないもの

§2 のクラスタを FFI の面と突き合わせた差分。

- **クラスタ E/F/G 全部** — 資格情報の発行・一覧・取り消し。FFI には
  `pair_with_code` しかなく、Grant を作る・見る・取り消す面が一つもない。
- **クラスタ B/C** — Endpoint と Enrollment Key の管理。`isekai-p2p` には面が
  あるが FFI は通していない。
- **クラスタ I の点検** — `--relays` 相当。FFI に相当物なし。
- **クラスタ H の一部** — `Narrowing`（`--gateway`）と `device_name`（`--task`）。
  `portal-client-ffi` は `narrowing: Default::default()` 固定
  （`lib.rs:109`）＝ 上限のまま、`device_name` も
  `"portal-client-android"` 固定（`:106`）。
- **イベント** — ここは「無い」のではなく、**FFI 2 本の間で非対称**だった。
  `isekai-client-ffi` は `#[uniffi::export(callback_interface)]` の
  `FrameSink`（`lib.rs:205`）を持ち、`on_state`（接続状態の遷移）、
  `on_path`（経路が増えた／移った）、`on_rtt`、`on_frame`、`on_log` を
  境界の向こうへ渡す。Kotlin 側（`ViewerModel.kt`）と Swift 側
  （`ViewerSink.swift:33`, `:41`）に実装がある。
  一方 `portal-client-ffi` は `is_closed()` のポーリングだけで、
  自身のコメントがそう明言している。
  つまり **§4.1 と同じ形の非対称**で、設計の先例はすでに存在する。

逆に、FFI にあって Rust 層に面が無いものもある: **締め切り**
（`APP_PAIR_DEADLINE` / `APP_CONNECT_DEADLINE`）。
`p2p_sdk_api_review.md` §5.3 のとおり、下に一つもない。

## 7. 逆算した「必要な面」の候補

ここまでを束ねると、SDK が覆うべき領域は 4 概念ではなく **7 群**になる。
※ これは**要求の一覧**であり、API の形の提案ではない。

1. **身元** — 鍵、サインイン（人／無人の両方）、Endpoint Token、`Narrowing`。
   クラスタ A。現状 `isekai-p2p` にある。
2. **自分の棚卸し** — 自分の Endpoint 群と Enrollment Key の一覧・取り消し。
   クラスタ B・C。`isekai-p2p` にあるが FFI に出ていない。
3. **アクセスを与える（発行側）** — Grant / Ticket / Provisioning Key の
   作成・一覧・取り消し、ラベル、3 種の期限、upsert の意味論、方針からの調停。
   クラスタ E・F・G。**面はある（§4.0）。意味論は 4 つのうち 3 つ入った（§4.3）。**
   残るのは素通しではない 2 つ（ルートの `Reading`、一覧の行の読み方）と、
   `ttl` がメソッドを跨いで意味を変えること（§4.4）。
4. **アクセスを受け取る（引き換え側）** — ペアリングコード、Ticket、
   Provisioning Key の引き換え。クラスタ D。`isekai-p2p` にある。
5. **繋ぐ** — Listener / Initiator、ローカルの待受けと転送先、
   relay-only の選択。クラスタ H。`isekai-p2p` にあるが、転送そのものは app。
6. **点検** — リレーの RTT とアドレスファミリの観測、観測アドレス、
   経路（レグ／直結）の状態。クラスタ I ＋ H の一部。**面はあるが低位**（§5）。
7. **寿命と締め切り** — 終了順序、締め切り、セッションの状態通知。
   **締め切りはどこにも面が無く**、FFI が各自で被せている（§6 末尾、
   `p2p_sdk_api_review.md` §5.3）。終了順序も型に現れない（同 §5.2）。
   一方**通知の面は `isekai-client-ffi` の `FrameSink` に既にある**ので、
   ここで新規に設計すべきなのは「締め切りと終了順序」だけで、
   通知は先例を広げる話になる（§6）。

## 8. SDK に出さない候補 — 消費者ゼロの面

逆算の副産物として、**定義と自分の単体テストしか無い**制御プレーン API が出た。
「クレート外に消費者がいない」より強い条件で、内部利用も無いもの:

| API | 出現 |
| --- | --- |
| `delete_public_listener` | 定義（`proxy.rs:1637`）＋自分のテスト 1 |
| `get_peer_listener` | 定義（`:1548`）のみ |
| `peer_connect_with_grant` | 定義（`:2295`）＋自分のテスト 1（`_measured` 版だけが使われている） |
| `ProxyClient::get_certificate` | 定義（`:2331`）＋自分のテスト 2 |

`p2p_sdk_api_review.md` §3.4 の一覧とは**条件が違う**ので、混ぜてはいけない。
あちらは「クレート外の参照 0」で、内部利用は除いていない。実際その 5 件は
すべて内部で使われている: `measure_for_connect` は接続経路から
（`initiator.rs:1049`、§5）、`RelayRttReporter` は `ListenerSession` から
（`listener.rs:429`、§5）、`poll_signaling` と `ListenerEvent` は
`listener::run` から、`open_public_bind_session` は `public.rs:286` から。
**どれも面を畳む対象ではない** —— 外部に出すかどうかの判断材料であって、
消せる面の一覧ではない。畳める候補は上の表の 4 件だけ。

## 9. Q2 への入力 — 区別が要るエラー

§2 のクラスタから、**どの失敗を区別できないと機能が成立しないか**を拾った。
`p2p_sdk_api_review.md` §5.4 のとおり、`ProxyError` は
`status` / `problem.kind` / `detail` / `retry_after` を持っているのに、
編成層の `anyhow` と FFI の文字列化で失われる。

| 区別したい失敗 | どのクラスタが要求するか | 現状の `ProxyError` 側の材料 |
| --- | --- | --- |
| 資格情報が期限切れ／取り消し済み | D, E, F, G | `status` + `problem.kind` |
| 相手が拒否した（Grant が無い・narrowing 外） | H | `problem.kind` |
| 枠が尽きた（`max_live_grants` 等） | E, G | `429` + `provisioning-slots-exhausted` + `retry_after` |
| 一時的に落ちている（再試行すべき） | 全部 | `503` + `retry_after` |
| 作ろうとしたものが既にあった（upsert） | E | `200` + `created_at`（§4.2） |
| 認証のやり直しが必要 | A | `401`/`403` + `IdentityError` |
| ネットワークが死んでいる | 全部 | `ProxyError::Transport` |
| 締め切り超過 | 全部 | **材料なし**（§6 末尾） |

つまり Q2 で必要な分類は **8 種**で、うち 7 種は下層に材料があり、
失われているのは上の 2 層だけ。残る 1 種（締め切り）は材料そのものが無い。

## 10. 残っている問い

本文書は面の広さ（Q1）の下敷きで、**面の確定はしていない**。逆算の結果として
新たに決める必要が出たもの:

1. **発行側（§7-3）をどの層に置くか** — **半分決着（#351）**。
   面は再輸出された `ProxyClient` として既にあり（§4.0）、8 メソッドのうち
   7 つに素通しの関数を足しても 2 つ目の名前しか増えない（§4.3）。
   §4.2 の意味論は 4 つのうち 3 つが #337 / #345 / #347 / #349 / #350 で
   入り、方針調停だけが意図的に `portal-core` に残った。
   **素通しではない 2 つのうち 1 つは入れた**（#352、§4.3）: 一覧行の
   binding 種別の分類を `Bound` / `bound_to` として `BindingView` の隣へ。
   残るのはルートの `Reading`（3 つの revoke が食い違っている。到達可能性は
   未確認）と、API の形の問題 1 件（§4.4）。
2. ~~**upsert と方針調停（§4.2）は誰のものか**~~ — **決着（#350）**。
   `already_existed` / `existed_before` / `Ledger` は `isekai_p2p::grants` に
   移した。分割点は方針テーブルが始まるところで、`Table` を読む
   `plan` / `plan_now` / `Wanted` / `Changes` はアプリ側に残る。
   `plan` がレジャーから必要とするのは「自分が作った全部」だけで、
   `Ledger::ours()` がそれを出す。
3. **点検の面（§7-6）をどこまで下げるか** — `FamilyProbe` や `legs()` のような
   低位の型をそのまま見せるか、要約を見せるか。
4. **§8 の消費者ゼロの面を畳むか** — 面を狭める好機だが、
   `get_peer_listener` のように「まだ使っていないだけ」の可能性もある。

## 11. 参照

- `docs/p2p_sdk_api_review.md` — 現状の API 設計（本文書はその §9 Q1 の下敷き）
- `docs/portal.md` — portal の操作手引き（クラスタ D–G の利用者向け記述）
- `docs/portal_gateway_plan.md` — Gateway と Grant の方針調停
- `docs/portal_agent_plan.md` — `Narrowing` と agent モード
- `docs/relay_proximity_client.md` — `--relays` と `ProbeOptions`
