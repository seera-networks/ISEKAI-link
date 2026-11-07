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

`portal-server` の 47 フラグと `portal-client` の 50 フラグを 9 クラスタに束ねた。

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

FFI の 4 概念が覆っているのは **D の一部（受け取り側）と H の一部**だけ。

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
| E | `create_grant` **[raw]**, `list_grants` **[p2p+raw]**, `revoke_grant` **[p2p+raw]**, `issue_capability` **[p2p+raw]**, upsert の判定 `already_existed` **[app]** |
| F | `create_ticket` **[raw]**, `list_tickets` **[raw]**, `revoke_ticket` **[raw]**, `redeem_ticket` **[p2p+raw]** |
| G | `create_provisioning_key` **[raw]**, `list_provisioning_keys` **[raw]**, `provisioning_redemptions` **[raw]**, `revoke_provisioning_key` **[raw]**, `redeem_provisioning_key` **[p2p+raw]** |
| H | `ListenerSession`, `InitiatorSession`, `RelayOptions`, `listener::run`, `direct_path`, `legs()`, `observed_address()`, `Narrowing`（`--gateway`）, `device_name`（`--task`） | **[p2p]** + 転送・ルーティングは **[app]** |
| I | `relay_rtt::{measure, observe_families}` + `list_relays` **[p2p]** / 同意は **[app]** |

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
| `redeem_ticket` | `initiator.rs` | `portal-client/src/main.rs` |
| `create_provisioning_key` | **なし** | `portal-server/src/main.rs` |
| `list_provisioning_keys` | **なし** | `portal-server/src/main.rs` |
| `provisioning_redemptions` | **なし** | `portal-server/src/main.rs` |
| `revoke_provisioning_key` | **なし** | `portal-server/src/main.rs` |
| `redeem_provisioning_key` | `initiator.rs` | `portal-client/src/main.rs` |

**`isekai-p2p` が包んでいるのは「引き換える側」と、Grant の「読む／取り消す」だけ。
資格情報を発行・一覧する面は 8 メソッド分まるごと無く**、portal-server は
`isekai_p2p::agent::ProxyClient` という**再輸出された生クライアント**を受け取って
自分で叩いている（`main.rs:39`）。つまり `isekai-p2p` はこの領域に対して
抽象を持たず、素通しの窓だけを開けている。

これは「ペアリングだけでは足りず Grant を作る API 全体が必要」という見立ての、
コード上の裏付けである。しかも Grant 単体ではなく、**Ticket と
Provisioning Key を含む発行側すべて**が同じ穴に落ちている。

### 4.1 先例は同じクレートの中にある

Identity 側の管理（クラスタ B・C）は**すでに包まれている**:
`isekai_p2p::endpoints::{list, get, revoke}`、
`isekai_p2p::enrollment::{Identity::new, issue, list, enrollments, revoke}`、
`isekai_p2p::membership::{me, describe}`。portal-client はこれを使っている
（`main.rs:1537`, `:1559`, `:1605`, `:1682`, `:1721`, `:1754`, `:1021`）。

形は「クライアントとトークンを取る薄いモジュール関数」。発行側に足すべき面も
**この先例に倣えばよく、新しい設計を要らない**。欠けているのは
proxy 側だけで、Identity 側との非対称は歴史的なものに見える。

### 4.2 発行側には「素通しでは足りない」意味論がある

生クライアントを渡すだけでは済まない根拠が、すでに portal 側に溜まっている。

- **`create_grant` は upsert**。プロキシは既存 id を `200` で返し `created_at` を
  据え置く。新規作成と再作成の区別は `created_at` の経過時間を
  30 秒の窓（`ExistedBefore::WINDOW`）と比べて推定するしかなく、その判定は
  `portal_core::gateway::grants::already_existed` に**アプリ側で**実装された。
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
RTT とアドレスファミリの観測を表に出す（`portal-client/src/main.rs:1074`, `:1085`）。

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
- **イベント** — `is_closed()` のポーリングだけ。Grant が取り消された、
  レグが張り替わった、といった通知の面がない。

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
   クラスタ E・F・G。**面が無い（§4）。ここが最大の欠落。**
4. **アクセスを受け取る（引き換え側）** — ペアリングコード、Ticket、
   Provisioning Key の引き換え。クラスタ D。`isekai-p2p` にある。
5. **繋ぐ** — Listener / Initiator、ローカルの待受けと転送先、
   relay-only の選択。クラスタ H。`isekai-p2p` にあるが、転送そのものは app。
6. **点検** — リレーの RTT とアドレスファミリの観測、観測アドレス、
   経路（レグ／直結）の状態。クラスタ I ＋ H の一部。**面はあるが低位**（§5）。
7. **寿命と締め切り** — 終了順序、締め切り、セッションが死んだ通知。
   **現状どこにも面が無く、FFI が各自で被せている**（§6 末尾）。

## 8. SDK に出さない候補 — 消費者ゼロの面

逆算の副産物として、**production の消費者が一つも無い**制御プレーン API が出た。
定義と自分の単体テストだけのもの:

| API | 出現 |
| --- | --- |
| `delete_public_listener` | 定義（`proxy.rs:1637`）＋自分のテスト 1 |
| `get_peer_listener` | 定義（`:1548`）のみ |
| `peer_connect_with_grant` | 定義（`:2295`）＋自分のテスト 1（`_measured` 版だけが使われている） |
| `ProxyClient::get_certificate` | 定義（`:2331`）＋自分のテスト 2 |

`p2p_sdk_api_review.md` §3.4 の消費者ゼロ一覧
（`poll_signaling`, `ListenerEvent`, `measure_for_connect`, `open_public_bind_session`）
に続くもの。なお同一覧の `RelayRttReporter` は**内部で使われている**
（§5 のとおり `ListenerSession` が spawn する）ので、面を畳む対象ではない。

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

1. **発行側（§7-3）をどの層に置くか** — §4.1 の先例に倣って `isekai-p2p` に
   薄いモジュールを足すか、SDK のハンドルの一部にするか。
2. **upsert と方針調停（§4.2）は誰のものか** — `already_existed` と `Ledger` は
   今アプリ側にある。SDK が `create_grant` を出すなら、これも一緒に出るのか、
   アプリに残すのか。
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
