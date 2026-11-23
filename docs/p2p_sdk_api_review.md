# ISEKAI link p2p — 現状の API 設計

- status: 現状記述（as-is）。再設計の提案ではない
- version: 0.1
- 対象: `7032efc`（`rust/isekai-p2p`, `rust/isekai-p2p-core` および現在の利用側）

## 1. この文書の目的と範囲

ISEKAI link p2p を**外部に提供する SDK として使えるようにするか**を検討するための
材料として、**今そこにある API** を棚卸しする。

- 書くもの: 公開されている型・関数、層の分かれ方、利用側が実際に書く呼び出し列、
  API が暗黙に要求している約束事（ランタイム、終了順序、タイムアウト、エラー）、
  そして SDK 化の観点で摩擦になる箇所の**証拠つきの一覧**。
- 書かないもの: 望ましい API の提案、移行計画、互換性方針。これらは本文書を
  入力として別途決める（§9 に決めるべき問いだけ残した）。

`docs/p2p_library_plan.md` は「CLI だけにあった機能をライブラリ化し camera アプリから
使う」という**ワークスペース内再利用**の計画で、現在の形の出発点である。本文書は
その結果として出来上がった面を、**ワークスペース外の利用者**の視点で測り直すもの。

## 2. 層の構成

```
  Kotlin / Swift アプリ (android/, android-portal/, ios/)
        │  uniffi
  ┌─────┴──────────────────────────────────────────────┐
  │ isekai-client-ffi (1,133 行)  portal-client-ffi (788 行)  ← 事実上の SDK、2 本
  └─────┬──────────────────────────────────────────────┘
  ┌─────┴──────────────────────────────────────────────┐
  │ camera-core (1,571 行)        portal-core (11,709 行)     ← アプリ固有の編成
  └─────┬──────────────────────────────────────────────┘
  ┌─────┴──────────────────────────────────────────────┐
  │ isekai-p2p (214 公開アイテム)                             ← 2 つのセッション型
  └─────┬──────────────────────────────────────────────┘
  ┌─────┴──────────────────────────────────────────────┐
  │ isekai-p2p-core (248 公開アイテム, feature = "msquic")     ← プロトコル部品
  └────────────────────────────────────────────────────┘
```

公開アイテム数は `pub fn|struct|enum|trait|type|const|mod` の grep 概数。**合計 462**。
内訳の大きいものは `proxy.rs` 108、`identity.rs` 60、`auth0.rs` 31、`initiator.rs` 28、
`listener.rs` 26。

CLI も同じ層に乗っている: `isekai-p2p` 自身が `[[bin]] isekai-agent` を持つ。
`isekai-p2p` に直接依存するのは `camera-core`, `portal-core`,
`isekai-client-ffi`, `portal-client-ffi`, `portal-client`, `portal-server`,
`utils`。**`camera-server` と `camera-client` は含まれない** — この 2 つは
`camera-core` の再輸出を通し、`isekai_p2p` を一度も名指ししない。
つまり camera 側は上図のとおりアプリ core の上に乗り、portal 側は CLI が
`isekai-p2p` を直接叩く、という非対称がある。

### 2.1 feature ゲート

`isekai-p2p-core` は `default = []`、`msquic` feature で
`transport` / `bind` / `observed` / `datapath` の 4 モジュールが生える。
`isekai-p2p` は feature を持たず、`isekai-p2p-core` を
`features = ["msquic"]` で固定依存する（`rust/isekai-p2p/Cargo.toml:19`）。

つまり **`isekai-p2p` を使う＝msquic ネイティブスタックを必ず引く**。
feature なしでビルドできるのは `isekai-p2p-core` 単体のときだけで、これは
`proxy.rs` の wire 型が純粋に保たれている理由でもある（`RelayReach::families` が
enum ではなく `Vec<String>` なのはこの制約から来ている）。

## 3. 公開 API の棚卸し

### 3.1 `isekai-p2p-core` — プロトコル部品

| モジュール | 役割 | 代表的な公開面 |
| --- | --- | --- |
| `endpoint` | Endpoint 鍵と ID | `EndpointKey`, `ENDPOINT_ID_PREFIX`, `EndpointError` |
| `pop` | リクエストごとの所有証明 | 署名の生成・検証 |
| `identity` | Identity API クライアント | `IdentityClient<T>`, `Narrowing`, `IdentityError` |
| `proxy` | 制御プレーンのクライアントと wire 型 | `ProxyClient<T>` (`proxy.rs:1461`), `ControlPlaneTransport` (`:120`), `ProxyError` (`:152`), `Grant` (`:568`), `PeerConnection` (`:1376`) |
| `transport` † | MASQUE/H3 トランスポート | `MasqueH3Transport` (`transport.rs:107`), `AddressFamily`, `Binding`, `Landing` |
| `bind` † | リレーのレグを開く | `open_bind_session` (`:462`), `open_public_bind_session` (`:534`), `open_connect_relay` (`:847`), `RelayOptions` (`:64`) |
| `observed` † | 相手から見えた自分のアドレス | `ObservedAddress`, `ObservedAddressWatch` |
| `datapath` † | データパスへのフック | `DatapathHook`, `Hop`, `Verdict` |
| `certificate` / `hostname` / `https` / `mtu` / `attestation` | 補助 | — |

† は `msquic` feature 付き。

### 3.2 `isekai-p2p` — 編成（orchestration）

公開面の中心は 2 つのセッション型。

**`ListenerSession`**（受け側、`listener.rs`）

```
create                        (cfg, forward_to, ttl)                       :359
create_with_options           (cfg, forward_to, ttl, opts)                 :375
create_with_token             (cfg, endpoint_token, forward_to, ttl)       :391
create_with_token_and_options (cfg, endpoint_token, forward_to, ttl, opts) :409
```
以降 `issue_capability(allowed_endpoint, ttl)` `:479`、
`bind(connection_id, relay_base_url, relay_family, info_family)` `:520`、
`legs()` `:472`、`observed_address()`、`show_pairing_code`、`list_grants`、
`revoke_grant`、`poll_signaling` `:703`、`subscribe`、`renew_connections`、`close`。

**`InitiatorSession`**（掛け側、`initiator.rs`）

```
connect                        (cfg, capability, listener_id, candidates, local_bind)             :642
connect_with_options           (cfg, capability, listener_id, candidates, local_bind, opts)       :668
connect_with_token             (cfg, token, capability, listener_id, candidates, local_bind)      :693
connect_with_token_and_options (cfg, token, capability, listener_id, candidates, local_bind, opts):715
connect_with_grant             (cfg, listener_id, candidates, local_bind, opts)                   :743
connect_with_grant_and_token   (cfg, token, listener_id, candidates, local_bind, opts)            :765
PeerDirectory::connect         (&self, cfg, listener_id, candidates, local_bind, opts)            :614
```
以降 `local_addr()`、`connection()`、`connection_id()`、`observed_address()`、
`relay_leg()` `:917`、`video_host()`、`ended()`、`stop_replacing_the_leg()`、`close`。

**設定と資格情報**: `P2pConfig` は 9 フィールドのフラットな構造体
（`config.rs:30`）。`Credential`（`auth.rs:68`）が人の Auth0 サインインと
無人ジョブ用 Enrollment Key を束ねる。自由関数は
`issue_endpoint_token` `:89`、`proxy_client` `:272`、`load_or_generate_key` `:75`、
`list_policies` `:156`、`policy_stream` `:174`。

**チャネル駆動のドライバ**: `listener::run(session, cmd_rx, policy, events, shutdown)`
（`listener.rs:1203`）＋ `ListenerCommand` / `SignalingEvent` / `AcceptPolicy`
（`Auto` / `AutoNotify` / `Manual`、`:90`）。Rust 層の中で最も SDK 的な形をした
唯一の面で、`portal-core` はここを使っている。

**再輸出モジュール `agent`**: `isekai-p2p-core` の型を 15 本の `pub use` で
転送する手編みの面。`portal-core` / `camera-core` は `isekai-p2p-core` に
直接依存せず、ここだけを通る。

### 3.3 FFI — 既存の「SDK」

uniffi による 2 本。**ほぼ同じ形が 2 回書かれている。**

| | `portal-client-ffi` | `isekai-client-ffi` |
| --- | --- | --- |
| 鍵 | `generate_endpoint_key_pem`, `endpoint_id_of` | 同じ 2 本 |
| ペアリング | `pair_with_code` (`:144`) | `pair_with_code` (`:657`), `pairing_code_in_scan` |
| 接続 | `connect` (`:380`) | `connect` (`:765`), `list_cameras` |
| セッション | `PortalSession { local_port, is_closed, disconnect }` | `ViewerSession { connection_id, path_status, migrate, disconnect }` |
| 設定 | `PortalConfig`（7 フィールド） | `ClientConfig` |
| エラー | `PortalError` | `ClientError` |

この 2 本が実際には「SDK の形」をすでに示している: **鍵を作る / 相手と繋がる /
ローカルポートを得る / 切る**。ただしアプリ固有で、Rust API からその都度手で導出された。

### 3.4 アプリ層が自分で書いている部分

`isekai-p2p` の上に、利用側が相当量を書いている。`portal-core` だけで 11,709 行、
`session` / `path` / `grant` / `consent` / `datagram` / `frame` / `udp` などに分かれる。

p2p の部品のうち**利用側が手で駆動している**もの:

| 部品 | 駆動している場所 |
| --- | --- |
| `direct_path::advertise` | 2 箇所: `portal-core/src/session.rs:269`, `camera-core/src/video.rs:167` |
| `direct_path::{prefer_path, RelayPath}` | `portal-core/src/path.rs:117`, `camera-core/src/video.rs:25` |
| `legs()` / `relay_leg()` | 4 箇所: `camera-core/src/server.rs:158`, `portal-core/src/session.rs:251`, `portal-client/src/main.rs:888`, `portal-client-ffi/src/lib.rs:455` |
| `observed_address()` | 5 箇所: `portal-core/src/session.rs:838`, `camera-core/src/server.rs:152`, `camera-client/src/main.rs:434`, `isekai-client-ffi/src/lib.rs:918`, `camera-core/examples/relay_migration_e2e.rs:195` |
| `relay_rtt` | `portal-client/src/main.rs` **のみ** |
| `DatapathHook` | テストと example のみ |

FFI の 2 本が `relay_leg()` と `observed_address()` を直接使っている点に注意。
§3.3 で「事実上の SDK」と呼んだ層自身が、低位の面を消費している。

逆に、**公開されているが利用側に消費者がいない**面:
`poll_signaling`、`RelayRttReporter`、`ListenerEvent`、`measure_for_connect`
（いずれもクレート外の参照 0。`poll_signaling` は `listener::run` 経由でのみ到達される）。
`open_public_bind_session` も `agent` へ再輸出されているが、外部利用は 0
（`isekai-p2p/src/public.rs:286` が唯一の呼び出し元）。

## 4. 典型的な呼び出し列

`portal-core/src/session.rs` が実際に通る順序（これが現状の「使い方」の実例）。

**受け側**: `issue_endpoint_token` → `proxy_client` →
`ListenerSession::create_with_token_and_options`（`:222`）→ `session.legs()` を
`RelayLegs::PerConnection` に包む → `listener::run` に `ListenerCommand` の
チャネルを渡して駆動 → `SignalingEvent` を見て `direct_path::advertise` を呼ぶ →
終了時に `peer::drain_registration`。

**掛け側**: `issue_endpoint_token` → `InitiatorSession::connect_with_options`
（`:733`）→ `observed_address()` を watch → `local_addr()` に自前の転送を繋ぐ →
`close()` → `drain_msquic` / `shutdown_msquic`。

この 1 フローのために `portal-core/src/session.rs` が `isekai_p2p` から
入れている名前は、7 つの `use` 文で **17 個**:
`ReachableListener`, `RelayOptions`, `direct_path`(self), `RelayLegs`,
`endpoint_cert`, `run`, `ListenerCommand`, `AttestedPeer`, `PeerSession`,
`issue_endpoint_token`, `proxy_client`, `AcceptPolicy`, `InitiatorSession`,
`ListenerSession`, `P2pConfig`, `PeerDirectory`, `SignalingEvent`。
さらに `peer::drain_registration`（`:154`）と `agent::ObservedAddress`（`:837`）を
フルパスで呼ぶので、**合計 19 の入口**を 1 ファイルが掴んでいる。

## 5. API が暗黙に要求している約束事

ここは型に現れないが、守らないと壊れる部分。SDK 化では最も重要な領域。

### 5.1 ランタイムとプロセス全体の状態

- **tokio 必須**。公開シグネチャに `CancellationToken`（4 箇所）、
  `watch::Receiver`（1）、`mpsc::Receiver`（2）が現れる。
- **msquic の registration はプロセス全体で 1 つ**:
  `static REGISTRATION: Mutex<Option<Arc<msquic_async::Registration>>>`
  （`transport.rs:421`）。初回使用時に開き、以後すべての接続（制御プレーン、
  bind セッション、リレーのレグ）がここから下がる。
- したがって「1 プロセスに 2 つ独立したスタック」は現状できない。

### 5.2 終了順序

利用側が正しい順序で呼ぶ責任を持つ。

- `drain_msquic(timeout)`（`:460`）— 閉じずに排出し、**成否にかかわらず
  必ず** `std::mem::forget` で registration をリークする（`:476`、
  `if !drained` の外）。デストラクタを走らせずにプロセスを去る経路のためのもので、
  自身の doc が理由を書いている — 「終了経路で閉じて得るものはないので、ここは閉じない」。
- `shutdown_msquic(timeout)`（`:480`）— 排出してから閉じる。排出できたときだけ
  `drop`（＝`RegistrationClose` が走る）、**タイムアウトしたときに限って**
  `forget` でリークする。
- `peer::drain_registration(&reg, timeout)`（`peer.rs:110`）。

**2 つの違いは「いつリークするか」**: `drain` は常に、`shutdown` は失敗時だけ。
終了経路で `shutdown` を選ぶと、排出できた場合に `RegistrationClose` の
同期待ちへ入る。

守らなかった場合の症状は `portal-client-ffi` の `close_and_wait` に詳述されている:
`Runtime::drop` は実行中のタスクを中断するため、`close()` 途中で落とすと
リレーのレグがプロキシのリース切れまで予約されたまま未報告になり、さらに
最後の `Arc<Registration>` を `wait_idle()` 前に落とすと msquic 内部の
`RegistrationClose` で**同期・中断不能な待ち**に入る（isekai-link#176）。

**この知識は型にもドキュメントにも現れず、FFI のコメントにしかない。**

### 5.3 タイムアウトが存在しない

`portal-client-ffi/src/lib.rs` の `APP_PAIR_DEADLINE` のコメントが、
`issue_endpoint_token` / `PeerDirectory::open` / `pair` /
`ProxyClient::request_json` / `send` を読み下した結果として記録している:

> **No layer under this call has ever had a timeout**

FFI は自前で `APP_PAIR_DEADLINE`（30 秒）と `APP_CONNECT_DEADLINE` を被せている。
つまり**締め切りは API の責務になっておらず、各利用側が再発明している**。

### 5.4 エラーの型

二層に割れている。

- **下層は型つきで豊か**: `ProxyError`（`proxy.rs:152`）は `status`、
  `Problem`（kind と detail の両方）、`retry_after` を持つ。`IdentityError`、
  `EndpointError`、`AttestationError`、`RefreshError` も同様。
  宣言数で 74。
- **編成層は `anyhow`**: `anyhow::Result` を返す宣言が 117。
  `isekai-p2p` 自身が定義する独自エラーは `auth0::RefreshError` だけ。
- **FFI で文字列に潰れる**: `PortalError::Connect(format!("{e:#}"))` のように
  整形済み文字列になる。`portal-client-ffi` は `PortalError` を 13 箇所で
  構築し、そのうち 5 箇所が `format!("{e:#}")`、残りも `e.to_string()` で、
  **型として残るものは一つもない**。

`anyhow` は source を保つので `downcast_ref` で回収は可能だが、
ワークスペース全体で 4 箇所しか行われておらず（`config.rs:540`, `:859`,
`public.rs:242`, `portal-core/src/agent.rs:281`）、**API の約束として文書化されていない**。
結果として Kotlin / Swift 側は「Grant が revoke された」と
「ネットワークが落ちている」を文字列でしか区別できない。

## 6. SDK 化の観点で見た摩擦

いずれも本文書作成時にコードで確認したもの。影響の大きい順。

1. **エラーが分類不能になる（§5.4）**。下層の `status` / `problem.kind` /
   `retry_after` が編成層の `anyhow` と FFI の文字列で失われる。再試行すべきか、
   ユーザーに再認証を求めるべきか、諦めるべきかを呼び出し側が判断できない。

2. **締め切りが API の責務でない（§5.3）**。下に一つもタイムアウトがなく、
   同期 FFI 呼び出しが無期限にハングし得る（isekai-link#184 の実例）。

3. **終了順序が型で守られていない（§5.2）**。間違えるとレグのリークか
   中断不能な待ち。知識の所在は FFI のコメントだけ。

4. **コンストラクタの組み合わせ爆発**。`create*` 4 本、`connect*` 6 本（+
   `PeerDirectory::connect`）。軸は「トークンを自分で発行するか渡すか」×
   「`RelayOptions` を渡すか」×「capability か grant か」の 3 つで、
   本来は引数側の表現で済む。

5. **長い位置引数リスト**。`bind.rs` の入口は
   `open_bind_session` 8 引数、`open_public_bind_session` 7、
   `open_connect_relay` 10（いずれも位置引数で、末尾 2 つは
   `opts: RelayOptions, family: Option<AddressFamily>`）。
   `RelayOptions`（3 フィールド）は `Default` を導出しており、
   オプションを取らない経路 4 箇所がそれを使っている
   （`listener.rs:402`, `initiator.rs:708`, `public.rs:298`,
   `bin/isekai-agent.rs:445`）。一方で**構造体リテラルで組む 7 箇所は
   すべて全フィールドを書き出し、`..Default::default()` を使うものは 0** で、
   各所に `datapath_hook: None` が並ぶ。既定は効いているが、
   1 つでも指定したい呼び出し側は 3 つ全部書くことになる。

6. **enum であるべきものが `Option<&str>`**。
   `ListenerSession::bind(connection_id, relay_base_url, relay_family, info_family)`
   は `Option<&str>` を 3 つ取り、うち 2 つはアドレスファミリの綴りで、
   `relay_family::chosen` が中で解釈して不正な綴りを `warn!` に落とす。
   型で弾けるものを実行時ログに落としている。

7. **名前の衝突**。`proxy::Binding`（Endpoint の制御プレーン上のバインディング）と
   `transport::Binding`（ソケットのモード）が同名で、
   再輸出側で `SocketBinding` に改名して回避している（`lib.rs` にその旨のコメントあり）。

8. **公開面が広すぎる**。合計 462 公開アイテム。SDK として提示する面としては
   そのままでは広く、かつ消費者 0 の公開 API（§3.4）が混ざっている。

9. **外部クレート型の露出**。公開シグネチャに `anyhow::Result` 31、
   `Arc<...>` 8、`CancellationToken` 4、`serde_json::Value` 2、`msquic_async` 2。
   SDK の利用者に tokio / tokio-util / anyhow / msquic のバージョンを固定させる。

10. **具体型でテストできない面**。`relay_rtt::measure_for_connect`（`:942`）は
    `&ProxyClient<MasqueH3Transport>` を取るため予算計算を単体テストできず、
    実際に 2 件のバグ（残り予算での観測、接続予算の超過）が本番で初めて見つかった。
    `ControlPlaneTransport` という継ぎ目は**既にある**のに使われていない。

11. **再輸出が 3 段の手編み**。core → `isekai_p2p::agent` → 各アプリ core。
    追加のたびに手で足す必要があり、かつ一貫していない:
    `config::release_enrollment` と `config::spawn_token_renewal` は `pub` だが
    トップレベル再輸出がなく、`isekai_p2p::config::` でしか届かない。

12. **イベント通知の仕組みがない**。FFI は `is_closed()` のポーリングで、
    理由も明記されている（"this crate has no event-callback story to Kotlin yet"）。
    Rust 側には `watch` / `broadcast` / `mpsc` があるので、
    欠けているのは**境界をまたぐ**通知だけ。

13. **SDK の形が 2 回書かれている（§3.3）**。`portal-client-ffi` と
    `isekai-client-ffi` が同じ 4 概念をそれぞれ実装している。
    共通化されていないこと自体が、「その層が設計されたことがない」ことの証拠。

## 7. すでに良い形になっているもの

SDK 化で壊さないほうがよい部分。

- **`ControlPlaneTransport` / `EventStreamTransport`**（`proxy.rs:120`, `:69`）—
  `ProxyClient<T>` を実トランスポートから切り離す継ぎ目。テストの `MockTransport` が
  これで成立している。§6-10 の修正はこの継ぎ目を使うだけで済む。
- **`ProxyError` の情報量**（§5.4）。サーバーが言った `retry_after` を
  呼び出し側が計算し直さない設計は正しい。失われているのは上の層でだけ。
- **`listener::run` + `ListenerCommand` / `SignalingEvent` / `AcceptPolicy`** —
  チャネル駆動で、所有権と並行性の扱いが素直。Rust 層で最も SDK 的な面。
- **`DatapathHook` / `Hop` / `Verdict`** — 利用側がデータパスに介入できる
  明示的な拡張点。
- **`Narrowing`** — トークンを絞る軸を型で持ち、「更新で広げられない」
  という不変条件が `P2pConfig` のコメントに書かれている。
- **`redacted_debug!`** — 秘密を落とす `Debug` を利用側にも提供している。
- **`msquic` feature で wire 型が純粋に保たれている**（§2.1）。
  制御プレーンの型だけを使う利用者はネイティブスタックを引かずに済む。

## 8. 本調査で見つかった欠陥

**`shutdown_msquic` が doc コメントを失っている**（`transport.rs:480`）。

`drain_msquic`（`:460`）の直前に 2 つの doc ブロックが連結しており、1 つ目は
本来 `shutdown_msquic` のもの（"Shut the msquic registration down and wait
until every connection and stream derived from it has been closed"）。
`shutdown_msquic` 自身には doc コメントが 1 行もない。

`drain_msquic` を後から挿入した際に、直後の項目の doc を奪った形。コンパイルも
clippy も通るため検出されなかった。**終了順序（§5.2）を説明する 2 関数の片方が
無記載**というのは、SDK 化の観点でそのまま放置できない。修正は doc ブロックを
2 つに割って後半を `shutdown_msquic` に戻すだけ。

**この文書自身が実害を受けた**: §5.2 の初稿は「`drain_msquic` はタイムアウト時に
リークする」と書いていた。連結された doc を `drain_msquic` のものとして読んだ結果で、
実際は `drain` が常にリークし、`shutdown` がタイムアウト時だけリークする
（コードレビューで指摘され、`:476` と `:502` を読んで訂正）。
終了順序を間違えると #176 の同期待ちに入るという、この節が警告している
まさにその取り違えを、この節自身が一度やった。

## 9. SDK 設計時に決めるべき問い

本文書では答えを出さない。現状調査から**必ず決めなければならないと分かった**もの。

1. **提示する面の広さ**: 462 の公開アイテムのうち何を SDK の面とするか。
   FFI 2 本が収斂している 4 概念（鍵 / ペアリング / 接続 / ローカルポート）で
   足りるのか、`DatapathHook` や `legs()` のような低位の面も要るのか。
   → **4 概念では足りない。** portal の機能から逆算した結果は
   `docs/p2p_sdk_surface_from_portal.md`。Grant / Ticket / Provisioning Key を
   **作る・一覧する・取り消す**面が 8 メソッド分まるごと `isekai-p2p` に無く
   （作成 3・一覧 3・取り消し 2）、portal-server が生クライアントを
   直叩きしている。必要な領域は 4 ではなく 7 群。
2. **エラーの型**: SDK 境界で何を分類可能にするか（必要な区別 8 種の一覧は
   `docs/p2p_sdk_surface_from_portal.md` §9）。少なくとも
   「再試行可能か」「再認証が必要か」「相手に拒否されたか」は区別が要るはず。
3. **締め切りの所在**: API が持つのか、利用側が被せるのか。持つなら既定値は何か。
4. **ライフサイクルの所有**: プロセス全体の registration（§5.1）を前提に置き続けるか、
   SDK のハンドルに閉じ込めるか。後者なら 1 プロセス複数インスタンスが可能になる。
5. **イベントの渡し方**: Rust の `watch` / `broadcast` を FFI 境界で
   どう表現するか（コールバック、ポーリング、ストリーム）。
6. **バージョン互換の約束**: 現在 2 クレートは `version.workspace = true` で
   ワークスペースと一体。外部提供するなら semver の約束をどこに引くか。
7. **FFI 2 本の統合**: 共通の下地を 1 本にするか、アプリごとの薄いラッパーを
   残すか。

## 10. 参照

- `docs/p2p_library_plan.md` — 現在の形の出発点（CLI → ライブラリ化）
- `docs/isekai_p2p_datapath_hook_plan.md` — `DatapathHook` の設計
- `docs/p2p_signaling_plan.md` — `SignalingEvent` / `AcceptPolicy` の背景
- `docs/relay_address_family_plan.md` — `relay_family` と `bind` の family 引数
- `docs/relay_proximity_client.md` — `relay_rtt` と `ProbeOptions`
- `docs/public_listener_client_plan.md` — `open_public_bind_session`
- isekai-link#176（`RegistrationClose` の同期待ち）、
  isekai-link#184（タイムアウト不在によるハング）
