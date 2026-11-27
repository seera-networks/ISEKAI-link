# SDK の設計 — 7 群から面を決める

- status: 設計（§9 Q1 の答え）。判断を要する点は選択肢で示し、推奨を添える。
  実装はまだ無い
- version: 0.1
- 対象: `1d63993`（`main`, v0.10.2）
- 前提:
  - `docs/p2p_sdk_surface_from_portal.md` §7 — **必要な面の 7 群**。本文書の入力
  - `docs/p2p_sdk_api_review.md` §9 — 決めるべき 7 問（Q1–Q7）
  - `docs/p2p_sdk_error_type.md` — **Q2 は実装済み**（`isekai_p2p_core::outcome`）。
    本文書はそれを前提に置き、再設計しない

## 0. この文書が決めること、決めないこと

**決めること**: 7 群それぞれを SDK の面に出すか、出すならどの形で出すか。
Q1（面の広さ）への答えを、群ごとの素案シグネチャとして置く。

**決めないこと**: 下の 8 つ（**D1–D8**）。いずれも「正解が事実から出てこない」もので、
選択肢と推奨だけを置く。§6 に一覧がある。

**既決として扱うもの**（再提案しない）:

| 事項 | どこで決着したか |
| --- | --- |
| エラーの型（Q2） | `Outcome` / `Reading` として実装（#345, #347, #349） |
| upsert と台帳の所在 | `isekai_p2p::grants` へ（#350）。方針調停は app のまま |
| 一覧行の binding 種別 | `Bound` / `bound_to`（#352） |
| `ttl` の名前付け | #356 |
| 計測の駆動 | 自動。駆動の面は要らない（surface §5） |

残っている小さな未決は 1 つだけ: **revoke 系 3 ルートの `Reading` が食い違っている**
（surface §4.3, §10-1）。§3.3 で扱う。

## 1. 入力の要約 — 7 群と、本文書の扱い

| # | 群 | 現状の所在 | 不足しているもの | 本文書の扱い |
| --- | --- | --- | --- | --- |
| 1 | 身元 | `isekai-p2p`（`Credential`, `P2pConfig`, `issue_endpoint_token`） | — | **入口にする**（§3.1） |
| 2 | 自分の棚卸し | `isekai-p2p`（`endpoints`, `membership`, `enrollment`） | FFI に出ていない | **群ごとのアクセサ**（§3.2） |
| 3 | アクセスを与える | 再輸出された `ProxyClient` の 8 メソッド | 意味論は入った。残りは `Reading` 1 件 | **アクセサ＋既存の意味論**（§3.3） |
| 4 | アクセスを受け取る | `isekai-p2p`（3 つの redeem） | 入口が 3 つに割れている | **1 つ足す**（§3.4） |
| 5 | 繋ぐ | `isekai-p2p`（2 つの Session） | 転送は app。ポート面は FFI だけが持つ | **2 段で出す**（§3.5） |
| 6 | 点検 | `relay_rtt`, `legs()`, `observed_address()` | 低位すぎる | **要約を足す**（§3.6） |
| 7 | 寿命と締め切り | 終了は `drain`/`shutdown_msquic`。締め切りは FFI だけ | 下に面が無い | **ハンドルに持たせる**（§3.7） |

## 2. 先に決める 3 つ

この 3 つは他の全部のシグネチャを決めてしまうので、先に置く。

### D1 — ハンドルの所有（Q4）

msquic の registration はプロセス全体に 1 つ
（`static REGISTRATION`、`isekai-p2p-core/src/transport.rs:441`）で、
今は「1 プロセスに 2 つ独立したスタック」が作れない（api_review §5.1）。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 現状維持。関数とセッション型を並べ、状態はプロセス全体 | 変更ゼロ | 面に入口が無い。テストが直列化する |
| B | `Sdk` ハンドルに全部閉じる。registration もハンドルごと | 1 プロセス複数インスタンス | msquic 側の作り直しが必要。今の利用者に要求が無い |
| C | ハンドルを入口にするが、registration は内部で共有のまま | 入口が 1 つになる。FFI 2 本が同居できる | 複数インスタンスは「独立」ではない |

**推奨 C。** B を求めている利用者が今いない（portal も camera も 1 プロセス 1 スタック）
一方、入口が無いことは 7 群すべてのシグネチャに効く。C なら
`Sdk::connect(credential, config)` が第一引数を吸収し、B へ上げる道も塞がない。

### D2 — 2 クレートをどう見せるか

今は `isekai-p2p`（編成）と `isekai-p2p-core`（部品）が両方公開で、
`isekai_p2p::agent` が core を三段目で再輸出している（`lib.rs:71`）。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 現状維持 | 変更ゼロ | 外から見て面が 2 つある。`agent` は名前が内容と合っていない |
| B | facade クレート 1 本（`isekai-sdk`）を足し、2 クレートは内部扱い | semver を引ける（D7）。面が 1 つ | クレートが 1 つ増える |
| C | `isekai-p2p` を facade にし、core は `isekai_p2p::low` に改名して出す | クレートは増えない | 編成と facade が同じクレートに混ざる |

**推奨 B。** 理由は D7（semver）と同じで、**外に出す面と内部の面に別の寿命を与えたい**。
`agent` という名前は「agent モード」と無関係なのに core の窓になっていて、
改名の機会でもある。

### D3 — 非同期の形

| | 選択肢 | 推奨 |
| --- | --- | --- |
| A | async Rust のまま。FFI 側で blocking に被せる（今の 2 本がやっている） | **推奨** |
| B | SDK 自体を blocking にし、内部でランタイムを持つ | |

**A。** Rust 利用者（`portal-core`, `camera-core`）は async のまま使っていて、
blocking にすると両方が損をする。FFI の blocking は既に 2 本で書かれている。

## 3. 群ごとの面

素案のシグネチャは**形を見るためのもの**で、名前は確定ではない。

### 3.1 身元 — 入口

```rust
let sdk = Sdk::open(Credential::auth0(token_source), P2pConfig { .. }).await?;
```

`Credential` と `P2pConfig` は既にある。サインインの扱いだけ判断が要る。

**D4 — サインインを SDK が駆動するか**

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | トークン源を受け取るだけ（`AssertionSource` / `Auth0TokenSource`、今の形） | UI が面に入らない | device-code の 3 状態を各利用者が書く |
| B | SDK が device-code を駆動し、状態を通知で出す | 利用者が書く量が減る | 面に UI の都合が入る。`--login` が 10 分待つ経路を SDK が持つ |

**推奨 A。** `portal-client` の `--login` は人がブラウザを開く前提で、
そこは app の領分である。ただし §4.2 の通知を使って **B を後から足せる**ようにしておく。

### 3.2 自分の棚卸し — 群ごとのアクセサ

```rust
sdk.endpoints().list().await?;          // endpoints::list
sdk.endpoints().revoke(id, reason).await?;
sdk.enrollment_keys().issue(spec).await?;
sdk.me().await?;                        // membership::me
```

面は全部ある。足すのは**グルーピングだけ**で、意味論は足さない
（surface §4.3 の「素通しは足さない」をここでも守る）。
462 の公開アイテムを 1 つの名前空間に並べないための措置である。

### 3.3 アクセスを与える — 同じ 8 メソッドを群に分ける

`create_grant` / `list_grants` / `revoke_grant`、`create_ticket` /
`list_tickets` / `revoke_ticket`、`create_provisioning_key` /
`list_provisioning_keys` / `provisioning_redemptions` /
`revoke_provisioning_key`（`proxy.rs:1965`–`:2189`）。

```rust
sdk.grants().create(spec).await?;       // Made<Grant> — already_existed を持つ
sdk.grants().list().await?;
sdk.tickets().revoke(id).await?;
sdk.provisioning_keys().redemptions(id).await?;
```

**D5 — revoke の `Reading` を揃えるか**

3 つの revoke が `409` の読みで食い違っている（surface §4.3）。
`Reading` を揃えないと、SDK の利用者は「取り消し済み」と「取り消せなかった」を
ルートごとに違う規則で読むことになる。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 揃えてから出す | 利用者が 1 つの規則で読める | 到達可能性が未確認のまま揃えると、起きていない取り消しを報告する側に倒れ得る |
| B | 現状のまま出し、ルート差を文書化する | 嘘をつかない | 面としては不揃い |

**推奨 A、ただし先に到達可能性の確認。** `error_type.md` §0-4 が同じ罠を踏んでいる
（`not_found` と `conflict` を分けた理由がそれ）。確認できないルートは B に落とす。

### 3.4 アクセスを受け取る — 入口を 1 つ足す

今は `pair_with_code` / `redeem_ticket` / `redeem_provisioning_key` の 3 つで、
利用者は文字列を見て**どれを呼ぶか自分で決めている**。判別の材料は既に面にある
（`TICKET_PREFIX`, `PROVISIONING_KEY_PREFIX`, `pairing_code_from_input`,
`ticket_from_transfer`）。

```rust
sdk.redeem(input).await?;   // 既存 3 つは残す
```

**推奨: 足す。** 3 つを畳むのではなく 4 つ目を足す。
QR から来た 1 本の文字列を扱うのは FFI 2 本が両方やっていることで、
判別規則が app 側に 2 つ複製されている。

### 3.5 繋ぐ — 2 段で出す

FFI 2 本が収斂した 4 概念の 4 つ目は「**ローカルポートを得て切る**」だった
（api_review §3.3）。一方 `camera-core` は QUIC のストリームとデータグラムを
直接使う。どちらも実在する利用で、同じ面では収まらない。

```rust
// 段 1: ポート面（FFI 2 本が欲しがる形）
let fwd = sdk.connect(peer).forward_to(local_addr).await?;   // 掛け側
let srv = sdk.listen().map(capability, local_addr).await?;   // 受け側
// 段 2: QUIC 面（camera-core が使う形）
let session = sdk.connect(peer).session().await?;            // InitiatorSession
```

**D6 — `Narrowing` と `device_name` を面に出すか**

`portal-client-ffi` は `narrowing: Default::default()`（上限のまま）と
`device_name: "portal-client-android"` を固定している
（`portal-client-ffi/src/lib.rs:141`, `:144`）。これは面が無いのではなく、
**FFI が通していない**だけ（surface §6）。

| | 選択肢 | 推奨 |
| --- | --- | --- |
| A | SDK の `connect` の引数に出す | **推奨**。固定値はアプリの決定であって SDK の既定ではない |
| B | 既定のまま隠す | |

### 3.6 点検 — 要約を足し、低位は `low` に残す（§10-3 への答え）

portal が実際に使っているのは `relay_rtt::measure` /
`observe_families` / `list_relays`（`portal-client/src/main.rs:1133`, `:1147`, `:1157`）。
返るのは `RelayRttSample` と `FamilyObservation` で、どちらも測定器の語彙である。

```rust
sdk.inspect().relays().await?;   // RelayView { url, rtt, families, reachable }
sdk.inspect().paths()?;          // PathView { carrying, reserve: Vec<PathView> }
sdk.inspect().observed()?;       // ObservedAddresses（既存の型）
```

**推奨: 要約を足し、低位の型は消さない。** `ProbeOptions` の調整は面に残す
（surface §5 が「要るのは読む面と `ProbeOptions`」と書いている）。
`legs()` や `FamilyProbe` は `low` 側に置き、要約で足りない利用者だけが降りる。

`PathView` は v0.10.2 で入った `path_preference` の状態
（運んでいる 1 本と予備）をそのまま読めばよく、新しい概念は要らない。

### 3.7 寿命と締め切り — ハンドルに持たせる

**D7 — 締め切りの所在（Q3）**

下に面が一つも無く、FFI が各自で被せている:
`APP_PAIR_DEADLINE` = 30 s、`APP_CONNECT_DEADLINE` = 60 s
（`portal-client-ffi/src/lib.rs:165`, `:268`）。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 利用側が被せる（現状） | SDK が時間の判断をしない | 面に現れないので、新しい利用者は締め切り無しで書く |
| B | 全メソッドが `deadline` 引数を取る | 明示的 | 引数が全部に増える |
| C | ハンドルが既定を持ち、呼び出しごとに上書きできる | 既定が面に現れ、上書きもできる | 既定値を決めなければならない |

**推奨 C。既定は FFI の 2 値をそのまま出発点にする** —— 唯一「人が待つ時間」から
決められた実測値であり、作り直す理由が無い。

**D8 — 終了順序（api_review §5.2）**

`drain_msquic` は成否にかかわらず registration をリークし、
`shutdown_msquic` は排出できたときだけ閉じる（`transport.rs:467`, `:500`）。
正しい順序は今、利用側の責任である。

| | 選択肢 | 推奨 |
| --- | --- | --- |
| A | 文書化するだけ | |
| B | `Drop` でやる | 不可。async で待てない |
| C | `sdk.close(timeout).await` を面にし、`drain` は「プロセスを去る経路」として残す | **推奨** |

## 4. 横断的な事項

### 4.1 エラー — 既決（Q2）

`Outcome` / `Reading` をそのまま SDK の面に出す。`ProxyError` も一緒に出す
（`outcome` の doc が書いているとおり、読みと原因は両方要る）。
**本文書で足すものは無い。** 唯一の残件は §3.3 の `Reading` 揃え。

### 4.2 通知（Q5）— 先例を広げる

`isekai-client-ffi` の `FrameSink`（`lib.rs:206`）が
`on_frame` / `on_state` / `on_path` / `on_rtt` / `on_log` を境界の向こうへ渡していて、
Kotlin と Swift に実装がある。`portal-client-ffi` は `is_closed()` のポーリングだけ。
つまり**設計の先例は既にあり、非対称なだけ**（surface §6）。

| | 選択肢 | 推奨 |
| --- | --- | --- |
| A | Rust 側は `watch`/`broadcast`、FFI 境界はコールバック trait（`FrameSink` の一般化） | **推奨** |
| B | ポーリングだけ | |
| C | ストリーム型を境界に出す | |

A の形は `SessionObserver { on_state, on_path, on_rtt }` で、
`on_frame` は camera 固有なので SDK の面ではなく camera 側の拡張に残す。

### 4.3 semver と層（Q6）

今は 2 クレートとも `version.workspace = true` で、ワークスペース（v0.10.2）と一体。
外に出すなら**別の寿命**が要る。D2 で facade を足す案（B）と噛み合う:
facade だけが semver を約束し、内部 2 クレートはワークスペース版のまま。

### 4.4 FFI 2 本（Q7）

| | 選択肢 | 推奨 |
| --- | --- | --- |
| A | facade の上に薄い 2 本を残す | **推奨** |
| B | 1 本に統合する | |

A。2 本は**別のアプリの都合**（frame sink があるかどうか、同意の面があるかどうか）を
持っていて、統合すると片方に要らない面が入る。共通の下地は facade が担う。

## 5. SDK に出さない面

- **消費者ゼロの 4 件**（surface §8）: `delete_public_listener`,
  `get_peer_listener`, `peer_connect_with_grant`, `ProxyClient::get_certificate`。
  面を狭める好機だが、**畳むかどうかは SDK の面に出さないことと別**（§10-4）。
  本文書の提案は「SDK の面に出さない」だけで、クレートから消すことは提案しない。
- **低位の面**: `DatapathHook`, `BindSession`, `MasqueClientEvent`,
  `open_public_bind_session`。`low` に置く（D2-C を採らないなら `agent` のまま）。
- **計測の駆動**: `measure_for_connect` は接続経路が内部で呼ぶ（surface §5）。

## 6. 判断の一覧

| | 判断 | 選択肢 | 推奨 | 決まらないと止まるもの |
| --- | --- | --- | --- | --- |
| D1 | ハンドルの所有（Q4） | 現状 / 完全分離 / 入口だけ | **C** | 7 群すべての第一引数 |
| D2 | クレートの見せ方 | 現状 / facade / `low` 改名 | **B** | semver（D7 相当）と `agent` の名前 |
| D3 | 非同期の形 | async / blocking | **A** | FFI の書き方 |
| D4 | サインインの駆動 | 受け取るだけ / SDK が駆動 | **A** | §3.1 の入口の引数 |
| D5 | revoke の `Reading` | 揃える / 文書化 | **A**（確認後） | §3.3 の面の一貫性 |
| D6 | `Narrowing` / `device_name` | 出す / 隠す | **A** | FFI の固定値 2 つ |
| D7 | 締め切り（Q3） | 利用側 / 全引数 / ハンドル既定 | **C** | 新しい利用者の既定挙動 |
| D8 | 終了順序 | 文書 / Drop / `close()` | **C** | プロセス終了時の正しさ |

通知（Q5）と FFI 統合（Q7）は §4.2 / §4.4 に推奨を置いたが、
**先例があるので判断ではなく作業**に近い。

## 7. 作る順

1. **D1–D3 を決める。** 他が全部これに従う。
2. facade の骨格と、§3.2 / §3.3 の群アクセサ。**素通しのみで意味論は足さない**ので、
   ここは機械的に進む。
3. D7 / D8（締め切りと `close`）。面に現れるので早い方がよい。
4. §3.4 の `redeem` 1 本と、§3.5 のポート面。FFI 2 本の重複がここで消える。
5. §4.2 の通知を `portal-client-ffi` 側にも広げる。
6. §3.6 の点検の要約。
7. §3.3 の `Reading` 揃え（到達可能性の確認が先）。

## 8. 参照

- `docs/p2p_sdk_surface_from_portal.md` — 7 群（本文書の入力）
- `docs/p2p_sdk_api_review.md` — 現状の API と Q1–Q7
- `docs/p2p_sdk_error_type.md` — `Outcome` / `Reading`（Q2 の答え）
- `docs/p2p_sdk_error_classification.md` — 8 種の失敗の判定材料
- `docs/p2p_library_plan.md` — クレート分割の経緯
