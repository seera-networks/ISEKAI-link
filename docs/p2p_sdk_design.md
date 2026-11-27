# SDK の設計 — 7 群から面を決める

- status: 設計（§9 Q1 の答え）。**D1–D9 すべて決定済み**（0.3）。実装はまだ無い
- version: 0.3
- 対象: `1d63993`（`main`, v0.10.2）
- 前提:
  - `docs/p2p_sdk_surface_from_portal.md` §7 — **必要な面の 7 群**。本文書の入力
  - `docs/p2p_sdk_api_review.md` §9 — 決めるべき 7 問（Q1–Q7）
  - `docs/p2p_sdk_error_type.md` — **Q2 は実装済み**（`isekai_p2p_core::outcome`）。
    本文書はそれを前提に置き、再設計しない

## 0. この文書が決めること、決めないこと

**決めること**: 7 群それぞれを SDK の面に出すか、出すならどの形で出すか。
Q1（面の広さ）への答えを、群ごとの素案シグネチャとして置く。

**決めないこと**: もう無い。0.1 で挙げた 8 つと、0.2 で派生した 1 つ（D9）は
**すべて決定済み**（§6）。残っているのは判断ではなく作業で、§7 がその順である。

**0.2 で決まったこと**: D1 = C、D2 = B、D3 = A（0.1 の推奨どおり）。
この 3 つは他の全部のシグネチャを決めるので先に確定させた（§2）。
確定の結果 **D9 が生まれ、D8 の選択肢が割れた**。

**0.3 で決まったこと**: D4 = A、D5 = A（確認が先）、D6 = A、D7 = C、
D8 = C1、D9 = A。いずれも推奨どおり。これで判断は尽きた。
確定の過程で**書き出すべきことが 3 つ**出た:

| | 何が出たか | どこ |
| --- | --- | --- |
| 1 | **D8 = C1 と D9 = A が噛み合っていなかった。** 「msquic を閉じるのはプロセスの持ち主」と「低位は facade に出さない」を素直に読むと、facade だけを使うアプリは終了処理ができない。D9 の「低位」の範囲をデータパスと bind の内部に限定し、`shutdown` / `drain` は約束する面に置くことにした | §3.7, §5 |
| 2 | **D6 は `portal-client-ffi` のシグネチャを変える。** 固定値 2 つが引数になるので、FFI の載せ替えと同時に出す（先に出すと FFI だけ 2 度変わる） | §3.5, §7 |
| 3 | **D7 は分類を 1 つ増やす。** 締め切り超過は下層に材料が無い唯一の失敗なので、下層を触らず SDK 側の読みとして足す | §3.7 |

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

## 2. 先に決めた 3 つ — 決定済み（0.2）

この 3 つは他の全部のシグネチャを決めてしまうので先に確定させた。
選択肢の表は**なぜそれを選ばなかったか**の記録として残す。

### D1 — ハンドルの所有（Q4）

msquic の registration はプロセス全体に 1 つ
（`static REGISTRATION`、`isekai-p2p-core/src/transport.rs:441`）で、
今は「1 プロセスに 2 つ独立したスタック」が作れない（api_review §5.1）。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 現状維持。関数とセッション型を並べ、状態はプロセス全体 | 変更ゼロ | 面に入口が無い。テストが直列化する |
| B | `Sdk` ハンドルに全部閉じる。registration もハンドルごと | 1 プロセス複数インスタンス | msquic 側の作り直しが必要。今の利用者に要求が無い |
| C | ハンドルを入口にするが、registration は内部で共有のまま | 入口が 1 つになる。FFI 2 本が同居できる | 複数インスタンスは「独立」ではない |

**決定: C。** B を求めている利用者が今いない（portal も camera も 1 プロセス 1 スタック）
一方、入口が無いことは 7 群すべてのシグネチャに効く。C なら
`Sdk::open(credential, config)` が第一引数を吸収し、B へ上げる道も塞がない。

**この決定が確定させたもの**: 7 群すべての第一引数は `Sdk` ハンドル。
§3 の素案はすべてこの形になっている。

**この決定が作った制約**: ハンドルは複数あり得るのに registration は 1 つなので、
**`close()` が 1 つのハンドルのために msquic を閉じてはいけない**。
D8（§3.7）の選択肢はこれを前提に読む必要がある。「独立したインスタンス」ではない、
というのは面の説明にも書く — `Sdk` を 2 つ持っても設定は 2 つだが下は 1 つである。

### D2 — 2 クレートをどう見せるか

今は `isekai-p2p`（編成）と `isekai-p2p-core`（部品）が両方公開で、
`isekai_p2p::agent` が core を三段目で再輸出している（`lib.rs:71`）。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 現状維持 | 変更ゼロ | 外から見て面が 2 つある。`agent` は名前が内容と合っていない |
| B | facade クレート 1 本（`isekai-sdk`）を足し、2 クレートは内部扱い | semver を引ける（D7）。面が 1 つ | クレートが 1 つ増える |
| C | `isekai-p2p` を facade にし、core は `isekai_p2p::low` に改名して出す | クレートは増えない | 編成と facade が同じクレートに混ざる |

**決定: B。** 理由は semver（§4.3）と同じで、**外に出す面と内部の面に別の寿命を
与えたい**。`agent` という名前は「agent モード」と無関係なのに core の窓になっていて、
置き換えの機会でもある。

**この決定が確定させたもの**:

- **新しいクレート 1 本**（仮に `isekai-sdk`）。中身は再輸出と、§3 で「足す」と
  書いたものだけ。`isekai-p2p` と `isekai-p2p-core` からコードは動かさない。
- **semver を約束するのは facade だけ**（§4.3）。内部 2 クレートはワークスペース版の
  まま（今は v0.10.2）で、約束の対象外である。
- **`isekai_p2p::agent` は残す**。repo 内の利用者（`portal-core`, `camera-core`）は
  今これを通して core を見ており、facade へ載せ替えるまでは窓が要る。
  載せ替えが済んだ時点で畳めるかどうかは、そのときの参照数で決まる。

**この決定が作った問い**: 低位の面を facade が再輸出するか — **D9**（§5）。

### D3 — 非同期の形

| | 選択肢 | |
| --- | --- | --- |
| A | async Rust のまま。FFI 側で blocking に被せる（今の 2 本がやっている） | **決定** |
| B | SDK 自体を blocking にし、内部でランタイムを持つ | |

**決定: A。** Rust 利用者（`portal-core`, `camera-core`）は async のまま使っていて、
blocking にすると両方が損をする。FFI の blocking は既に 2 本で書かれている。

**この決定が確定させたもの**: facade のメソッドは `async fn`。
ランタイムは利用側のもので、SDK は作らない（api_review §5.1 の「tokio 必須」は
前提として残り、面にも書く）。

## 3. 群ごとの面

素案のシグネチャは**形を見るためのもの**で、名前は確定ではない。
第一引数が `Sdk` ハンドルであること（D1 = C）と、`async fn` であること（D3 = A）、
置き場所が facade クレートであること（D2 = B）は確定している。

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

**決定: A。** `portal-client` の `--login` は人がブラウザを開く前提で、
そこは app の領分である。ただし §4.2 の通知を使って **B を後から足せる**ようにしておく。

**この決定が確定させたもの**: facade は **`AssertionSource` を trait として出す**。
具体の `Auth0TokenSource` / `StaticAuth0Token` だけを出すと、自分のトークン源を
持つ利用者（OIDC を自前で回すサービス）が入れない —— A を選んだ意味が消える。

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

**決定: A、ただし先に到達可能性の確認。** `error_type.md` §0-4 が同じ罠を踏んでいる
（`not_found` と `conflict` を分けた理由がそれ）。確認できないルートは B に落とす。

**この決定が課した順序と制約**:

1. まず 3 ルートの `409` が**到達可能か**を確かめる。到達不能なら、そのルートの
   `Reading` は何を書いても観測されないので、揃えるのは自由である。
2. 到達可能で意味が違うなら、**揃える向きは厳しい側**。`409` を「もう済んだ」と
   読む方へ寄せると、`portal-server` が**起きていない取り消しを台帳から落とす**
   （`error_type.md` §0-5 がまさにそれを防いだ箇所）。
3. 確認できないルートは B（差を文書化）に落とし、揃った分だけ面に出す。

### 3.4 アクセスを受け取る — 入口を 1 つ足す

今は `pair_with_code` / `redeem_ticket` / `redeem_provisioning_key` の 3 つで、
利用者は文字列を見て**どれを呼ぶか自分で決めている**。判別の材料は既に面にある
（`TICKET_PREFIX`, `PROVISIONING_KEY_PREFIX`, `pairing_code_from_input`,
`ticket_from_transfer`）。

```rust
sdk.redeem(input).await?;   // 既存 3 つは残す
```

**この文書の決定（§0 の「決めること」）: 足す。** 3 つを畳むのではなく 4 つ目を足す。
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

| | 選択肢 | |
| --- | --- | --- |
| A | SDK の `connect` の引数に出す | **決定**。固定値はアプリの決定であって SDK の既定ではない |
| B | 既定のまま隠す | |

**この決定が作った段取り**: `portal-client-ffi` の `connect` の**シグネチャが変わる**
（固定値 2 つが引数になる）。Kotlin / Swift の呼び出し側に届く変更なので、
§7 の「FFI を facade に載せ替える」段と**同時に**出す。先に出すと FFI だけが
2 度変わる。

### 3.6 点検 — 要約を足し、低位は `low` に残す（§10-3 への答え）

portal が実際に使っているのは `relay_rtt::measure` /
`observe_families` / `list_relays`（`portal-client/src/main.rs:1133`, `:1147`, `:1157`）。
返るのは `RelayRttSample` と `FamilyObservation` で、どちらも測定器の語彙である。

```rust
sdk.inspect().relays().await?;   // RelayView { url, rtt, families, reachable }
sdk.inspect().paths()?;          // PathView { carrying, reserve: Vec<PathView> }
sdk.inspect().observed()?;       // ObservedAddresses（既存の型）
```

**この文書の決定: 要約を足し、低位の型は消さない。** `ProbeOptions` の調整は面に残す
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

**決定: C。既定は FFI の 2 値をそのまま出発点にする** —— 唯一「人が待つ時間」から
決められた実測値であり、作り直す理由が無い。

**この決定が確定させたもの**:

- `Sdk::open` が既定を受け取る（`Deadlines { pair: 30s, connect: 60s, .. }`）。
- 締め切りがかかるのは**要求と応答**であって、セッションの寿命ではない。
  待受けや通知の購読に締め切りは無く、終わらせ方は `close()`（D8）と
  キャンセルである。ここを混ぜると「接続が 60 秒で切れる SDK」になる。
- 締め切り超過は `Outcome` に材料が無い唯一の失敗（surface §9）なので、
  **分類を 1 つ足す**必要がある。`error_type.md` の 8 種に 9 つ目を足すのではなく、
  締め切りは SDK 側の読みとして出す（下層は何も知らないままでよい）。

**D8 — 終了順序（api_review §5.2）**

`drain_msquic` は成否にかかわらず registration をリークし、
`shutdown_msquic` は排出できたときだけ閉じる（`transport.rs:467`, `:500`）。
正しい順序は今、利用側の責任である。

**D1 = C が制約を 1 つ足した。** ハンドルは複数あり得るのに registration は
プロセスに 1 つなので、`close()` が `shutdown_msquic` をそのまま呼ぶと
**他のハンドルの下を抜く**。選択肢はその前提で読む。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 文書化するだけ（現状） | 変更ゼロ | 正しい順序が面に現れない |
| B | `Drop` でやる | 呼び忘れが無い | **不可**。async で待てない |
| C1 | `sdk.close(timeout).await` はこのハンドルのセッションだけ閉じる。msquic は閉じない | 複数ハンドルで安全 | プロセス終了時に別途 `shutdown_msquic` が要る（今と同じ） |
| C2 | `close()` が最後のハンドルのときだけ `shutdown_msquic` を呼ぶ（参照計数） | 呼び出し側が順序を知らなくて済む | 参照計数が facade の責務になる。`drain` の「リークして去る」経路と噛み合わせが要る |

**決定: C1。** `drain_msquic` は成否にかかわらず registration をリークする設計で
（プロセスを去る経路のため）、その判断は**プロセスの持ち主のもの**である。
facade が参照計数で代行すると、ライブラリが「プロセスを終える」判断に入り込む。
C2 は「SDK が 1 つしか無い」前提のアプリには便利だが、それは D1 = B を選んだ世界の
利便性で、ここでは買わない。

**この決定と D9 = A の整合（見落としかけた点）**: C1 は「msquic を閉じるのは
プロセスの持ち主」と言っているのに、D9 = A は「低位の面は facade に出さない」と
言っている。`shutdown_msquic` / `drain_msquic` は今 `isekai_p2p::agent` 経由でしか
届かないので、**両方を素直に読むと facade だけを使うアプリは終了処理ができない**。

したがって **D9 の「低位」はデータパスと bind の内部を指し、プロセスの寿命は
含まない**。`isekai_sdk::{shutdown, drain}` は約束する面の側に置く —— 利用者が
守るべき契約（api_review §5.2）であって、覗き込む配管ではない。

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

| | 選択肢 | |
| --- | --- | --- |
| A | Rust 側は `watch`/`broadcast`、FFI 境界はコールバック trait（`FrameSink` の一般化） | **採用** |
| B | ポーリングだけ | |
| C | ストリーム型を境界に出す | |

A の形は `SessionObserver { on_state, on_path, on_rtt }` で、
`on_frame` は camera 固有なので SDK の面ではなく camera 側の拡張に残す。

### 4.3 semver と層（Q6）— D2 = B で決着

今は 2 クレートとも `version.workspace = true` で、ワークスペース（v0.10.2）と一体。
**facade だけが semver を約束し、内部 2 クレートはワークスペース版のまま**。
外に出す面と内部の面に別の寿命を与える、というのが D2 = B を選んだ理由そのものである。

残るのは facade の最初の版をどう置くかだけで、これは実装時の判断になる
（`0.1.0` から始めるか、ワークスペースに合わせて `0.10.x` から始めるか）。
**面が固まる前に `1.0` を約束しない**、という点だけ先に書いておく。

### 4.4 FFI 2 本（Q7）

| | 選択肢 | |
| --- | --- | --- |
| A | facade の上に薄い 2 本を残す | **採用** |
| B | 1 本に統合する | |

A。2 本は**別のアプリの都合**（frame sink があるかどうか、同意の面があるかどうか）を
持っていて、統合すると片方に要らない面が入る。共通の下地は facade が担う。

## 5. SDK に出さない面

- **消費者ゼロの 4 件**（surface §8）: `delete_public_listener`,
  `get_peer_listener`, `peer_connect_with_grant`, `ProxyClient::get_certificate`。
  面を狭める好機だが、**畳むかどうかは SDK の面に出さないことと別**（§10-4）。
  本文書の提案は「SDK の面に出さない」だけで、クレートから消すことは提案しない。
- **低位の面**: `DatapathHook`, `BindSession`, `MasqueClientEvent`,
  `open_public_bind_session`。**D9 — facade がこれを再輸出するか**（D2 = B から派生）:

  | | 選択肢 | 得るもの | 失うもの |
  | --- | --- | --- | --- |
  | A | facade は再輸出しない。要る利用者は `isekai-p2p` に直接依存する | semver の約束が面の広さと一致する。facade が小さく保たれる | 「SDK だけで足りない」利用者が 2 クレート見ることになる |
  | B | facade が `low` として再輸出する | 入口が 1 つ | 約束していない面が facade の名前空間に入る。semver の線が曖昧になる |

  **決定: A。** facade を足した理由は「約束する面を切り出す」ことなので、
  約束しないものを同じクレートに入れると理由が消える。`camera-core` の
  `DatapathHook` 利用はまさにこの「降りる」側で、repo 内の依存なら 2 クレートでも
  不便はない。外部利用者から要求が出たら B へ上げる。

  **範囲の限定**（D8 = C1 との整合、§3.7）: ここで言う「低位」は
  **データパスと bind の内部**である。`shutdown_msquic` / `drain_msquic` は
  利用者が守る契約なので facade 側に出す。`camera-core` は `DatapathHook` のために
  `isekai-p2p` に直接依存したままになり、repo 内では facade と 2 本が同居する。
- **計測の駆動**: `measure_for_connect` は接続経路が内部で呼ぶ（surface §5）。

## 6. 判断の一覧 — すべて決定済み

選んだ理由は各節にある。ここは**何が確定したか**だけを書く。

| | 判断 | 決定 | 確定したもの |
| --- | --- | --- | --- |
| D1 | ハンドルの所有（Q4） | **C** 入口だけ | 7 群すべての第一引数は `Sdk`。`close()` は msquic を閉じない |
| D2 | クレートの見せ方 | **B** facade クレート | semver は facade だけが約束。`agent` は載せ替えまで残す |
| D3 | 非同期の形 | **A** async | facade は `async fn`。ランタイムは利用側のもの |
| D4 | サインインの駆動 | **A** 受け取るだけ | `AssertionSource` を trait として出す（自前のトークン源が入る） |
| D5 | revoke の `Reading` | **A** 揃える（確認が先） | 到達可能性の確認 → 厳しい側へ揃える → 確認できない分だけ文書化 |
| D6 | `Narrowing` / `device_name` | **A** 出す | `portal-client-ffi` のシグネチャが変わる。FFI 載せ替えと同時 |
| D7 | 締め切り（Q3） | **C** ハンドル既定＋上書き | 既定は 30 s / 60 s。締め切りは要求と応答にかかる。分類が 1 つ増える |
| D8 | 終了順序 | **C1** 自分のセッションだけ | msquic を閉じるのはプロセスの持ち主。`shutdown`/`drain` は facade に出す |
| D9 | 低位の面の再輸出 | **A** 出さない | 「低位」はデータパスと bind の内部。`camera-core` は 2 本に依存したまま |

Q5（通知）と Q7（FFI 統合）は §4.2 / §4.4 に答えがあり、`FrameSink` という先例が
あるので**判断ではなく作業**である。Q2 と Q6 は既決（§0、§4.3）。
これで api_review §9 の 7 問はすべて答えが付いた。

## 7. 作る順

判断は尽きているので、以下は作業の順である。**各段がそれ自体で出せる**ように切った。

1. **facade クレートの骨格** — `Sdk::open` / `async fn` / `Deadlines` の既定と、
   `AssertionSource` の再輸出、`shutdown` / `drain`（D1, D2, D3, D4, D7, D8, D9）。
   入口の形がここで固まる。中身は空でよい。
2. **群アクセサ** — §3.2 / §3.3。**素通しのみで意味論は足さない**ので機械的に進む。
3. **`redeem` 1 本**（§3.4）と**点検の要約**（§3.6）。どちらも足すだけで、
   既存の面を変えない。
4. **ポート面**（§3.5 段 1）。FFI 2 本が持っている形を facade に移す段で、
   ここから下は FFI に届く。
5. **FFI 2 本を facade に載せ替える** + **D6 の 2 引数**を同時に出す（§3.5）。
   Kotlin / Swift に届く変更はこの 1 回にまとめる。
6. **通知を `portal-client-ffi` に広げる**（§4.2）。`FrameSink` の一般化。
7. **`Reading` 揃え**（D5）。先に 3 ルートの `409` の到達可能性を確かめる。
   揃った分だけ面に出し、残りは差を文書化する。

1 と 2 は面を足すだけなので、既存の利用者（`portal-core`, `camera-core`）は
どちらも触らずに済む。利用者が動くのは 5 からである。

## 8. 参照

- `docs/p2p_sdk_surface_from_portal.md` — 7 群（本文書の入力）
- `docs/p2p_sdk_api_review.md` — 現状の API と Q1–Q7
- `docs/p2p_sdk_error_type.md` — `Outcome` / `Reading`（Q2 の答え）
- `docs/p2p_sdk_error_classification.md` — 8 種の失敗の判定材料
- `docs/p2p_library_plan.md` — クレート分割の経緯
