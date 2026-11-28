# SDK の設計 — 7 群から面を決める

- status: 設計（§9 Q1 の答え）。D1–D15 決定済み。**段 2a のレビューが 1 つ
  立てた（D16 — 制御プレーン呼び出しの締め切り）**。§7 段 1 / 2b / D14 /
  段 2a 実装済み。残りは revoke 3 本（D5 待ち）と段 2c 以降
- version: 0.12
- 対象: `1d63993`（`main`, v0.10.2）
- 前提:
  - `docs/p2p_sdk_surface_from_portal.md` §7 — **必要な面の 7 群**。本文書の入力
  - `docs/p2p_sdk_api_review.md` §9 — 決めるべき 7 問（Q1–Q7）
  - `docs/p2p_sdk_error_type.md` — **Q2 は実装済み**（`isekai_p2p_core::outcome`）。
    本文書はそれを前提に置き、再設計しない

## 0. この文書が決めること、決めないこと

**決めること**: 7 群それぞれを SDK の面に出すか、出すならどの形で出すか。
Q1（面の広さ）への答えを、群ごとの素案シグネチャとして置く。

**決めないこと**: もう無い。D14 が決まった（**B**、0.10 で実装）ので、
本文書の判断は尽きている（§6）。残りは作業である（§7）。

**0.5 で決まったこと**: D10 = A、D11 = A（どちらも推奨どおり）。
確定の過程で、**D10 の前提が 0.4 で書いたものより良いことが分かった**（§3.3）:
`ListenerSession` の 2 つはアプリ向けの競合する名前ではなく、**クレート自身の
シグナリングループが request/reply で使う配管**だった（`listener.rs:1416`, `:1419`）。
`portal-server` は生のクライアントを直叩きしており（`portal-server/src/main.rs:1240`,
`:1466`）、この 2 つは呼んでいない。畳む／残すの話ですらない。

**0.2 で決まったこと**: D1 = C、D2 = B、D3 = A（0.1 の推奨どおり）。
この 3 つは他の全部のシグネチャを決めるので先に確定させた（§2）。
確定の結果 **D9 が生まれ、D8 の選択肢が割れた**。

**0.3 で決まったこと**: D4 = A、D5 = A（確認が先）、D6 = A、D7 = C、
D8 = C1、D9 = A。いずれも推奨どおり。
確定の過程で**書き出すべきことが 3 つ**出た:

| | 何が出たか | どこ |
| --- | --- | --- |
| 1 | **D8 = C1 と D9 = A が噛み合っていなかった。** 「msquic を閉じるのはプロセスの持ち主」と「低位は facade に出さない」を素直に読むと、facade だけを使うアプリは終了処理ができない。D9 の「低位」の範囲をデータパスと bind の内部に限定し、`shutdown` / `drain` は約束する面に置くことにした | §3.7, §5 |
| 2 | **D6 は `portal-client-ffi` のシグネチャを変える。** 固定値 2 つが引数になるので、FFI の載せ替えと同時に出す（先に出すと FFI だけ 2 度変わる） | §3.5, §7 |
| 3 | **D7 は分類を 1 つ増やす。** 締め切り超過は下層に材料が無い唯一の失敗なので、下層を触らず SDK 側の読みとして足す | §3.7 |

**0.4 でレビューが正したこと**: 0.3 までの主張のうち、ツリーと食い違っていたもの。
決定（A/B/C の選択）は 1 つも覆らなかったが、**中身が 9 点動いた**。

| | 正したこと | どこ |
| --- | --- | --- |
| 1 | **締め切りの読みは既にある。** `Unreachable::Deadline { waited }`（`outcome.rs:110`）が「Nothing produces this yet」付きで存在し、締め切り超過は 8 種の **#8**。要るのは分類ではなく**作る側** | §3.7 |
| 2 | **8 メソッドに `list_grants` / `revoke_grant` は入らない。** 既に `ListenerSession` に包まれている（`listener.rs:678`, `:684`）。この 2 つにアクセサを足すのは素通しではない → **D10** | §3.3 |
| 3 | **`Made` は upsert の答えではない。** `(Grant, Made)` の 3 アーム enum で、`existed_before` は `Made::Existing` を意図的に非権威として扱う（#350 が避けた枯れの罠） | §3.3 |
| 4 | **D4 の継ぎ目は 2 つある。** `Auth0TokenSource` と `AssertionSource` の**両方が trait**。片方だけ出すと、もう片方の資格情報で自前のトークン源が入らない | §3.1 |
| 5 | **D6 の 2 つは `connect` の引数ではない。** どちらも `P2pConfig` のフィールドで、登録・enroll・トークン発行で消費される＝接続より前。出す場所は `Sdk::open` | §3.5 |
| 6 | **§3.4 の理由が事実ではなかった。** FFI 2 本は ticket も Provisioning Key も引き換えない。3 分岐は `portal-client` の 1 箇所だけ。残る理由は弱く、判断を立て直した → **D11** | §3.4 |
| 7 | **点検の三状態を潰していた。** `list_relays` の `Ok(None)`（近さで選ばない）と空一覧（登録無し）は別物で、`portal-client` は別の文を出す | §3.6 |
| 8 | **D9 の例が間違っていた。** `DatapathHook` に本番の利用者はいない（example とテストだけ）。`camera-core` が低位に留まる理由は QUIC 面 | §5 |
| 9 | **semver の道筋が書かれていなかった。** facade だけ `version.workspace` を使わない例外が要り、git-rev と submodule path 依存のため **crates.io には出せない** | §4.3 |

小さい訂正も同時に入れた: 4 概念の 4 つ目は「切る」（「ローカルポートを得て切る」ではない）、
点検の引用順、`paths()` / `observed()` は同期でよい理由（D3 は網に触るものの話）、
§7-5 は `portal-client-ffi` が自分のワークスペースと lock を持つこと。

**0.6 で実装が正したこと**: 素案 1 点 —— `Sdk::open` は `P2pConfig` 1 つを取り、
`async` でも `Result` でもない（§3.1）。

**0.7 — semver が形を決めた 3 点**（段 1 のレビューで出た）。D2 = B が「facade が
約束する」と決めた以上、**後から足せないものを先に置く**必要がある:

- `Deadlines` は `#[non_exhaustive]`。段 2 以降が 3 つ目の締め切りを足したとき、
  構造体リテラルを書いた利用者が壊れる＝major を強いられるのを避ける。
  外からは `Deadlines::default().with_redeem(..)` で組む。
- `close` は `bool` を返す。「時間内に終わったか」は呼び出し側の判断で、
  `shutdown` / `drain` が `bool` を返すのと同じ理由である（終わらなかった drain は
  リレーのリースを予約したまま残す）。戻り値を後から足すのも破壊的変更になる。
- `tokio` は dev-dependency だけ。facade のビルドにランタイムは要らないので、
  利用者が facade 経由でランタイムを引き込むことはない。

**CI の穴も段 1 で塞いだ**: 新クレートを建てるジョブが無く、`isekai-p2p` の
再輸出が変わっても気付けない状態だった（CI の cargo 呼び出しは全部 `-p` 指定）。
`migration-spike.yml` のテストに `-p isekai-sdk` を足し、両トリガーの
`paths:` に `rust/isekai-sdk/**` を入れた（closure チェックは通る —— facade の
依存は `isekai-p2p` の部分集合）。

**0.10 — D14 = B が実装で見つけたもの**。`issue_endpoint_token` は
`Result<EndpointToken, TokenError>` になった（`isekai-p2p/src/token.rs`）。腕は 3 つ
で、素案の 2 つに**局所的な矛盾**が加わった —— 同じ `Credential` が別の鍵の登録を
既に使っている場合で、これは `anyhow::bail!` が 2 箇所にあった。読みは
`TokenError::outcome()`（`Identity` は `Outcome::of_identity`、`Credential` は
`Reauthenticate`、`Mismatched` は `Rejected`）。

**そして 2b が 1 箇所取りこぼしていた**。`enrollment::issue` は
`.map_err(explain_membership_refusal)?` を残していて、この関数が返すのは
`anyhow::Error`、`IdentityError::Transport` は `#[from] anyhow::Error` —— つまり
**`403` が「Transport」の腕に入り、ネットワーク障害（`Unreachable`）として
読まれていた**。2b が型を変えた時点で静かにそうなった（本体は 1 行も動かして
いないのに、意味が動いた）。助言は**印字する側**（`portal-client`）で付け直し、
`explain_membership_refusal` は「報告側で呼ぶもの」と文書化した。
`a_wrapped_refusal_loses_its_status` が罠を固定している。

**`{:#}` の罠は型を足すたびに付いてくる**（#386 と同じもの）: `TokenError` の
`Display` はこの層が足す 1 文だけなので、サーバの答え（状態・本文・原因）は
`anyhow::Error` 経由でしか出ない。更新ループの 3 つの報告と
`token_flow` のテストはそう直した。

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
let sdk = Sdk::open(P2pConfig { credential, key, device_name, narrowing, .. });
```

`Credential` と `P2pConfig` は既にある。サインインの扱いだけ判断が要る。

**0.6 で素案を正した**（実装で分かった 1 点）: 0.5 までは
`Sdk::open(Credential::auth0(..), P2pConfig { .. }).await?` と書いていたが、
**`P2pConfig` は `credential` をフィールドに持つ**（`isekai-p2p/src/config.rs:31`）。
資格情報を二重に渡す形だった。そして `open` は**網に触らない**ので
`async` でも `Result` でもない —— 最初の呼び出しがスタックを開き、
到達できない設定もそこで報告される。呼び出し側がまだ再試行するものを
持っていない時点で失敗を返しても何もできない。

これは D6 = A の置き場所の裏付けにもなっている: `device_name` と `narrowing` は
`open` が受け取る同じ `P2pConfig` のフィールドである。

**D4 — サインインを SDK が駆動するか**

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | トークン源を受け取るだけ（`AssertionSource` / `Auth0TokenSource`、今の形） | UI が面に入らない | device-code の 3 状態を各利用者が書く |
| B | SDK が device-code を駆動し、状態を通知で出す | 利用者が書く量が減る | 面に UI の都合が入る。`--login` が 10 分待つ経路を SDK が持つ |

**決定: A。** `portal-client` の `--login` は人がブラウザを開く前提で、
そこは app の領分である。ただし §4.2 の通知を使って **B を後から足せる**ようにしておく。

**この決定が確定させたもの**: facade は **2 つの trait を両方出す**。
`Auth0TokenSource`（`isekai-p2p/src/auth.rs:25`）が §3.1 の素案
`Credential::auth0(..)` の継ぎ目で、`AssertionSource`（同 `:52`）が無人
ワークロード（`Credential::Enrollment`）側の継ぎ目である。**どちらも trait** で、
具体の実装は `StaticAuth0Token`（同 `:355`）。片方だけ出すと、出さなかった側の
資格情報で自分のトークン源を持ち込めない —— A を選んだ意味が半分消える。

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

**D10 — `list_grants` / `revoke_grant` はどちらの名前で出すか**

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | facade のアクセサを唯一の名前にし、`ListenerSession` の 2 つは repo 内の利用者が載せ替わるまで残す | 読みが 1 つ（`Outcome`）に揃う | 載せ替えまで 2 つの名前が同居する |
| B | `ListenerSession` の 2 つをそのまま面にし、アクセサには出さない | 名前は増えない | `grants()` が create と list で非対称になる。`anyhow` の読みが面に出る |

**決定: A。** `ListenerSession` 版は `anyhow::Result` を返していて、
`Outcome` を前提にした SDK の読みとは合わない（`error_type.md` が
「読みと原因は両方要る」と書いた形になっていない）。

**前提が 0.4 より素直だった**（0.5 で確認）: `ListenerSession` の 2 つは
**アプリ向けの競合する名前ではない**。クレート自身のシグナリングループが
request/reply で呼ぶ配管で（`isekai-p2p/src/listener.rs:1416`, `:1419`）、
`camera-server` はコマンドチャネル越しにそこへ届いている
（`camera-server/src/main.rs:872`, `:1356`）。一方 `portal-server` は
生のクライアントを直叩きしていて（`portal-server/src/main.rs:1240`, `:1466`）、
この 2 つは呼んでいない。

したがって A は「2 つの名前のうち片方を選ぶ」ではなく、**facade のアクセサは
`ProxyClient` を直接呼び、`anyhow` を継がない**という一行に落ちる。
`ListenerSession` の 2 つはそのまま配管として残る。

**upsert の答えを `Made` で出してはいけない。** `create_grant` が返すのは
`(Grant, Made)` で、`Made` は `Fresh` / `Existing` / `Unknown` の
3 アーム（`proxy.rs:582`）。upsert の判定は `grants::existed_before`
（`isekai-p2p/src/grants.rs:67`）であり、その doc が **`Made::Existing` は
権威ではない**と明記している —— プロキシが新規作成にも `200` を返すなら、
自分が作った Grant まで `theirs` に入って誰も更新せず、短い TTL で枯れる。
facade が `Made` を upsert の答えとして見せると、#350 が避けたその罠が戻る。
出すのは `existed_before` / `already_existed` の読みである。

### 3.3 アクセスを与える — 同じ 8 メソッドを群に分ける

surface §4 が数えた 8 つは、**`isekai-p2p` に面が無い**ものである:
`create_grant` / `create_ticket` / `create_provisioning_key`、
`list_tickets` / `list_provisioning_keys` / `provisioning_redemptions`、
`revoke_ticket` / `revoke_provisioning_key`（`proxy.rs:1965`–`:2189`）。

**`list_grants` と `revoke_grant` はこの 8 つに入らない。** 既に
`ListenerSession` に包まれていて（`isekai-p2p/src/listener.rs:678`, `:684`）、
戻りは `anyhow::Result` である。したがってこの 2 つにアクセサを足すのは
**素通しのグルーピングではなく、読みの違う 2 つ目の名前を増やす**ことになる
（surface §4.3 がまさに警戒した形）。→ **D10**。

```rust
sdk.grants().create(spec).await?;       // (Grant, Made) — Made は 3 アームの enum
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
利用者は文字列を見て**どれを呼ぶか自分で決めている**。判別の材料は既に面にある:
`secret_prefix`（`proxy.rs:1292`）と 4 つの接頭辞（`TICKET_PREFIX`,
`TICKET_TRANSFER_PREFIX`, `PROVISIONING_KEY_PREFIX`, `ENROLLMENT_KEY_PREFIX`）。

**0.3 が書いていた理由は事実ではなかった**（0.4 で訂正）。「判別規則が app 側に
2 つ複製されている」と書いたが、**FFI 2 本はどちらも ticket も Provisioning Key も
引き換えない** —— `pair_with_code` だけで、やっているのはペアリングコードの
正規化である（`portal-client-ffi/src/lib.rs:205`,
`isekai-client-ffi/src/lib.rs:727`）。3 分岐が実在するのは 1 箇所、
`portal-client/src/main.rs:743`, `:1258`（`what_it_is`）だけである。

残る理由は弱い: **面に dispatch が無い**こと —— 材料は公開されているのに、
「この文字列を引き換える」1 本が無いので、SDK の利用者は `what_it_is` 相当を
自分で書く。足すなら **Enrollment Key を弾く**必要もある（引き換えられない
ものが 4 つ目の接頭辞として存在する）。→ **D11**。

```rust
sdk.redeem(input).await?;   // 既存 3 つは残す
```

**D11 — `redeem` 1 本を足すか**

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 足す（3 つは残す）。Enrollment Key は弾く | QR の 1 本を扱う経路が面にある。`what_it_is` 相当を各自が書かなくて済む | 5 つ目の名前。重複の除去にはならない（複製は無かった） |
| B | 足さない。`secret_prefix` で各自が分ける | 面が増えない | 分岐が利用者ごとに増える。弾くべき 4 つ目を各自が思い出す必要がある |

**決定: A。** 理由は 0.3 が書いたものより弱いが、`portal-client` が実際に
`secret_prefix` + `what_it_is` を書いている以上、**2 人目の利用者も同じものを書く**。
ただし「重複を消す」ではなく「dispatch を面に置く」と理由を言い直す。

**この決定が確定させたもの**:

- **弾き方も面の一部。** Enrollment Key は 4 つ目の接頭辞として実在し、
  引き換えられない。`redeem` はそれを**何だったか言って断る**必要がある
  （`portal-client` の `what_it_is` が今やっている仕事、`main.rs:1258`）。
  「不正な文字列」と区別できないと、利用者は enroll 側に回す判断ができない。
- **読みは `Outcome` に乗せる。** 弾くのは失敗だが*再試行で直らない*ので、
  `Reading` の `fixable`（直して出し直せる）側に置く —— 待っても変わらない
  `Busy` ではない。`error_type.md` §0-3 が 2 つの指示を 1 本のリストで
  言えないと書いた、まさにその区別である。

### 3.5 繋ぐ — 2 段で出す

FFI 2 本が収斂した 4 概念は「**鍵を作る / 相手と繋がる / ローカルポートを得る /
切る**」で（api_review §3.3）、3 つ目と 4 つ目がこの群にあたる。一方 `camera-core` は QUIC のストリームとデータグラムを
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
| A | 利用者が与えられるようにする | **決定**。固定値はアプリの決定であって SDK の既定ではない |
| B | 既定のまま隠す | |

**どこに出すか（0.4 で訂正）**: `connect` の引数ではない。両方とも `P2pConfig` の
フィールドで、**接続より前**に消費される —— `device_name` は登録と enroll
（`isekai-p2p/src/config.rs:367`, `:588`）、`narrowing` はトークン発行
（同 `:318`, `:419`）。§3.1 が `P2pConfig` を `Sdk::open` に渡しているので、
**出す場所はそこ**で足りる。`connect` ごとの引数にすると、呼び出しごとに
トークンを再発行する話になってしまう。

**段取り**: `portal-client-ffi` の固定値 2 つは `build_p2p_config`
（`portal-client-ffi/src/lib.rs:141`, `:144`）にあり、これは `pair_with_code`
（`:191`）と `connect`（`:448`）の**両方**に効く。したがって動くのは
`connect` のシグネチャ 1 本ではなく FFI の設定の形で、§7 の載せ替えと
**同時に**出す。先に出すと FFI だけが 2 度変わる。

### 3.6 点検 — 要約を足し、低位は `low` に残す（§10-3 への答え）

portal が実際に使っているのは `relay_rtt::measure` /
`list_relays` / `measure` / `observe_families`
（`portal-client/src/main.rs:1133`, `:1147`, `:1157` — この順）。
返るのは `RelayRttSample` と `FamilyObservation` で、どちらも測定器の語彙である。

```rust
sdk.inspect().relays().await?;   // Option<Vec<RelayView>> — None は「近さで選ばない」
sdk.inspect().paths()?;          // Paths { carrying: PathView, reserve: Vec<PathView> }
sdk.inspect().observed()?;       // ObservedAddresses（既存の型）
```

**三状態を潰さないこと**（0.4 で訂正）: `list_relays` は
`Ok(None)`（このプロキシは近さでリレーを選ばない）と**空の一覧**（登録リレーが無い）を
区別し、`portal-client` はそれぞれ別の文を出す（`main.rs:1133`–`:1144`）。
要約が `Vec` 1 本だとこの区別が消えるので、`Option<Vec<_>>` のまま出す。

**同期で読めるものは同期**（D3 との整合）: D3 = A が言う `async fn` は
**網に触るもの**である。`paths()` と `observed()` は手元の状態を読むだけなので
同期でよく、`relays()` は測るので `async`。

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
  **読みは既にある**: `Unreachable::Deadline { waited }`
  （`isekai-p2p-core/src/outcome.rs:110`）。その doc が「**Nothing produces this
  yet**」と書いているとおり、足りないのは分類ではなく**それを作る側**である。
  締め切りは `error_classification.md` の 8 種の **#8** で（同 §5 の表、材料「なし」）、
  9 つ目を足す話ではない。facade が自分の締め切りで `Deadline` を作る。

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

### 3.8 段 2 に埋まっていた 2 つの判断

§7 段 2 は「素通しのグルーピングだけなので機械的に進む」と書いてあり、
発行側（§3.3）についてはそのとおりだった。棚卸し側（§3.2）と、
どちらにも必要な**資格の受け渡し**に、判断が 2 つ残っていた。

**D12 — 棚卸し側の読みをどうするか**

発行側は `ProxyClient` 直叩きで `Result<_, ProxyError>` になり、D10 = A の
「`anyhow` を継がない」がそのまま通る。棚卸し側は下が `anyhow::Result` を返す
（`isekai-p2p/src/endpoints.rs:43`, `:54`, `:74`、`enrollment` と `membership` も同様）。
素通しで包むと、**D10 = A でまさに避けた「`anyhow` の読みが面に出る」状態**が
棚卸し側に入り、面の中で読みが 2 種類になる。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 下に合わせて `anyhow::Result` を出す | 実装ゼロ | 面の約束に「この失敗は分類できない」が入る。あとで変えると破壊的変更 |
| B | facade が `IdentityClient` を直接呼ぶ | 読みが揃う | **今は不可能** —— `IdentityClient` も `HttpsTransport` も `isekai-p2p` から再輸出されていない。出すには facade のために下の面を広げることになり、facade を作った理由と逆 |
| C | `isekai-p2p` の棚卸し 3 モジュールを型付きの失敗に変え、facade はそれを通す | 読みが揃い、**今の利用者（`portal-server` / `portal-client`）も分類できるようになる** | 段 2 より大きい。アプリの呼び出し側を動かす |

**決定: C、ただし段 2 とは別の段で（実装済み）。** `error_classification.md` が「材料は下にあり、
失われているのは上の 2 層」と書いたその上の層がここで、`IdentityError` は既に
型として存在する（`agent` で再輸出済み）。A は semver を約束するクレートに
**「分類できない」を焼き込む**ので、段 1 のレビューで 3 つ直したのと同じ罠である。

したがって段 2 は**発行側だけ**にし（読みは既に正しい）、棚卸し側は C を入れた後に
続ける。これは §7 の順の組み替えであって、新しい作業ではない。

**D13 — Endpoint トークンを誰がいつ取るか**

発行側のアクセサは `ProxyClient` を要し、それには Endpoint トークンが要る
（`proxy_client(&cfg, endpoint_token)`）。今の利用者は全員 **コマンドごとに
1 回発行**している（`portal-server/src/main.rs:723`, `:1461`,
`portal-client/src/main.rs:1130`）。CLI は一発実行なのでそれで足りる。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | 呼び出しごとに発行（CLI と同じ） | 状態を持たない。常に新鮮 | 発行側の呼び出し 1 回ごとに Identity API への往復。一覧を定期更新する UI がそれを叩き続ける |
| B | ハンドルが持ち、期限が近づいたら取り直す | 往復はトークンの寿命ごとに 1 回 | facade が状態と方針を持つ。`Sdk` は `Clone` なので共有（`Arc<Mutex<_>>`）になる |
| C | 呼び出し側がトークンを渡す | 方針が面に出ない | SDK が吸収すべきものを呼び出し側に返す |

**決定: B。** 余裕値には先例があり、発明しなくてよい:
`auth0.rs:57` の `REFRESH_MARGIN = 60s` と `is_stale()`（`now + margin >= expires_at`）が
Auth0 トークンに対して同じ判断をしている。`EndpointToken` は `expires_in` を
持っているので、同じ形がそのまま書ける。A は CLI が一発実行だから成立している
形で、SDK は一発実行ではない。

共有になることは `close` の doc が既に言っている（クローンは所有物を共有する）ので、
面の説明と矛盾しない。

### 3.9 2b が実際に見つけたもの、と残った 1 つ

**2b は 8 シグネチャの入れ替えで済んだ。** `endpoints` / `enrollment` /
`membership` の 8 関数を `anyhow::Result<T>` から `Result<T, IdentityError>` に
変え、本体は 1 行も動かしていない —— `IdentityError::Transport` が
`#[from] anyhow::Error` なので、`MasqueH3Transport::connect(..)?` の `?` も
そのまま通る。

**壊れた呼び出し側は 1 箇所、しかもそれが D12 = C の価値そのものだった。**
`portal-core/src/agent.rs:279` の `not_found` は `anyhow::Error` を受け取り、
`chain()` を歩いて `IdentityError` に downcast してから
`Outcome::of_identity` を読んでいた。型が通るようになったので、鎖を歩く部分が
消えて述語が読みそのものになった。**他のアプリ呼び出し側は 1 行も変えていない**
（`IdentityError` は `std::error::Error` なので `?` と `with_context` がそのまま
効く）。

**D14 — トークン発行の読みをどうするか**

発行側のアクセサ（§3.3）は `ProxyClient` を要し、それには Endpoint トークンが
要る（D13 = B）。ところが `issue_endpoint_token` は今も `anyhow::Result` で、
**しかもその失敗には Identity API のものではないものが混ざっている** ——
「現在の Auth0 トークンが取れなかった」（`config.rs` の `issue`）。
`IdentityError` に押し込むと `Transport` の腕に入り、ネットワークの失敗として
読まれる。それは「資格情報を取り直せ」という指示を捨てる誤読である。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | `anyhow` のまま。facade のアクセサがそれを返す | 実装ゼロ | D10 / D12 で避けた `anyhow` が、よりによって**入口**に出る |
| B | `issue_endpoint_token` に型付きの失敗を与える（`Identity(IdentityError)` ＋ 資格情報の腕）。読みは `Outcome` | 面の読みが 1 種類に揃う。`portal-*` も分類できる | `isekai-p2p` に小さな型が 1 つ増える |
| C | facade が自分のエラー型を作って畳む | 下を触らない | facade が意味論を持つ＝「素通しだけ」を破る。約束する面に新しい語彙が増える |

**決定 B**（0.10 で実装）。D12 = C と同じ理屈（失われている場所で直す）であり、
**`Outcome` に足した腕は無い**: `Reauthenticate { explain }` が既にあり
（`outcome.rs` の `Outcome`）、「資格情報を取り直せ」はまさにその腕である。
読みの関数は `isekai-p2p` 側に置いた（core は `isekai-p2p` の型を知らないので、
`Outcome::of_*` には入れられない）。

**実装が足した 3 つ目の腕。** 素案は 2 腕（`Identity` ＋ 資格情報）だったが、
`config.rs` には `anyhow::bail!` が 2 箇所あった —— 同じ `Credential` が別の鍵の
登録を既に使っている場合で、これは**サーバに何も訊いていない**局所的な矛盾である。
`Mismatched` として分け、読みは `Rejected`（「要求が成り立たなかった。状態は
動いていない」＝鍵ごとに `Credential` を与えれば直る）にした。`Refused` では
ない: 「認可が断った」とは、規則が引かれたという主張だからである。

**`Reauthenticate` は資格情報の失敗すべてに付く。** `Auth0TokenSource` /
`AssertionSource` は `anyhow::Error` で答える trait なので、「更新を断られた」と
「認可サーバが答えなかった」は同じ形で届く。2 つの誤読のうち安全なのはこちら
である —— どちらでも動けるのは source を持っている側だけで、本当に「入り直せ」
である場合、app の source は既に自分のサインイン状態を印している
（`auth0::RefreshingAuth0Token`）。`Unreachable` と読めば、終わったセッションに
待ち続けろと言うことになる。

**消えたのは鎖歩きである。** `already_registered` は `downcast_ref` を捨てて腕を
見るだけになり（D12 が `portal-core` でしたのと同じ）、`is_permanent` は
`error.outcome()` が `Refused` かを見るだけになった。資格情報の腕は意図的に
「恒久」ではない（source が次の周で渡せることがある）。

**ただし core に 1 つメソッドが増えた（レビューが出した）。** `of_identity` は
`explain` を**サーバの答えだけ**から作る。だから助言（どの鍵か、どの
Enrollment Key のファイルか、ゲスト期間が終わったのか）を付けた `Identity` の腕を
`outcome()` に通すと、**その助言が落ちていた** —— `Credential` と `Mismatched` は
自分の言葉を `Outcome` に載せるので、面として非対称でもあった。
`Outcome::with_context(said)` を core に足して両方を保つ（順序は `anyhow` の
context と同じく外側が先）。`Unreachable::Deadline` は言葉を持たないので素通し
する —— 答えを読む関数はどちらも `Transport` しか作らないので、到達しない。

**`{:#}` の罠は 3 件目に出た。** `portal-client-ffi/src/lib.rs` の
`PortalError::Pair(format!("{e:#}"))` —— **別ワークスペースなのでビルドは通り、
言葉だけが消える**。Android で `register: true` の組み立てが `403` や `429` を
受けたとき、Kotlin 側に届くのは `"could not issue an Endpoint Token"` だけに
なっていた。型付きのエラーを入れるたびにこの罠が付いてくるので、
**鎖が欲しければ `anyhow::Error::from(e)` を通す**という規則を、その呼び出し側の
コメントにも書いた（同じファイルの他の `{e:#}` は `anyhow::Result` が相手なので
正しい、という判別も併せて）。

### 3.10 段 2a を書いて立った判断 — アクセサ 1 本が 2 層を跨ぐ

**D15 — 発行側アクセサの失敗の型**

`sdk.tickets().list()` は 2 つの理由で失敗する: Endpoint トークンが取れない
（`TokenError`）と、プロキシが断った／届かない（`ProxyError`）。`proxy_client`
は接続構築で `anyhow::Result` を返すので、ここも素通しにすると facade が
`anyhow` を継ぐ。

| | 選択肢 | 得るもの | 失うもの |
| --- | --- | --- | --- |
| A | `ProxyError` 1 本に畳む（トークン失敗を `Transport` 腕へ） | 型が 1 つ | **D14 が取り除いた誤読そのもの**。「資格情報を取り直せ」が `Unreachable` になる |
| B | `SdkError { Token, Proxy { source, reading } }` ＋ `outcome()` | 両方の型が保たれ、読みは `Outcome` 1 種類 | facade に型が 1 つ（`#[non_exhaustive]` 必須） |
| C | 不透明な構造体＋アクセサ | semver に最も強い | 利用者が `match` できない |

**決定 B**（0.11 で実装）。D14 が C を却下した理由は「facade が**畳む**＝意味論を
持つ」ことであり、B は畳まず「どちらの層が落ちたか」を言うだけである。

**`Reading` はルートの隣に置いた**（同じ判断の派生）。`Outcome::of_proxy` は
ルートごとの `Reading` を要するが、それを facade に書くと facade が意味を持つ。
7 本ぶんを `isekai_p2p_core::proxy::reading` に公開定数として置き、各メソッドの
doc から指した —— surface §4.3 が数えた「同じ `409` が呼び出し側ごとに 3 通りに
読まれている」の根治でもある。

**段 2a のレビューが見つけたもの**（9 件、すべて実体があった）:

- **キャッシュしたクライアントは恒久的に死ぬことがある。** MASQUE チャネルは
  tower の `Buffer` で、worker は内側の最初の `poll_ready` エラーを
  「以後のリクエストも同じエラーで失敗させるために」保存して受信口を閉じる
  （tower 0.5.3 `buffer/worker.rs`）。クライアントの構築は何にも届かないので、
  **最初の呼び出しがプロキシ不在と重なったハンドルは、プロキシが戻った後も
  プロセスが終わるまで同じ古いメッセージで `Unreachable` を返し続けた**
  —— キャッシュは `Arc` 共有なのでクローン全部が、である。`Transport` を見たら
  キャッシュを捨てる。
- **`401` でも捨て、さらに 1 回だけ再試行する。** 時計のずれ、呼び出しの間の
  サスペンド、床（`RENEW_MIN`）より短い TTL —— マージンが予測しない理由で
  トークンが拒まれ得る。利用者はこのハンドルのトークンを作れないので、
  `Reauthenticate`（「資格情報を取り直せ」）と答えるのはキャッシュの帳簿が
  助言として漏れ出すことになる。新しいトークンで 1 回だけやり直し、それも
  拒まれたらその拒否は Endpoint 自身のものとしてそのまま報告する。
- **`close` は持ち物を離さなければならなくなった。** 段 1 の `close` は
  「今は何も持っていない」ので `true` を返すだけだったが、ハンドルは MASQUE
  トンネル（＝生きた msquic ハンドル）を持つようになった。`shutdown_msquic` は
  生ハンドルがあると `RegistrationClose` を飛ばして `false` を返すので、
  文書化された順序（ハンドルを閉じてからスタックを落とす）が成り立たなくなって
  いた。
- **トークンの「まだ使える」に `RENEW_MIN` の床を当ててはいけない。**
  `renew_delay` の床は更新ループが空回りしないためのもので、「このトークンは
  まだ有効か」への答えではない。`token_ttl` が短い（＝呼び出し側が設定できる、
  サーバが切り下げる）場合、期限切れのトークンを 30 秒間「新鮮」と扱っていた。
  トークン自身の寿命を上限に clamp する。
- **群は値渡しにする。** `Grants<'a>(&'a Sdk)` に `&self` のメソッドを置くと、
  返る future が一時オブジェクトを借用するので
  `let f = sdk.grants().list();` が `E0716` になり、`ids.iter().map(..)` の
  素直な並行化も書けなかった（実際に再現して確認）。

**実装が教えた 3 点**:

- **`404` は status では読めない**（0.12 で訂正）。0.11 は
  `provisioning_redemptions` の `404` を `Missing::Vanished` と書いたが、これは
  `Reading::gone_kinds` 自身のドキュメントが警告している誤りだった ——
  problem+json でない `404`（中間装置のページ、ベースパス誤り、そのルートを
  持たないプロキシ）は `Problem { status: 404, problem: None }` として届くので、
  status で読むと「その鍵は無い」と答えてしまう。slug で読むのが正しいが、この
  ルートが実際にどの slug を返すかは観測されていないので書かない（D5 と同じ
  理屈）。結果として **7 本の読みは今はすべて同じ**。それでも定数を 7 本置くのは、
  ルートごとに名前が付いていれば最初に食い違うルートだけが動くからである
  （最初に食い違うのは revoke 3 本）。`create_grant` の upsert は **`200` で
  「既にあった」を返す**（`Made::Existing`）ので、`409` に意味は無い。
- **トランスポート失敗の原因鎖は `ProxyError` からは辿れない。**
  `ProxyError::Transport` は `anyhow::Error` を持つが source として印していない
  （`IdentityError::Transport` は `#[from]` で印している）。だから
  `of_proxy` が `{inner:#}` を `explain` に焼いており、**その言葉は
  `outcome()` 側にある**。`SdkError` の `Error::source` のドキュメントがこれを
  明記している。
- **キャッシュは `renew_delay` を共有する**（D13 = B）。`auth0.rs` の
  `REFRESH_MARGIN` を写すのではなく、既にテストのある
  `isekai_p2p::config::renew_delay` を公開して使う —— マージンが 2 つに
  分かれて片方だけ調整される事故を避ける。`ProxyClient` は `Clone` で
  `set_endpoint_token` が `Arc<RwLock<_>>` 越しなので、**トンネルを張り替えずに
  トークンだけ差し替わる**（セッションが走っているリレー脚を落とさない）。
  ロックは `std::sync::Mutex` で、**await 中は保持しない** —— facade の依存を
  1 クレートに保つため（`tokio` は dev のみ）。冷えたハンドルに 2 つの呼び出しが
  同時に来ると両方がトークンを取り得るが、後の 1 つが共有クライアントの上で
  差し替えるだけなので、1 往復の損で済み不整合は起きない。

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

**そのために要る例外（0.4 で明記）**: `rust/Cargo.toml` は
「**一つの版をワークスペース全体で**。すべては単一のタグで切られる」と書いていて、
各メンバは `version.workspace = true` でそれに従っている。facade が自分の線を
引くなら、**facade だけが `version.workspace` を使わない**という例外になる。
例外を作る判断そのものは D2 = B に含まれるが、ワークスペースの規則に
一行書き足す必要がある。

**crates.io には今出せない**: 依存に git-rev 固定の `h3` 系 3 本
（`rust/Cargo.toml:39`–`:41`）と、submodule を指す path 依存
（`axum-h3`, `h3-util`, `msquic-async`、同 `:25`, `:42`, `:52`）がある。
したがって「外に出す」は当面 **git / vendored での利用**を意味し、
semver はその上での約束である。publish を望むなら依存の形を先に変える話になる。

残るのは facade の最初の版だけで、これは実装時の判断になる
（`0.1.0` か、ワークスペースに合わせた `0.10.x` か）。
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
  約束しないものを同じクレートに入れると理由が消える。repo 内の依存なら
  2 クレートでも不便はない。外部利用者から要求が出たら B へ上げる。

  **「降りる」側の例を 0.4 で差し替えた**: `DatapathHook` を挙げていたが、
  **本番の利用者はいない** —— `camera-core/examples/validation_loss.rs` と
  `portal-core/tests/loopback.rs` だけで、`channel-masque` 自身の doc も
  「a test instrument」と書いている（api_review §3.4 も「テストと example のみ」）。
  `camera-core` が低位に留まる本当の理由は §3.5 段 2 の **QUIC 面**（ストリームと
  データグラム）である。

  **範囲の限定**（D8 = C1 との整合、§3.7）: ここで言う「低位」は
  **データパスと bind の内部**である。`shutdown_msquic` / `drain_msquic` は
  利用者が守る契約なので facade 側に出す。`camera-core` は §3.5 段 2 の QUIC 面の
  ために `isekai-p2p` に直接依存したままになり、repo 内では facade と 2 本が同居する。
- **計測の駆動**: `measure_for_connect` は接続経路が内部で呼ぶ（surface §5）。

## 6. 判断の一覧

選んだ理由は各節にある。ここは**何が確定したか**だけを書く。

| | 判断 | 決定 | 確定したもの |
| --- | --- | --- | --- |
| D1 | ハンドルの所有（Q4） | **C** 入口だけ | 7 群すべての第一引数は `Sdk`。`close()` は msquic を閉じない |
| D2 | クレートの見せ方 | **B** facade クレート | semver は facade だけが約束。`agent` は載せ替えまで残す |
| D3 | 非同期の形 | **A** async | facade は `async fn`。ランタイムは利用側のもの |
| D4 | サインインの駆動 | **A** 受け取るだけ | `Auth0TokenSource` と `AssertionSource` を**両方** trait として出す |
| D5 | revoke の `Reading` | **A** 揃える（確認が先） | 到達可能性の確認 → 厳しい側へ揃える → 確認できない分だけ文書化 |
| D6 | `Narrowing` / `device_name` | **A** 出す | `P2pConfig` のフィールドとして `Sdk::open` に出す（`connect` の引数ではない）。FFI は設定の形が動くので載せ替えと同時 |
| D7 | 締め切り（Q3） | **C** ハンドル既定＋上書き | 既定は 30 s / 60 s。読みは既にある（`Unreachable::Deadline`）ので、要るのは作る側 |
| D8 | 終了順序 | **C1** 自分のセッションだけ | msquic を閉じるのはプロセスの持ち主。`shutdown`/`drain` は facade に出す |
| D9 | 低位の面の再輸出 | **A** 出さない | 「低位」はデータパスと bind の内部。`camera-core` は QUIC 面のため 2 本に依存したまま |

0.4 のレビューで前提が動いて立ち上がった 2 つも、0.5 で決まった。

| | 判断 | 決定 | 確定したもの |
| --- | --- | --- | --- |
| D10 | `list_grants` / `revoke_grant` の名前 | **A** facade を唯一の名前に | アクセサは `ProxyClient` を直接呼び `anyhow` を継がない。`ListenerSession` の 2 つは配管として残る |
| D11 | `redeem` 1 本を足すか | **A** 足す | Enrollment Key は**何だったか言って断る**。読みは `Reading` の `fixable` 側 |

§7 段 2 に入って、さらに 2 つ出た（§3.8）。

| | 判断 | 選択肢 | 推奨 | 決まらないと止まるもの |
| --- | --- | --- | --- | --- |
| D12 | 棚卸し側の読み | — | **決定 C**（2b で実装済み。8 シグネチャ、呼び出し側は 1 箇所だけ変わり簡単になった） | — |
| D13 | Endpoint トークンの取得 | — | **決定 B**（`REFRESH_MARGIN = 60s` の先例に倣う） | — |
| D14 | トークン発行の読み | — | **決定 B**（実装済み。`TokenError` 3 腕。`Outcome` の腕は増やさず、`with_context` を 1 つ足した） | — |

段 2a を書いて、さらに 1 つ出た（§3.10）。

| | 判断 | 選択肢 | 決定 | 確定したもの |
| --- | --- | --- | --- | --- |
| D15 | アクセサの失敗の型 | 畳む / 2 腕 / 不透明 | **B** 2 腕＋`outcome()` | `SdkError { Token, Proxy { source, reading } }`。`Reading` は**ルートの隣**（`proxy::reading`）に置く |

段 2a のレビューが 1 つ立てた（§3.10）。

| | 判断 | 選択肢 | 推奨 | 決まらないと止まるもの |
| --- | --- | --- | --- | --- |
| D16 | 制御プレーン呼び出しの締め切り | 掛けない（利用者が包む）/ 3 つ目の既定値を足す / 呼び出しごとに引数 | **未決** | 無し（段 2c 以降は進められる。ただし掛けないままだと、ストリームを受けて答えないプロキシに対して呼び出しが永久に止まる） |

`Deadlines` の 2 つは「引き換え」と「接続」で、**どちらも計測された数である**
（FFI が「人が待つ時間」から選んだ）。制御プレーンの要求は 3 つ目の量で、
誰も計測していない —— ここで既定値を発明するのは D7 = C が避けたことそのもの
なので、0.12 は**掛けない**まま出し、利用者が
`tokio::time::timeout(d, sdk.tickets().list())` で包めることを文書化した。
`Deadlines` は `#[non_exhaustive]` なので、3 つ目を足すのは後からでも破壊的に
ならない。

これで §9 の 7 問には答えが付いている。本文書が出した判断は **16** で、
うち **15 が決定済み**（残りは D16）。

Q5（通知）と Q7（FFI 統合）は §4.2 / §4.4 に答えがあり、`FrameSink` という先例が
あるので**判断ではなく作業**である。Q2 と Q6 は既決（§0、§4.3）。
これで api_review §9 の 7 問はすべて答えが付いた。

## 7. 作る順

判断は尽きたので、以下は作業の順である。**各段がそれ自体で出せる**ように切った。

1. **facade クレートの骨格** — `Sdk::open` / `async fn` / `Deadlines` の既定と、
   `Auth0TokenSource` / `AssertionSource` の再輸出、`shutdown` / `drain`
   （D1, D2, D3, D4, D7, D8, D9）。入口の形がここで固まる。中身は空でよい。
   `version.workspace` の例外（§4.3）もここで入れる。
2a. **群アクセサ（発行側）の create / list**（実装済み）— §3.3。
   `grants().create/list`、`tickets().create/list`、
   `provisioning_keys().create/list/redemptions` の **7 本**。
   **D13 = B** のトークンキャッシュ（`renew_delay` 共有）と **D15 = B** の
   `SdkError` がここで入る。`grants()` の 2 本は `ProxyClient` を直接呼ぶ
   （D10 = A）。
2b′. **revoke 3 本** — **D5 が塞いでいる**。`409` が到達可能かを確かめ、
   到達可能なら厳しい側へ揃えてから、`reading` に 3 本を足して面に出す。
   先に `Reading` を書くと、推測が定数の権威を持ってしまう。
2b. **棚卸し 3 モジュールを型付きの失敗に**（D12 = C、実装済み）。`isekai-p2p` の
   `endpoints` / `enrollment` / `membership` の 8 シグネチャ。**動いた呼び出し側は
   `portal-core/src/agent.rs` の 1 箇所だけ**で、`portal-client` の 10 箇所は
   `.context(..)?` で anyhow に入れているので無変更だった（`portal-server` は
   この 8 つを呼んでいない）。**facade より先に下を直す**段で、ここだけは
   「素通し」ではない。
2c. **群アクセサ（棚卸し側）** — §3.2。2b が済めば素通しで足りる。
3. **`redeem` 1 本**（§3.4、D11 = A。Enrollment Key を名指しで断る）と
   **点検の要約**（§3.6）。どちらも足すだけで、既存の面を変えない。
4. **ポート面**（§3.5 段 1）。FFI 2 本が持っている形を facade に移す段で、
   ここから下は FFI に届く。
5. **FFI 2 本を facade に載せ替える** + **D6 の 2 項目**を同時に出す（§3.5）。
   Kotlin / Swift に届く変更はこの 1 回にまとめる。
   **`portal-client-ffi` は自分のワークスペース**で、自分の tracked な
   `Cargo.lock` を持つ（`rust/Cargo.toml` がその理由を書いている: 古いままだと
   タグを切った後に `cargo build --locked` が落ちる —— 0.7.0 がそれで FFI を
   壊して出た）。facade を向け直す**同じ段でロックを作り直す**。
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
