---
title: リレーが落ちたら、貼り直して paths を入れ替える
status: draft
related: portal_plan.md フェーズ4, p2p_mode_migration_plan.md, portal-core/src/path.rs
---

# リレーが落ちたら、貼り直して paths を入れ替える

リレーのサーバが再起動すると、そのレグの上に乗っている inner QUIC は**二度と
リレーを使わない**。直接経路が張れていれば通信は続くが、**フォールバックが
永久に失われた状態**で続く。次に直接経路が切れたらセッションは終わる。

新しいレグを張り直し、multipath でそれをパスとして**足し**、古いリレーパスを
**外す**。これがこの計画の内容である。

> 以下、`§n` は**本書**の節。仕様書を指すときは「**proxy 仕様 §n**」と書く。
> msquic の核は `submodules/msquic-async-rs/seera-msquic` を指す。

---

## 0. 結論を先に

### 0.1 提案の形は成立する。そして、それ以外の形は取れない

提案（client 側は `add_path` の `remote_addr` に MASQUE クライアントの代理 UDP
ソケットのアドレスを渡す／server 側は `add_bound_addr` を呼んでそれを MASQUE の
forward 先にする）は成立する。**しかもこの役割分担は設計の選択ではなく、核が
強制している。**

`peer.rs` の `enable_migration` が立てるのは `ReceiveObservedAddressReports` /
`AddAddressMode::NatTraversal` / `MultipathEnabled` / `PathKeepAliveIntervalMs`
であって、**`ServerMigrationEnabled` は立てていない**。したがって
`State.ServerMigrationNegotiated` は**両端とも false** である
（`connection.c:3388`、`Settings.ServerMigrationEnabled` が偽なら代入自体が走らない）。

その帰結が次の表で、**これがこの計画のすべての形を決めている**。

| 操作 | portal-client（QUIC client） | portal-server（QUIC server） | 根拠 |
| --- | :---: | :---: | --- |
| `add_path` | **○** | ✕ `INVALID_STATE` | `QuicConnAddPath` |
| `remove_path` | **○** | ✕ | `QuicConnRemovePath` |
| `add_bound_addr` | ✕ | **○** | `QuicConnAddBoundAddress` |
| `remove_bound_addr` | ✕ | **○**（ただし §3.4） | `QuicConnRemoveBoundAddress` |
| **受信パケットから新しいパスを作る** | ✕ | **○** | `path.c:358` |

読み方は 2 つある。

1. **client は自分でパスを足すしかない。** 受信からパスは生えないので、新しい
   レグが張れても、client がそこへ `add_path` しない限り何も起きない。
2. **server は自分でパスを足せない。かわりに、受信すれば勝手に生える。**

提案はこの 2 行そのものである。

### 0.1.1 P0 で測った（2026-09-29）

`portal-core/examples/relay_repath_spike.rs`。ループバックの UDP フォワーダが
リレーの代わりで、止めて別のを立てるのが「再起動」である。接続は
`transport::connect` が作るので、**portal が実際に出荷している設定**に対する答え
である。

> **この節は一度、答えを出しすぎた。** 初版は 4 回走らせて「5 問すべて通った」と
> 書いた。**33 回走らせると 3 回に 1 回落ちる。** 下はその後の内容である。

#### 見つかったのは、答えではなく阻害要因である

**`add_path` は成功し、何も起きないことがある。** 25 回のうち 8 回、`add_path` は
`Ok` を返し、クライアントのパス数も 1 → 2 に増え、そして**プローブが 1 つも
出ない** — `PathAdded` は来ず、server にもパスは生えず、10 秒待って何も起きない。

原因は核にある。

```c
// connection.c:9363 — add_path の直後
if (Path != &Connection->Paths[0] && Path->DestCid != NULL) {
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
}
```

**`DestCid` が無ければ `PATH_CHALLENGE` はそもそもキューされない。** そして
destination CID は、プールに予備があるときだけ新しいパスに割り当てられる
（`pathid.c:750`、`QuicPathIDGetUnusedDestCid` が `NULL` を返したらそのまま
戻る）。

**測定がこれを裏づけている。** spike は失敗した回に「新しいレグに届いた
データグラム数」を出すようにした。**失敗した回はすべて 0 である** — 送られて
いないのであって、送って返事が無いのではない。

```
FAIL  2. no PathAdded within 10s -- 0 datagram(s) reached the new leg,
         so the probe was never sent (no destination CID for the new path?)
```

**これは設計の前提条件である。** 貼り直しは「予備の destination CID がある」
ことに依存し、CID は接続越しに届く — **唯一の生きたパスが死んでいれば、
補充できない。** `QUIC_ACTIVE_CONNECTION_ID_LIMIT` は核のコンパイル時定数で、
Rust 側から動かす口は無い。

> 試して**効かなかった**こと: レグを止める前に 0.2 秒・2 秒待つ（8 回ずつ、
> どれも 6/8）。古いレグを生かしたまま `add_path` する（6/8）。
> **プールは時間では埋まらず、古いレグの生死とも関係しない。**

#### 通った回に言えること

以下は**プローブが出た回についての**答えであり、そこは安定している。

| # | 問い | 答え（プローブが出たとき） |
| --- | --- | --- |
| 1 | `add_path` は loopback の remote を取るか | **取る**（25/25） |
| 2 | `PathAdded` はどれくらいで来るか | **214 µs 〜 1.2 ms** |
| 3 | **server 側は、何も呼ばずにパスが生えるか** | **生える**（1 → 2） |
| 4 | 新しいレグを実際にトラフィックが通るか | **通る** |
| 5 | `remove_path` は枠を空けるか | **空ける**（両方 2 → 1） |

**3 はこの spike の成果として残る。** `add_bound_addr` も MASQUE の forward 先の
付け替えも要らない — server 側の msquic に対する操作は 1 つも無い。プローブが
出ないときに生えないのは server の問題ではなく、**何も届いていないから**である。

> **§0.2 の話とは別である。** msquic は何もしなくてよいが、**listener の
> レグを貼る論理は別問題**で、そちらは §0.2 のとおり貼り直さない。

**2 の速さは設計に効く** — ただし `began` は `add_path` が返ったあとに取って
いるので、これは**下限**である。

**5 は §0.3 を和らげる。** 非同期だが 10 秒以内に枠は戻り、server 側の対応する
パスも消えた。

#### 測り方を 2 回間違えた

1. server の基準値を `add_path` の**あと**に読んでいた。そのときには既に 2 本で、
   「増えなかった」と報告しながら実際には増えていた。基準はハンドシェイク直後に
   取る
2. **4 回走らせて「安定」と書いた。** 3 回に 1 回落ちるものを 4 回引いて全部
   当たった。**spike は繰り返し走らせて初めて答えになる**

### 0.2 しかし listener は、死んだレグを貼り直さない — 意図的に

本書の初版はここに「server 側は何もしなくてよい可能性がある」と書いた。**誤りで
ある。** 根拠にした `poll_and_bind` という関数は**存在しない** — `listener.rs:567`
に残っている古いコメントの中の名前で、実物は `poll_signaling` である。そして
その振る舞いは逆だった。

```rust
// listener.rs:685 — レグのタスクが終わったとき
state.spent.insert(id.clone());
// listener.rs:696 — 次の巡回
|| state.spent.contains(&connection.connection_id)
```

**レグが死んだ接続は `spent` に入り、二度と bind されない。** `spent` が消えるのは
プロキシがその接続を一覧から落としたとき（`forget_gone`）だけで、テスト
`a_peer_whose_leg_died_is_not_bound_again` がこの規則を固定している。

これは事故ではなく判断である。**同じ `connection_id` にレグを貼り直すのは、
「一度死んだものを生き返らせる」という意味になる。**

したがって server 側の道は 2 つしかない。

| | |
| --- | --- |
| **A. 新しい `connection_id` で入り直す** | client が `peer_connect` をやり直す。プロキシの一覧から古い ID が落ちれば `spent` も消え、listener は**新しい接続として**レグを貼る（既存の経路をそのまま使える） |
| **B. `spent` の規則に例外を作る** | 「レグは死んだが inner QUIC は生きている」を listener が知る必要がある。listener はそれを知らない — 知っているのは client だけである |

**A を採る。** B は listener に、自分の持っていない情報を前提にした例外を足す
ことになる。A なら listener 側の変更は**ゼロかそれに近い**（§4 P0 で確かめる）。

その代わり **§2.2 が計画の中心になる**: 新しい `connection_id` で開いたレグを、
**古い inner QUIC 接続**のパスとして足す、という非対称を扱うことになる。

### 0.3 上限は 4 で、しかも `remove_path` は即座には空けない

`QUIC_MAX_PATH_COUNT` は **4**（`quicdef.h:398`）。リレーパス 1 + 直接経路 1 で
既に 2 で、貼り直すたびに 1 つ増える。

そして **multipath では `remove_path` は非同期である。** `MultipathNegotiated`
が真のとき `QuicConnRemovePath` は `LocalClose` / `SendAbandon` を立てて
`PATH_ABANDON` を送るだけで（`connection.c:8380` の `else` 側）、**`PathsCount`
はその場では減らない。**

- 「足してから外す」順序では、毎回 **N+1 が瞬間的な山**になる
- リレーが数秒おきに落ちる（flapping）と、`QuicConnAddPath` が
  `QUIC_STATUS_OUT_OF_MEMORY` を返す

**片付けは機能の一部だが、それだけでは上限を保証しない。** 貼り直しの間隔に
下限が要る（§3.3）。

---

## 1. いま何が起きているか

### 1.1 client のリレーパスは「最初のパス」である

```rust
// peer.rs: dial
conn.set_remote_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
```

`port` は `ConnectRelay::local_addr` のポート、すなわち**このプロセスが開いた
loopback UDP ソケット**で、MASQUE クライアントがその両端を面倒みている。inner
QUIC から見れば、リレーは「loopback の相手」でしかない。

### 1.2 前提は揃っている。ただし**条件付きで**

`direct_path::prepare` が `share_binding(true)` / `unconnected_socket(true)` /
`set_local_addr(127.0.0.1:0)` を立てるので `add_path` の前提は揃う。

**しかし `prepare` が呼ばれるのは `candidate` があるときだけ**であり
（`peer.rs:785`）、`MultipathEnabled` を立てる `enable_migration` も
`candidate.is_some()` である（`peer.rs:775`）。そして `candidate` は
`wait_for_observed` が時間内に観測アドレスを得られなければ `None` になり、
セッションは**リレー専用**で続く（`session.rs:700`）。

> **そしてリレー専用のセッションこそ、リレーが死ぬと即座に終わるものである。**
> 直接経路という二本目が無いのだから。**本書の仕組みは、いちばん助けが要る
> セッションには効かない。** §3.5 で扱う。

### 1.3 レグが死んでも、client には誰も知らせない

`InitiatorSession` は `open_connect_relay` を**一度だけ**呼ぶ。そして
`ConnectRelay` が公開しているのは `local_addr` / `relay_origin()` /
`observed()` / `shutdown_token()` だけで、**H3 接続が終わったことを外へ出す口が
無い**（`bind.rs:613`）。タスクは `start_connect_udp` が成功した後、自分の
`session_shutdown.cancelled()` を待つだけである。

気づく経路は事実上 `RelayLegLease` しかないが、そちらは §3.1 のとおり
**気づいた瞬間にレグを畳んでループを抜ける**。

### 1.4 `path.rs` は「リレーのペアは不変」を前提に書かれている

`keep_on_the_best_path` は起動時に一度読んで、以後**定数のように扱う**。しかも
2 箇所に持っている:

- `Paths::relay` — 「これはリレーか」の判定（`path.rs:229` ほか）
- ループのローカル `relay`（`path.rs:465`）— `prefer_path` の 3 つの呼び出し
  （`path.rs:538` / `:551` / `:597`）が使う

**両方を動かさないと、片方だけ新しくなって死んだレグを指し続ける。**

---

## 2. 形

```text
レグが死ぬ（client が知る）
   │
   ├─ 新しい peer_connect → 新しい connection_id・新しいチケット
   │      └─ listener 側: 一覧に現れるので既存の poll_signaling がレグを貼る
   │
   ├─ 新しい ConnectRelay（新しい loopback ポート）
   │
   ├─ conn.add_path(127.0.0.1:0, 新しい local_addr)
   │      → PATH_CHALLENGE が新しいレグを通って出ていく
   │
   ├─ PathAdded（path_id 付き）を待つ
   │      → path.rs の「リレーはこれ」を差し替える（§1.4、**先に要る**）
   │
   └─ conn.remove_path(旧 local, 旧 remote) — 非同期（§0.3）
```

### 2.1 `add_path` のローカルアドレス

`127.0.0.1:0` を渡す。`add_path` の doc によれば、具体アドレスを渡したパスは
**接続のバインディングを共有する** — ローカルポートは既存パスと同じになる。
新しい 4 タプルは `(同じ local, 新しい remote)` で、remote が違うので別のパス
になる。重複判定は 4 タプル一致なので `ADDRESS_IN_USE` は起きない。

### 2.2 inner QUIC は 1 つ、`connection_id` は 2 つ

§0.2 の A を採ると、**プロキシから見た「接続」が変わるのに、その上を通る QUIC
接続は同じ**という状態になる。確かめることが 3 つある。

1. 古い `connection_id` のリース／エッジは、client が畳んでよいのか
   （畳まないと枠を食い、畳むと listener 側の `spent` が消える契機にもなる）
2. 新しい `connection_id` のレグが立つまでの時間。listener の巡回間隔がそのまま
   下限になる
3. listener 側で `direct_path::advertise` がもう一度走り、`add_bound_addr` が
   **同じアドレスに対して** `ADDRESS_IN_USE` を返す（`direct_path.rs:138` が
   既に書いている）。新しいレグのバインディングは別アドレスなので通るはずだが、
   **それは 2 本目の直接経路候補を増やすことでもある** — 上限 4 に効く

---

## 3. 決めなければならないこと

### 3.1 「リレーが落ちた」をどう知るか

| | いつ分かるか | 問題 |
| --- | --- | --- |
| `ConnectRelay` の H3 接続が終わる | 即座 | **口が無い**（§1.3）。`MasqueClient` / `H3Channel` から出す配線が要る |
| `RelayLegLease` の `Verdict::LegGone` | 1 リース TTL 以内 | **気づいた瞬間に `leg.cancel(); return;`**（`relay_lease.rs:288` / `:365`）。検知に使うなら、貼り直しは `RelayLegLease` の**外**に置き、リースを張り直す側になる |
| `path.rs` の失速ウォッチドッグ | `STALLED_GRACE` 後 | 直接経路に乗っている間は**リレーに何も流れない**ので当たらない |

3 つ目が当たらないことが重要である。**直接経路に乗っているセッションは、リレー
パスが死んだことを自力では気づけない。**

1 つ目が第一候補だが、**これは「既にある信号を読む」ではなく「信号を作る」**
作業である。P1 の見積もりはそれを含む。

### 3.2 直接経路に乗っているときも貼り直すか

**貼り直す。** それがこの機能の目的である — 直接経路が生きているうちは通信に
影響が無く、だからこそ「フォールバックが消えている」ことに誰も気づかない。

### 3.3 何回、どれくらいの間隔で

指数バックオフで上限を持つ。**下限も要る**（§0.3）: `remove_path` が非同期な
ので、間隔が短すぎると `PathsCount` が減る前に次を足してしまう。

諦めた後のセッションは「直接経路だけで動いている」状態で、それは**動いては
いるが一本足である**ことを運用者が知るべき状態である。

### 3.4 `remove_bound_addr` は掃除ではない。**接続を殺しうる**

初版は「パスのエントリを消すとは書かれていない」として測定項目に置いた。
**書かれている。そして危険である。**

`QuicConnRemoveBoundAddress` はバインディング一覧を過ぎたあと
`Connection->Paths[]` を走査し（`connection.c:8213`）、**LocalAddress だけで
一致を取る**。一致したパスが `IsActive` か、または最後の 1 本なら
`QuicConnSilentlyAbort` を呼んで `QUIC_STATUS_ABORTED` を返す
（`connection.c:8229`〜`:8246`）。

listener では**すべてのパスが 1 つのバインディングのローカルアドレスを共有する**。
直接経路が張れていないセッションで、古いリレーレグのアドレスに対してこれを
呼べば、**セッションごと静かに落ちる。**

→ **server 側で `remove_bound_addr` を呼ぶ案は、そのままでは採れない。**
§0.2 の A なら、そもそも呼ぶ必要が無い（古い接続は別の接続として終わる）。

### 3.5 リレー専用のセッションをどうするか

§1.2 のとおり、`candidate` が無いセッションには multipath も共有バインディングも
無く、`add_path` は成立しない。**そして、そのセッションこそリレーが死ぬと終わる。**

選べるのは 2 つ。

| | |
| --- | --- |
| **本書の対象外と言う** | 助ける対象は「直接経路があるセッションのフォールバック」に限る。**正直だが、価値の大きい半分を落とす** |
| **`enable_migration` を無条件にする** | `candidate` の有無と multipath の有無を切り離す。`prepare` の 3 つの設定は候補アドレスを要求しない — `add_candidate_addr` だけが要求する。**影響範囲は `peer.rs` の 2 行だが、全セッションのハンドシェイクに効く** |

**決めずに実装を始めてはいけない。** 後者なら P0 の前に単独で出せる。

---

## 4. 段取り

| # | やること | 出口 |
| --- | --- | --- |
| **P0** ◐ | **spike**（`portal-core/examples/relay_repath_spike.rs`） | **server 側の msquic 操作が要らないことは決まった。** かわりに阻害要因が出た（§0.1.1）— **destination CID が無ければプローブが出ない。** P0 はそれが解けるまで閉じない |
| **P0b** | 予備の destination CID を確保する方法を見つける（§5-7） | **`add_path` が黙らない。** これが無いと P4 は 3 回に 1 回動かない |
| **P1** | レグの死を client に届ける（§1.3 の配線）。貼り直しはしない | 「フォールバックが消えた」が**ログに出る**。いまは無音 |
| **P2** | `path.rs` が「リレーのペアは動く」を知る（§1.4 の 2 箇所） | **まだ何も動かないが、P3 がこれ無しでは出せない**（§4 の注） |
| **P3** | 貼り直し — 新しい `peer_connect` と `ConnectRelay`、古い側の後始末（§2.2） | 新しいレグが立つ。inner QUIC はまだ使わない |
| **P4** | `add_path` と `PathAdded` 待ち、`remove_path`、間隔の下限（§0.3） | **inner QUIC が新しいリレーを使う** |
| **P5** | 実配備でリレーを再起動して端から端まで | — |

> **P2 は P3 より前でなければならない。** 初版は逆に並べていた。`PathAdded` は
> `keep_on_the_best_path` の中でしか観測できず、そこに新しいリレーの
> `PathAdded` が届くと `Paths::added` は「リレーではないペア」として **true** を
> 返し、`Step::MoveOnto` → `prefer_path` が走る。つまり **生きている直接経路から、
> 立てたばかりのリレーへ転送を移してしまう** — しかも統計は `direct` と
> ラベルされる。P4 だけを先に出すと、**いまより悪くなる。**

**P1 は単独で価値がある。** いまは「フォールバックが永久に失われた」ことを
誰も知らない。貼り直しが入る前でも、それが**見える**ようになるだけで、
一本足で走っているセッションを運用者が数えられる。

---

## 5. 確かめていないこと

**msquic についての未知は尽きていない。** 7 が残り、それは設計の前提に関わる。

1. **新しい `connection_id` で入り直したとき、listener 側が本当にレグを貼るか**
   （§0.2 A）。`spent` は古い ID のもので、新しい ID は素通しのはずだが、
   プロキシの一覧に両方が並ぶ時間がある
2. **古い `connection_id` のエッジを client が畳めるか。** 畳めないと枠を食う
3. ~~**MASQUE の `Forward` モードが、再起動したリレーをどう扱うか。**~~
   **読んで答えが出た。** 転送ソケットは `(StreamId, 送信元アドレス)` ごとに
   `UdpSocket::bind("0.0.0.0:0")` で新しく開かれ、その表は `MasqueClient` の中に
   ある（`from_quic_to_udp.rs:581`）。リレーの再起動は H3 接続ごと、つまり
   `MasqueClient` ごと消すので、**新しいレグは必ず新しい送信元アドレスを
   見せる。** 心配していた「古いソケットが残る」は起こらない
4. **`PATH_ABANDON` が完了して `PathsCount` が減るまでの時間**。10 秒以内には
   戻ることだけ見た（§0.1.1）
5. **`add_path` から `PathAdded` まで**。**214 µs 〜 1.2 ms** は下限である —
   時計は `add_path` が返ったあとに始めており、イベントキューは誰も drain して
   いない
7. **予備の destination CID をどう確保するか**（§0.1.1）。**これが P0 の成果の
   うち、いちばん重い。** `QUIC_ACTIVE_CONNECTION_ID_LIMIT` は核の定数で、
   msquic-async から触る口は無い。レグが死ぬ**前**に予備を持てるのか、
   持てているかを外から確かめられるのか、どちらも分かっていない
6. **listener 側で `advertise` が 2 度目に何をするか**（§2.2-3）。spike は
   `ListenerSession` を使っていないので、ここは答えていない

---

## 6. この計画で解かないもの

1. **リレー自身の冗長化。** 別のリレーへ張り替えるのは
   `relay_proximity_client.md` の続きであって、本書は「同じ相手にもう一度」だけ
   を扱う
2. **listener 側から貼り直しを起こすこと。** listener は「レグが死んだが QUIC は
   生きている」を知らない（§0.2 B）
3. **直接経路が落ちたときの再探索。** 本書はフォールバックを取り戻すだけで、
   直接経路をもう一度 punch する話はしない
