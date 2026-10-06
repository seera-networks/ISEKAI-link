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

> **冒頭の「直接経路が張れていれば通信は続く」は、一度嘘になって戻った。**
> P5 で測ると接続ごと落ちていた（§7.4）— 原因は msquic の側で、1 本のパスの
> loss detection が接続を閉じていたことである（§7.3）。**2026-10-05 に上流で
> 直り**、パスだけが放棄されるようになった（§7.7）。以下を読むときは、
> §7.2〜§7.4 が**その修正より前の観測**であることに注意してほしい。

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

#### どこで詰まっているか（追試の結果）

`QuicPathIDAssignCids` の中で `QuicSendSetSendFlag` が呼ばれていない、という
見立てを試した。**そこは直しても変わらない** — 20 回走らせて失敗の仕方も率も
同じで、失敗した回はやはり「新しいレグに 0 個」だった。

理由は**唯一の呼び出し元がすでに呼んでいる**からである。

```c
// connection.c:5397 — NEW_CONNECTION_ID を受け取ったときの処理の中
if (QuicPathIDAssignCids(PathID)) {
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
}
```

**そして、その唯一の呼び出し元が受信処理である。** `QuicPathIDAssignCids` も
`QuicConnAssignPathIDs` も、**相手から NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID
が届いたときにしか走らない。**

詰まりはもう 1 段上にある。

```c
// QuicConnOpenNewPath — add_path から呼ばれる
if (Connection->State.MultipathNegotiated) {
    PathID = QuicPathIDSetGetUnusedPathID(&Connection->PathIDs);   // 新しい path id
    ...
}
```

**multipath では、新しいパスは新しい path id を取る。そして生まれたばかりの
path id には destination CID が 1 つも無い** — それは相手が
`PATH_NEW_CONNECTION_ID` で**その path id に対して**発行してくるものである。

つまり `add_path` の時点で challenge が出るかどうかは、**相手がその path id 用の
CID を既に発行済みかどうか**という競争に掛かっている。そして出なかった場合、
補充は受信処理でしか起きないので、**唯一の生きたパスが死んでいれば永久に来ない。**

#### 待てば直る。そして LTTng で中身が見えた

**相手は先回りして出す。** `QuicPathIDSetGenerateNewSourceCids` は
`Connected` の時点で上限（`QUIC_ACTIVE_PATH_ID_LIMIT` = 4）まで path id を
作り、そのすべてに source CID を生成する（`crypto.c:1653`）。つまり path id と
CID は `add_path` を待たずに割り当てられる。

**LTTng でトレースを取った。** stdout バックエンドはイベントごとに printf
するので測る対象の時間を変えてしまう — LTTng ならそれが無い。

失敗した回のトレースで、**どちらの端がどの path id の destination CID を
受け取ったか**を数えた（2 回捕まえて、どちらも同じ形）。

| 接続 | 受け取った DestCid |
| --- | --- |
| **client** | **path id 0 だけ**（4 個） |
| server | path id 0・1・2・3 に各 16 個 |

そして時刻が説明している。

```
server が path id 1..3 を作った      14:07:00.718687873
最後にパケットが届いた               14:07:00.718684083   ← 3.8 µs 前
（以降 30 秒、受信ゼロ）
```

**サーバは自分の path id 1〜3 用の CID を作り、PATH_NEW_CONNECTION_ID を
キューに載せた。その時点でリレーはもう無い。** クライアントは path id 1 用の
CID を永久に受け取れない。

#### 待ちは効く（対照付き、LTTng 下）

| 停止前の待ち | 失敗 |
| --- | --- |
| 0 ms | **6 / 15**、別の回で **5 / 20** |
| 200 ms | **0 / 20** |
| 5000 ms | **0 / 15**、別途 **0 / 25** |

**同じ時間帯に交互**に走らせている。対照が 25〜40% で落ちているので、失敗し
やすい時間帯での 0 である。

**200 ms で足りる。** トレースが「サーバは数 ms 後にキューする」と言っている
以上そうなるはずで、実際そうなった — **予測して当たったのはこれが初めて**で、
機構が本当に押さえられたことの確認になっている。

> **率だけを見て 3 回間違えた。** 8 回ずつで「効かない」、25 回ずつで「平坦」、
> 120 回で「待てば直る」（実際は静かな時間帯）。**同じ構成の失敗率が 0%〜67% で
> 動く**以上、**同じ時間帯の対照**を挟まない比較は意味を持たない。決着したのは
> 対照を挟み、かつ**機構そのものを見た**からである。

#### 残っている謎（小さくなった）

一度だけ、計測を入れないビルドで **5000 ms が 3/20 落ちた**。その後は再現して
いない — **以降 0/55**（LTTng 40 回、計測なし 15 回）。

**その 3 回が何と言って落ちたかは記録していない。** 文面まで記録した失敗は
すべて「0 datagrams / destination CID が無い」であり、同じ機構だった可能性が
高いが、**確かめる手立てはもう無い。** 記録しなかったことがこの調査で唯一
取り返しのつかない手落ちである。

#### 観測した（`QUIC_LOGGING_TYPE=stdout` と、その場の printf）

C ライブラリを logging 付きで建て直し、`QUIC_PARAM_CONN_ADD_PATH` の直後で
**新しいパスの path id が持っている destination CID を数えた。**

```
PASS  2 | ADDPATH pathid=1 had_cid=1 assigned=0 dest_cids=4 unused=3
FAIL  2 | ADDPATH pathid=1 had_cid=0 assigned=0 dest_cids=0 unused=0
```

**10 回中 10 回、`had_cid` が成否を言い当てる。** そして失敗した回の path id 1 は
`dest_cids=0` — **その path id 用の CID が 1 つも届いていない。**

つまり詰まりはこうである。

1. `add_path` は `Path->DestCid != NULL` のときしか `PATH_CHALLENGE` を
   キューしない（`connection.c:9363`）
2. 新しいパスは新しい path id を取り、その path id の destination CID は
   **相手の `PATH_NEW_CONNECTION_ID` で届く**
3. 届いた CID をパスに**割り当てるのは `QuicPathIDAssignCids` だけ**で、
   その唯一の呼び出し元は**受信処理**である
4. したがって、**CID が届いていない状態で追加されたパスは、何も届かない限り
   永久に probe されない** — そして「何も届かない」は、リレーが死んだあとの
   まさにその状態である

**したがって順序がすべてである。** CID が届くのを待ってからレグを手放せば通り、
待たずに手放せば、待つ相手がもう居ない。

> **`QuicPathIDAssignCids` を `add_path` からも呼ぶ**ようにして測った。効かない。
> 失敗する回は `assigned=0` で返る — **未使用の CID が無い**のだから当然である。
> 欠けているのは呼び出しでもフラグでもなく、**CID そのもの**だった。

> **率は環境に強く依る。** 同じコードで 20%〜67% の失敗率を観測し、最後の
> 22 回（CPU 負荷を掛けた分を含む）は全部通った。**だから率での A/B は
> 信用できない** — 判定は `dest_cids` を見ること。

#### 設計への帰結

**§0.1.1 の B（レグが健全なうちに 2 本目のパスを開いておく）を採るべき理由が、
推測ではなく観測になった。** 健全なうちなら CID は届いており（`dest_cids=4`）、
パスは検証される。貼り直しは「そのパスの先に新しい MASQUE クライアントを
繋ぎ替える」になり、**`add_path` を接続が聞こえなくなってから呼ぶことがなくなる。**

#### したがって手は 3 つある

| | |
| --- | --- |
| **A. レグが死んでから開く（これを採る）** | 本番ではリレーは CID の交換が済むまで生きている。CID はハンドシェイクの数 ms 後に届き、**その後は滞留する**ので、数分〜数時間後に落ちたリレーなら揃っている |
| ~~B. レグが生きているうちにパスを開いておく~~ | **成立しない**（下記） |
| **C. msquic を直す** | `QuicConnOpenNewPath` が新しい path id を取ったとき、その path id 用の CID を相手に要求する。**上流の変更**。A の残余リスクを消したくなったときの手 |

**A を採る。**

> **B は成立しない。** 新しいパスの remote は「新しい MASQUE クライアントの
> ソケット」であり、それは**リレーに繋ぎ直して初めて存在する**。健全なうちに
> 開こうにも開く先が無く、行き先のないループバックソケットへ開いても
> `PATH_CHALLENGE` が相手に届かないのでパス検証は通らない。「後で繋ぎ替える」
> ことはできない — **検証を通すには最初から転送されている必要がある。**

**CID が滞留することの確認。** アイドル時の CID 回転
（`DestCidUpdateIdleTimeoutMs`, `send.c:1864`）が触るのは**存在するパスの現用
CID** だけである。path id 1 にはパスが無いので回転せず、未使用のまま残る。

**spike は失敗を誇張していた。** ハンドシェイク直後にリレーを殺すので、
CID が届く数 ms の窓を狙い撃ちしている。本番でその窓に当たるのは「セッション
確立の直後にリレーが落ちる」場合だけである。

#### 残余リスクは消えない。だから黙らせない

窓は狭いが、当たったときの症状は**無音**である — `add_path` は成功し、パスは
増え、probe は永久に出ない。**そして待っても直らない**（CID を運ぶ経路が無い）。

したがって貼り直しは **`PathAdded` を待ち、来なければ諦めて言う**。
`remove_path` で片付け、**そのセッションはフォールバックを失ったまま**である
ことを報告する。窓が狭いことは、報告しない理由にはならない。

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

> **測った。そして本節の警告は、書かれているより悪い（§7.8）。**
> 「即座には空けない」ではなく、**空かない。** 放棄されたパスも、
> `remove_path` が受理されたパスも `Connection->Paths` の枠を返さず、4 に
> 達すると `add_path` は以後ずっと `QUIC_STATUS_OUT_OF_MEMORY` である。
> リレーパス 1 + 直接経路 1 で 2 を使っているので、**検証されないパスを
> 2 回吸収したら、その接続は二度とパスを開けない。**
>
> 記録していた `QUIC_STATUS_NOT_FOUND` は別件だった。ワイルドカード
> `0.0.0.0:0` のハンドル自体は**在るパスには届く**（受理される）。
> `NOT_FOUND` は「そのパスがもう無い」の意味で、**掃除されていない証拠では
> なく、掃除された／そもそも開けていない証拠**である。
>
> **なぜ空かないかは §7.10 で確定した** — 相手が知りもしないパスの放棄に
> 相手の同意を待つため、`QuicPathRemove` が永久に呼ばれない。上流のバグで
> ある。

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

### 1.3 レグが死んでも、client には誰も知らせなかった（P1 で解消）

`InitiatorSession` は `open_connect_relay` を**一度だけ**呼ぶ。そして
`ConnectRelay` が公開しているのは `local_addr` / `relay_origin()` /
`observed()` / `shutdown_token()` だけで、**H3 接続が終わったことを外へ出す口が
無い**（`bind.rs:613`）。タスクは `start_connect_udp` が成功した後、自分の
`session_shutdown.cancelled()` を待つだけである。

気づく経路は事実上 `RelayLegLease` しかないが、そちらは §3.1 のとおり
**気づいた瞬間にレグを畳んでループを抜ける**。

> **P1 で口を作った。** `run_bridge` は H3 ストリームが終わると
> `inbound.recv()` が `None` を返して抜ける — そこが「レグが死んだ」瞬間で、
> それまでは debug ログ 1 行で消えていた。`start_connect_udp` がその終了を
> 表すトークンを返すようにし、`ConnectRelay::ended()` として外に出した。
>
> **`shutdown_token()` とは別物である。** あちらは「止めてくれ」と**言う**側、
> こちらは「止まった」と**言われる**側で、誰も頼んでいないのに止まったことが
> 分かるのはこちらだけである。セッションを畳めば両方が落ちるので、
> 判定は `watch_leg` に出してテストで固定した — **両方同時に落ちたら teardown**
> であり、`select!` のどちらの腕が先に起きたかに依存しない。
>
> **「言う」のは早くなければならない。** `close()` は `report_state("closed")`
> を最大 3 秒待ってからレグを畳んでいた。ところが**その報告こそがプロキシに
> レグを解放させる**ので、待っている最中に CONNECT-UDP が落ち、まだ誰も
> 「止めてくれ」と言っていない状態で `ended` が発火する — **通常終了のたびに
> 警告が出る。** `close()` の先頭で意思表示するようにした。
>
> **検知できるのは接続の喪失であって、ストリーム単独の終了ではない。**
> ブリッジがそれを知るのは受信チャネルが閉じたときで、その送信端が落ちるのは
> `from_quic_to_udp` のタスクごと終わるとき — ストリームの登録を個別に外す
> 経路が無いためである。**リレーの再起動は接続ごと落ちるので対象に入る**が、
> 「このセッションだけ閉じて H3 は生かす」リレーは検知できない。
>
> **どれくらいで知らせるかは P5 で決め直した。** この口ができた時点では
> レグの QUIC 接続の既定（keepalive 10 秒 + disconnect timeout 16 秒）に
> 乗っていて、検知に 18〜26 秒かかっていた。**レグだけ 2 秒 / 6 秒にして
> 7.6〜9.5 秒にした**（§7.5.3）。

### 1.4 `path.rs` は「リレーのペアは不変」を前提に書かれている

`keep_on_the_best_path` は起動時に一度読んで、以後**定数のように扱う**。しかも
2 箇所に持っている:

- `Paths::relay` — 「これはリレーか」の判定（`path.rs:229` ほか）
- ループのローカル `relay`（`path.rs:465`）— `prefer_path` の 3 つの呼び出し
  （`path.rs:538` / `:551` / `:597`）が使う

**両方を動かさないと、片方だけ新しくなって死んだレグを指し続ける。**

> **P2 で半分やった。** ループのローカルは消し、`Paths::relay` を唯一の出所に
> した（`prefer_path` の 4 箇所すべてがそこを見る）。
>
> そして**退避先が「問い」になった。** `Paths::fall_back()` は
> `Option<Pair>` を返し、レグが死んだあとは `None` である — 失速ウォッチドッグと
> `PathRemoved` の退避は、どちらもこれを訊いてから動く。**死んだリレーを
> available と宣言すると、生きている直接経路まで backup に落ちて接続が止まる**
> ので、訊かずに退避するのは何もしないより悪い。
>
> 「レグが死んだ」は P1 の `ConnectRelay::ended()` がそのまま使える —
> `keep_on_the_best_path` の新しい引数がそれである。
>
> **残りは「移った」で、P3 のものである。** いまの引数は
> `CancellationToken`（＝消えた）だけなので、P3 はそれを「新しいペア」を運べる
> ものに広げることになる。足場だけ先に置いても使われない死んだコードになるので、
> P2 では置かなかった。

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

> **回数の実効上限は 2 で、間隔とは関係ない（§7.8）。** 枠は返らないので、
> `REATTACH_ATTEMPTS` が 8 であっても、パスを開けるのは**最初の 2 回だけ**で
> ある — 3 回目以降はレグが立っても `add_path` が
> `QUIC_STATUS_OUT_OF_MEMORY` を返し、`path.rs` の「パスを開けなかったので
> この接続にはまだフォールバックが無い」という error が出るだけになる。
> **間隔の下限はそれでも要る**が、下限を守っても回数は増えない。
>
> **「失敗 2 回」である**（§7.10）。成功した貼り直しは枠を返すので回数を
> 食わない。食うのは**レグが立ったのにパスが検証されなかった**回だけで、
> それが 2 回で尽きる。間隔やバックオフでは動かない上限なので、動かすなら
> 「枠が尽きたら peer connection ごと貼り直す」か、上流を直すかである。
>
> **そして上流が直った（§7.11）。** seera-msquic#119 で検証されなかったパスも
> 枠を返すようになったので、この天井は**もう当たらない** — 1 本のセッションで
> リレーが 3 回落ちても `add_path` は 3 回とも通る。実測した。

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

> **P3 で前者を採った（2026-09-30）。** `RelayOptions::unconnected` が無い
> セッションは、レグが死んだときに**貼り直さず、その旨を言って終わる**
> (`Reattach::refusal`)。後者は `peer.rs` の 2 行だが全セッションの
> ハンドシェイクに効く変更で、貼り直しの是非とは別に測るべきものである。
> **落としている半分は落としたままで、ログにそう書いてある** — 黙って
> 貼り直して「直ったように見えるが何も繋がっていない」よりは良い。

---

## 4. 段取り

| # | やること | 出口 |
| --- | --- | --- |
| **P0** ◐ | **spike**（`portal-core/examples/relay_repath_spike.rs`） | **server 側の msquic 操作が要らないことは決まった。** かわりに阻害要因が出た（§0.1.1）— **destination CID が無ければプローブが出ない。** P0 はそれが解けるまで閉じない |
| **P0b** | 不要になった（§0.1.1 A）。CID は本番では揃っている | — |
| **P1** ✅ | レグの死を client に届ける（§1.3 の配線）。貼り直しはしない | 「フォールバックが消えた」が**ログに出る**。§1.3 は解消 |
| **P2** ✅ | `path.rs` が「リレーは永遠ではない」を知る（§1.4） | **`relay` の二重持ちを解消し、退避先が問いになった。** 「移った」は P4 で同じ引数を広げる |
| **P3** ✅ | 貼り直し — 新しい `peer_connect` と `ConnectRelay`、古い側の後始末（§2.2） | **新しいレグが立つ。inner QUIC はまだ使わない**（§4.1） |
| **P4** ✅ | `add_path` と `PathAdded` 待ち、`remove_path`、間隔の下限（§0.3） | **inner QUIC が新しいリレーを使う**（§4.2） |
| **P5** ◐ | 実配備でリレーを再起動して端から端まで | **P3・P4 は設計どおり動いた。そして前提が間違っていた**（§7） |

> **P2 は P3 より前でなければならない。** 初版は逆に並べていた。`PathAdded` は
> `keep_on_the_best_path` の中でしか観測できず、そこに新しいリレーの
> `PathAdded` が届くと `Paths::added` は「リレーではないペア」として **true** を
> 返し、`Step::MoveOnto` → `prefer_path` が走る。つまり **生きている直接経路から、
> 立てたばかりのリレーへ転送を移してしまう** — しかも統計は `direct` と
> ラベルされる。P4 だけを先に出すと、**いまより悪くなる。**

### 4.1 P3 で入ったもの

`InitiatorSession` の持ち物を `Attachment`（`PeerConnection` + `ConnectRelay` +
リース 2 本）に束ね、**その 1 個を所有する supervisor タスク**を置いた。
4 つは connection_id とレグのオリジンで結ばれているので、片方だけ差し替えると
「存在しないものを更新し続ける 2 本のループ」になる。

| | |
| --- | --- |
| 検知 | P1 の `ConnectRelay::ended()`（§3.1 の第一候補）。`RelayLegLease` の `Verdict::LegGone` は `leg` だけを畳んで `ended` は畳まないので、そこからもここへ落ちてくる |
| 順序 | **新しい方が立ってから古い方を retire する。** 初版は逆だった（§5-2 の「枠を食う」を先に取った）が、`closed` を先に報告すると **失効が届かなくなる** — `ended` を畳めるのはリース 2 本の renewal だけで、retire はそれを止める。貼り直しに失敗し続けた場合、直接経路で動き続けるセッションが「制御プレーンからは閉じていて、失効もできない」状態になる |
| 諦めたとき | 古い attachment を**そのまま持ったまま** shutdown を待つ。P1 の状態（フォールバック無しで走り続ける）に戻るだけで、行もリースも生きている |
| 間隔 | 1s から倍々で 30s 上限、8 回で諦める（約 2 分）。加えて **「レグが立ってからの経過」による下限**（§0.3）— 直前のレグが 200ms で落ちたなら残り 4.8s を待つ。経過にはリトライループ自身の待ち時間も含めるので、下限は 1 度しか請求されない |
| 諦めたあと | `error` で 1 度だけ言って終わる。§3.3 の「一本足で走っている」状態が**数えられる**ようになった |
| 失効 | `ended` が畳まれていたら貼り直さない。Endpoint が拒否されているなら新しい connection_id でも拒否される |

**公開フィールドが消えた。** `local_addr` と `connection` は差し替わるので、
`InitiatorSession` のフィールドではなくアクセサになった（`facts` watch を読む）。
`relay_ended()` も「聞いた時点のレグの」トークンを返す — P2 の `path.rs` が
欲しいのは今もこれ（「知っているリレーのペアは消えた」）で、**P4 が要るのは
「新しいペアはここ」を運べる別の信号**である。

**inner QUIC は何も知らない。** 立った新しいレグは、ログに出る以外なにもしない
— **つまり P4 までの間、貼り直しの成功は「何も運ばないリレー割り当てが 1 つ増える」
という意味でもある。** それでも先に出すのは、P4 が「既にあるレグに `add_path`
する」だけの変更になるからである。

**`open_connect_relay` に drop guard を足した。** 貼り直しの試行は shutdown で
キャンセルされるが、`open_connect_relay` は `ready_rx.await` の時点で既にレグを
立てている可能性があり、その future を落としても spawn 済みタスクが持つ
`CancellationToken` のクローンは畳まれない — **誰も止められないレグ、ソケット、
H3 接続がプロセスの寿命だけ残る。** これは P3 が初めてキャンセル点を作ったことで
露出した既存の穴で、両方の leg（bind 側も）で塞いだ。

### 4.2 P4 で入ったもの

P3 の信号を `CancellationToken`（＝消えた）から
**`watch::Receiver<Option<SocketAddr>>`**（`InitiatorSession::relay_leg`）に
広げた。`None` が「消えた」、`Some` が「今はここ」で、1 本の信号で両方を運ぶ。
2 本に分けると、片方が「既に退役したレグについて」答え続けることになる。

| | |
| --- | --- |
| 貼る | `Some(at)` で `add_path(add_path_local(at), at)`。`at` はセッションのループバックアドレス＝**パスの remote** である。local はポート 0（バインディング共有、§2.1）で、ip は remote から取る |
| 待つ | `PathAdded` を `RELAY_PATH_PATIENCE`（10 秒）待つ。来なければ **error で言って `remove_path`**（§0.1.1 の残余リスク）。CID が無いことによる無音は待っても直らない |
| 使えるようになるのは | **`add_path` の時ではなく `PathAdded` の時。** 開いただけのパスはまだ検証されておらず、検証されていないパスは退避先ではない |
| 片付け | 新しい方が検証されてから `remove_path(古いペア)`。multipath では `PATH_ABANDON` を送るだけで枠はその場では空かない（§0.3）。なお `remove_path` は `remove_bound_addr` と違い**接続を殺さない** — abort する分岐は multipath が無いときのものである（`connection.c:8306`〜） |

**`RELAY_PATH_ID` が定数でなくなった。** 貼り直したリレーは msquic が付けた
自分の id を持つパスで、0 番は**死んだ方**である。`direct_path::preference_for`
が 0 を「リレー」として使い続けると、**死んだパスを available に宣言して
生きている方を backup に落とす。** `RelayPath { pair, path_id }` を入れ、
camera 側は `RelayPath::first(relay_path)` を渡す（camera は貼り直さない）。

#### 危険なのは「同じイベントが両方を運ぶ」こと

`PathAdded` は直接経路の到来も、貼り直したリレーの検証完了も、まったく同じ形で
届く。直接経路として読むと **`Step::MoveOnto` → `prefer_path`** が走り、
**生きている直接経路から、立てたばかりのリレーへ転送を移す** — §4 の警告そのもの
である。したがって:

- リレーレグが答えたアドレスは**すべて覚えておく**（`relay_remotes`）。諦めた
  あとに遅れて届いた `PathAdded` も直接経路ではない
- `PathValidated`（id を持たず、先に来る）も同じ判定を通す。ここを抜けると
  猶予タイマが動き、満了で **multipath 以前のスイッチ**がリレーに対して走る
- 検証された時点で `preferred` が居れば、**新しいリレーパスは backup に落とす。**
  msquic は追加したパスを active にするので、放っておくと
  `QuicConnChoosePath` が直接経路とリレーを**ランダムに選ぶ**

#### リレーのパスは「取り上げられる」ようになった

ハンドシェイクのパスは接続ごとしか失われないが、**貼り直したリレーは普通の
パスなので、相手が `PATH_ABANDON` できる。** `PathRemoved` を「使っていない
パス」として読むと、**死んだパスを退避先として提供し続ける** — そこへ退避すると
直接経路を全部 backup に落としたあと、msquic が忘れた id の promote に失敗して
**active なパスが 0 本**になる。`Paths::removed` がリレーのペアを見るように
した。

なお `PathStatusChanged`（相手が backup と宣言）は**別物として扱わない**。
backup のパスは bind も検証も keepalive も生きており、退避先として消えてはいない。
そもそもこの系では listener 側は宣言しない（決めるのは initiator である）。

#### watch は最新値しか持たない

`None` → `Some` が速いと `None` は潰れて `Some` だけが届く。なので `Some` を
受けた時点で**まず `relay_is_gone()` を呼ぶ** — 新しいレグが立ったなら古い方は
死んでいる、というのは見えたかどうかに依らない事実である。待機中だった古い
貼り直しパスも、同じ理由でその場で畳む。

**P5 が残る。** ここまではすべて単体テストと spike であり、実配備でリレーを
再起動して端から端まで見るのは P5 である。

**P1 は単独で価値がある。** いまは「フォールバックが永久に失われた」ことを
誰も知らない。貼り直しが入る前でも、それが**見える**ようになるだけで、
一本足で走っているセッションを運用者が数えられる。

---

## 7. P5 で測った（2026-10-02）、そして残りが直るまで（〜2026-10-05）

実配備。`portal-server` + `portal-client`（どちらも seera-networks /
`org_tAUNRLW8USki2Big`）、リレーは `dp18c7c32424973fa65f0`（minazuki）。
2 秒ごとに転送先（`ssh`）へ TCP を張ってバナーを読むプローブを掛けながら、
リレーを再起動した。直接経路は毎回張れている（`192.168.1.59` 同士、path_id 1）。

### 7.1 P3・P4 は設計どおりに動いた

| | 測った値 |
| --- | --- |
| レグの死を検知するまで | **18 〜 22 秒**（3 回: 22.5 / 18.3 / 18.9 s） |
| 新しいレグが立つまで（P3） | **1.9 秒**（1.93 / 1.89 / 1.96 s） |
| `add_path` → `PathAdded`（P4） | **64 ms**（2 回とも 63〜64 ms） |
| 古いパスの片付け | `remove_path` → `get_path_statistics` から path_id 0 が**消えた**（§0.3 を実機で確認） |

そして **§5 の未確認項目 1・2 に答えが出た。**

```
16:14:33.221  a new relay leg is up   was=conn_PUa743MhF1oo  connection_id=conn_z7qmLPLEP8Yx
16:14:33.221  [server] Unbound { connection_id: "conn_PUa743MhF1oo" }
16:14:33.221  [server] Bound   { connection_id: "conn_z7qmLPLEP8Yx" }
16:14:33.252  [server] a peer is reaching this leg
16:14:33.284  the relay is back on a path of its own, held as backup; the direct path keeps the traffic  path_id=2
```

1. **listener は新しい `connection_id` にレグを貼る。** 古い ID は `Unbound`
   になり、新しい ID が `Bound` になって数十 ms 後にパスが検証された（＝
   往復がレグを通った）
2. **古い接続の `closed` 報告は通る**（`reported the peer connection closed`）
3. **CID の窓には当たらなかった。** `RELAY_PATH_PATIENCE` の満了は 1 度も
   起きていない。§0.1.1 の「数分走った接続なら CID は揃っている」という読みは
   実機で持った

### 7.2 しかし接続は死ぬ。そして**それは貼り直しのせいではない**

3 回とも、貼り直しが成功したあとで peer connection が落ちた。

```
16:14:13  リレー再起動
16:14:33  貼り直し完了（直接経路は 285〜343 µs で健全）
16:14:50  プローブ最後の PASS
16:14:52  the peer connection closed  (QUIC_STATUS_CONNECTION_TIMEOUT)
```

**対照を取った。** リレーを*停めたまま*にして貼り直しが成立しない状態で同じ
ことをすると、接続は **21 秒後**に落ちた — その 1 秒前の直接経路は
`rtt_us=243 min_rtt_us=87 bandwidth=50`、**完全に健全**である。

| | リレーが停まってから接続が落ちるまで |
| --- | --- |
| 再起動（貼り直しが成立） | **39 〜 40 秒** |
| 停止（貼り直し不成立、対照） | **21 秒** |

つまり **P4 は接続の寿命を 18 秒ほど延ばした。救ってはいない。**

### 7.3 機構: 1 本のパスの loss detection が接続ごと殺す（§7.7 で解消）

```c
// loss_detection.c:2049 — QuicLossDetectionOnLossDetectionTimeout
if (OldestPacket != NULL &&
    CxPlatTimeDiff64(OldestPacket->SentTime, TimeNow) >=
        MS_TO_US((uint64_t)Connection->Settings.DisconnectTimeoutMs)) {
    // Assume the path is dead and close the connection.
    QuicConnCloseLocally(Connection, ..., QUIC_STATUS_CONNECTION_TIMEOUT, NULL);
}
```

`QuicLossDetectionGetPathID(LossDetection)->Connection` — **loss detection は
path id ごとにあり、閉じるのは接続である。** つまり **どれか 1 本のパスで
`DisconnectTimeoutMs` の間 ACK されないパケットが outstanding になると、他の
パスがどれほど健全でも接続が閉じる。**

`QUIC_DEFAULT_DISCONNECT_TIMEOUT` は **16000 ms**（`quicdef.h:315`）で、
このワークスペースはどこでも上書きしていない。

観測と合う: `path_id=0 in_flight=2440` が張り付いたまま 16 秒。

### 7.4 したがって P1〜P4 が立っていた前提は間違っている（§7.7 で回復）

P1 と P2 は「**直接経路に移ったセッションは、リレーのレグが死んでも動き続ける
— ただしフォールバックが無いまま**」と書いた。実機ではそうならない。
**リレーパスが ACK を返さなくなってから 16 秒で接続ごと落ちる。**

そして **検知だけで 18 秒かかる。** 予算は 16 秒である。

> **貼り直しの速さは問題ではなかった。** 1.9 秒で立ち、64 ms で貼れている。
> 間に合わないのは**検知**で、しかもレグの死の検知自身が同じ 16 秒クロック
> （レグの QUIC 接続の `DisconnectTimeoutMs`）に乗っているので、
> 「検知してから貼り直す」という形では構造的に勝てない。

手は 3 つある。どれも P5 の範囲外で、測ってから決めるべきものである。

| | |
| --- | --- |
| **死んだパスを早く畳む** | `remove_path` はそのパスの loss detection を止める。レグが死んだと分かった時点で（＝置き換えを待たずに）畳めば、残りのパスは死んだパスの時計から自由になる。**run 2 では実際に畳んでおり、それが 18 秒を稼いだ分である** |
| **検知を速くする** | `RelayLegLease` の `Verdict::LegGone` はリース TTL 以内に分かる。レグ自身に短い keepalive を置く手もある。**16 秒より十分内側に入る必要がある** |
| **`DisconnectTimeoutMs` を上げる / msquic を直す** | 健全なパスがあるのに接続を閉じるのは multipath としては不適切に見える。上流の変更 — **これが採られた**（§7.7） |

> **3 つ目が答えだった（2026-10-05）。** 1 つ目と 2 つ目は P5 の中で入れて
> 効いているが（§7.5.3 で検知 8 秒、4 回連続で生存）、どちらも「16 秒の時計に
> 間に合わせる」ための手で、時計そのものは残っていた。上流が時計の鳴らし方を
> 変えた — **健全なパスが残っているなら、閉じるのは接続ではなくパスである。**
> したがって本節の見出しの「前提は間違っている」は、**この修正より前の話**で
> ある。P1・P2 が書いた「直接経路に移ったセッションはリレーのレグが死んでも
> 動き続ける」は、いま本当になった（§7.7）。

### 7.5 path_id 2 が ACK を受け取らない件 — LTTng で追った

§7.2 の「説明がついていないこと」を LTTng で追った（2026-10-02）。
`QUIC_ENABLE_LOGGING=on`（Linux では既定 `off` なので `build.rs` を一時的に
patch、計測後に revert）、`LD_PRELOAD=libmsquic.lttng.so`、
`lttng enable-event -u 'CLOG_*'` に `vpid`/`procname` コンテキストを付ける。
**両プロセスが同じセッションに入るので、どちらが何をしたかはこれが無いと
区別できない。** 追試 3 回（r1/r2/r3）＋初回（t1）。

#### 分かったこと

| | |
| --- | --- |
| client 側 | `ConnPathInitialized Path[2]` → `ConnPathValidated Path[2]` が **63 ms**。毎回成功している |
| **server 側もパスを生やす** | `ConnPathInitialized Path[3]`。§2.2 の未測定項目 3 が実トラフィックで確認された（spike ではなく） |
| 両方向に通っている | トレースの `DatapathSend`/`DatapathRecv` が **約 62 ms 周期で対になって**最後まで並ぶ。リレー側の `forwarded_bytes` も同じ |
| **それでも ACK が来ない** | client の path_id 2 は `rtt_us` が検証時の 1 サンプルで凍り、`in_flight` が 1220 →2440 のまま接続の最後まで減らない。**1220 は padding 済みの PATH_CHALLENGE 自身である** |

そして死ぬのは §7.3 のとおり `loss_detection.c:2049` である。

#### 見つかった**別のバグ**: リレーが 1 個落とす

4 回のうち 2 回（t1・r2）、リレー側ログにこれが出た。

```
17:…:12.492078  received COMPRESSION_ASSIGN capsule: context id 2, addr Some(127.0.0.1:38955)
17:…:12.492143  registered compressed context id 2        (from_udp_to_quic)
17:…:12.492162  from_quic_to_udp: unknown context id 2    ← 落とした
17:…:12.492167  received RegisterContextID Message … context id 2
17:…:12.492197  sending datagram 1220 bytes for context id 2
```

`from_udp_to_quic` が context を登録して相手に `COMPRESSION_ASSIGN` を返す
一方、`from_quic_to_udp` にはそれが**メッセージ経由で**伝わる。**その 19 µs
の窓に届いたデータグラムは捨てられる。** 貼り直しでは server 側 msquic が
新しい送信元を見た直後に 2 発まとめて返すので、この窓に当たりやすい。

落ちたのが **server 自身の PATH_CHALLENGE** だった場合、msquic は
**challenge を再送しない**ので 3 PTO 後に
`ConnPathValidationTimeout` → server はそのパスを捨てる。すると
`QuicSendWritePathAckFrames`（`send.c:286`）は **`Connection->Paths[]` を
回して各パスの path id の ACK を書く**実装なので、**path id 2 のパスが
無くなった server は path id 2 の ACK を永久に書けない。** t1・r2 の
「ACK が来ない」はこれで説明がつく。

#### しかし r3 がその答えを拒否する

**r3 ではリレーは何も落とさず、server の `Path[3]` は 63 ms で検証を通り、
最後まで消えていない。** それでも client の path_id 2 は
`in_flight=2440` のまま ACK を 1 つも受け取らず、接続は 22 秒後に落ちた。

> **つまり「ACK が来ない」には 2 つ目の原因がある。** リレーの取りこぼしは
> 実在するバグだが、死因そのものではない。**1 回の観測で満足していたら
> そう結論していた** — §0.1.1 で 3 回間違えたのと同じ形である。

**次に手を付けるのはここである。** 推測ではなく、server 側で path id 2 の
ack tracker が何をしているかを計測する（`QuicAckTrackerAckFrameEncode` が
path id 2 に対して呼ばれているか）。backup と宣言したパスの扱いが絡んで
いる可能性はあるが、**`QuicSendPathResponses` は IsActive を見ない**ことは
確認済みなので、そこではない。

### 7.5.1 ack tracker を計測した — そして ack tracker は無罪だった

`QuicAckTrackerAckPacket` / `QuicAckTrackerAckFrameEncode` /
`QuicSendWritePathAckFrames` に `fprintf(stderr, "[AT] …")` を 3 本入れて
（multipath の接続だけ、毎秒数行なので §0.1.1 の「stdout backend は時間を
変える」には当たらない）、path id ごとに「mark したか」「encode したか」
「writer が何を見たか」を取った。計測後に revert 済み。

| | path id 0 | path id 1（直接経路） | **path id 2（貼り直し）** |
| --- | --- | --- | --- |
| server が mark した数 | 8 | 25 | **2** |
| server が encode した数 | 5 | 16 | **2** |
| client が mark した数 | 10 | 25 | 7 |
| client が encode した数 | 7 | 19 | 6 |

**ack tracker は正しく動いている。** server は path id 2 で受け取った 2 個を
2 個とも mark して ACK を書いており、client も server の path-2 パケット
（pn 216〜222）を ack している。

**問題は届いていないことだった。** 貼り直し後の 40 秒間に server の msquic が
受け取ったデータグラムは **10 個**で、リレーが server 方向へ転送した数も
**ちょうど 10 個**だった（`ctx0 -> 127.0.0.1:30038` の内訳を数えた）。
**リレーもレグも 1 個も落としていない。**

#### 落としていたのは server 自身の binding である

client が path id 2 に送った 1220 バイトのパケットは 3 つ
（pn=180・182・184）。pn=180 は PATH_CHALLENGE で、**これだけが接続に
マッチした。** 残りの 2 つは **10 秒間隔**で、msquic の
**path keepalive**（backup パスを生かすための padding 済み PING）である。
その 2 つはこうなっていた。

```
17:22:59.912  PacketTxStatelessReset   (token f6491fb4…)
17:22:59.937  BindingDropPacket  src=127.0.0.1:54538  Reason=Already in stateless oper table
17:23:09.939  PacketTxStatelessReset
17:23:10.028  BindingDropPacket  src=127.0.0.1:54538  Reason=Already in stateless oper table
```

`BindingDropPacket` は**接続にマッチしなかった**パケットである。
つまり **server は、client が貼り直したパスで使っている destination CID を
知らない**ので、stateless reset を返している。client はそのトークンが合わない
ので無視し、keepalive を投げ続け、16 秒後に §7.3 が接続を閉じる。

**その CID は server が発行したものである。** client の `FirstCidUsage` は
path 2 で `5125eae4f344ce6456` — 直接経路の `512541c72083e2836a` と同じ
`5125` プレフィックス、すなわち server 自身の CID である。
**発行して相手に広告した CID を、binding が解決できない。**

#### 対照: 古いパスを畳むのは何に効いているのか

同じ時間帯で A/B を取った（`RELAY_REPATH_KEEP_OLD_PATH=1` で
`drop_the_path` を飛ばす実験パッチ、計測後 revert）。

| | リレー停止から接続が落ちるまで |
| --- | --- |
| **A. 置き換えが検証されたら古いパスを畳む**（現状） | **40 秒** |
| **B. 畳まない** | **20 秒** — 貼り直しを始めた **0.2 秒後**に落ちた |

B は**古いパス自身の 16 秒**で落ちている（リレーが落ちた時刻 + 16 秒に
一致）。**畳むことは必要で、約 20 秒を稼いでいる。** そして B は新しいパスが
立つ前に死ぬので、**CID の件の原因が「畳んだこと」かどうかは B では判定
できない**（§7.4 のとおり、検知 18 秒と予算 16 秒が同じ時計に乗っている）。

#### 残る 1 つは上流にある

**seera-msquic の multipath CID 管理である。** `Connected` の時点で
`QuicPathIDSetGenerateNewSourceCids` が追加 path id 用の source CID を作って
相手に広告するが、**相手が後から `add_path` したパスでそれを使うと、
binding がそれを解決できない。** portal 側でもリレー側でもない。

> **ここでも 1 回で結論しなかったのが効いた。** 「backup にしたから
> PATH_RESPONSE が返らない」も「ack tracker が path id 2 を飛ばす」も、
> 測って潰した仮説である（前者は `QuicSendPathResponses` が `IsActive` を
> 見ないことを読んで、後者はこの節の計測で）。

### 7.5.2 原因を特定した: 1 本の path id を畳むと**全部**の CID が消える

`pathid_set.c:303`、`QuicPathIDSetTryFreePathID`（path id 1 本の後始末）:

```c
if (!Path->UseBound) {
    QuicBindingRemoveAllSourceConnectionIDs(Path->Binding, Connection);
}
```

そして `QuicBindingRemoveAllSourceConnectionIDs`（`binding.c:637`）は

```c
QuicPathIDSetGetPathIDs(&Connection->PathIDs, PathIDs, &PathIDCount);
for (uint8_t i = 0; i < PathIDCount; i++) {        // ← この接続の **全** path id
    for (… PathIDs[i]->SourceCids …) { … HashEntry->Binding == Binding → 削除 … }
```

**1 本を畳んでいるのに、その binding に登録されている*すべての* path id の
source CID を消す。** そして **server では全パスが listener の binding を
共有している。** だから古いリレーパス（path id 0）を畳んだ瞬間に、
**生きている path id 1〜3 の CID も listener の binding から消える。**

以降、client が path id 2 の CID で送ったパケットは接続にマッチせず、
`BindingDropPacket` → `PacketTxStatelessReset`（§7.5.1 の測定どおり）。

**しかも直後の `QuicPathIDFreeSourceCids(PathID)`（`pathid.c:153`）が
「畳む path id の CID だけを、登録されている全 binding から消す」という
正しい範囲の処理をすでにしている。** つまり上の `RemoveAll` は
**畳む path id については冗長で、他の path id については破壊的**である。

#### 直して測った

`RemoveAll` の呼び出しを「この path id の CID だけをこの binding から外す」
に狭めて（`QuicPathIDFreeSourceCids` の内側のループと同じ形）、実配備で
リレーを再起動した。**ただし §7.4 の予算（16 秒）が先に切れて貼り直しが
間に合わないので、測定のために両端の `DisconnectTimeoutMs` を 60 秒に
上げた**（これも実験で、revert 済み）。

| | path id 2 の様子 | 接続 |
| --- | --- | --- |
| **CID を狭めた + 予算 60s** | `in_flight=0`、`rtt_us` が **31181 → 31161 → 31046** と更新され続ける | **リレー再起動を越えて生き残った。** プローブが 2 分 26 秒、1 度も落ちずに PASS |
| **対照: 予算 60s だけ**（CID はそのまま） | `rtt_us` が検証時の 32690 で**凍結**、`in_flight` が 1259 → 7941 と単調増加 | **ちょうど 60 秒後**に落ちた（同じ機構が後ろへずれただけ） |

**対照が結論を出している。** 予算を上げるのは死を遅らせるだけで、
**貼り直したパスが実際に使えるようになるのは CID の修正である。**

> **これが P5 で初めて「リレー再起動を越えてセッションが生き残った」記録で
> ある。**

#### 修正は seera-msquic 側に作った

`seera-networks/msquic` の `masa-koz/pathid-cid-scope`、
`b9002f44` *Retire one path ID's source CIDs, not every path ID's*。
`QuicPathIDFreeSourceCids(PathID)` を `QuicLibraryReleaseBinding` の**前**へ
移し、広い呼び出しを削った。狭い複製を書くのではなく移動にしたのは、
**それがすでに正しい範囲の処理だから**である。移動は必須で、装飾ではない:
CID のハッシュエントリは自分の binding ポインタを持っており、
binding の最後の参照が解放されたあとではそれが freed を指す。

`pathid.c` の `QuicPathIDCheckDestCids` に**同じ広さの削除がもう 1 つある。**
そこは直さずコメントだけ入れた — パスは消えるが path id は残るので、
欲しい条件は「この binding を他のパス/bound address が使っていないか」であり、
**その分岐（非アクティブなパスが destination CID を切らす）の再現手段が無い。**

#### 5 回走らせて、3 つの欠陥が独立に効いていることが分かった

| 走行 | リレーの取りこぼし | 貼り直し完走 | 生存 |
| --- | --- | --- | --- |
| fix3 | なし | ✅ | **✅ 2 分 26 秒、プローブ 0 失敗** |
| ctl3（対照・CID 未修正） | なし | ✅ | ❌ **ちょうど 60 秒**で落ちた |
| ver1 | **あり** | ✅ | ❌ |
| ver2 | **あり** | ❌（検知レースに負けた） | ❌ |
| ver3 | なし | ✅ | **✅ プローブ 0 失敗** |

**CID 修正があって、かつリレーが取りこぼさず、かつ検知が予算に間に合った
回は、すべて生き残った。** 落ちた回はそれぞれ §7.6 の別の欠陥で説明がつく。
3 つは独立である。

### 7.5.3 検知を 8 秒にした — レグ自身の keepalive と disconnect timeout

**検知が 18〜26 秒かかっていた理由は算術だった。** レグの QUIC 接続は
`make_client_config` の設定を使っており、`KeepAliveIntervalMs` 10 秒 +
`DisconnectTimeoutMs` 既定 16 秒。**レグが自分の死に気づくのは
「ping が出る + その ping が ACK されないまま待つ」ので 10 + 16 = 26 秒**
である。観測値 18〜26 秒はそのままこれだった。

`Liveness::{ControlPlane, RelayLeg}` を `make_client_config` に足し、
**レグだけ** keepalive 2 秒 / disconnect timeout 6 秒にした
（`isekai-p2p-core/src/transport.rs`）。制御プレーンは据え置き — 瞬断で
リクエストを落としたくない。

> **keepalive だけでは足りない。** それが修正の全体のように見えるので書いて
> おく: 1 秒の ping でも 1 + 16 = 17 秒で、予算 16 に入らない。
> **ping は時計が「いつ始まるか」を決め、disconnect timeout は
> 「いつ終わるか」を決める。** 両方要る。

| | 検知 |
| --- | --- |
| 変更前（10 s + 16 s） | **18 〜 26 秒**（予算 16 秒に負ける） |
| 変更後（2 s + 6 s） | **7.6 〜 9.5 秒**（7 回の実測） |

**代償は敏感さで、しかも対称ではない。** レビューが指摘した点である。

initiator の connect leg では小さい — 6 秒の瞬断でレグが死ぬが、それが
許容できるのは**レグを失うのがもう恒久的でないから**で（約 2 秒で立て直り、
`reattach_delay` の `REATTACH_MIN_INTERVAL` 下限がフラップを `peer_connect`
の連打に変えない、§0.3）。P3 より前にこの数字を入れるのは無謀だった。

**しかし listener の bind leg も同じ数字になり、そこには立て直しが無い。**
listener はレグが死んだ接続を `spent` に入れて二度と bind せず、initiator
からは見えない（自分のレグは健全なので置き換えを頼まない）。結果として
peer connection のリレーパスが ACK されなくなり、接続ごと落ちる。
**これは変更前からそうで、変更後は「より短い瞬断で」そうなる** —
listener 側の瞬断が約 25 秒必要だったところが約 8 秒になった。

それでも入れているのは、**これが無いと貼り直しが成立しない**からである。
initiator は約 10 秒で置き換えパスを開くので、listener はその時点で生きた
レグを持っていなければならない（proxy が新しい接続を bind する先がない）。
26 秒かけて気づく listener は、`RELAY_PATH_PATIENCE` が切れる頃まだ死んだ
レグの上にいる。**露出は意図的であり、それを消すのは
「listener が、接続がまだ claim されている間にレグが死んだ接続を bind し直す」
こと**（§0.2 B。そこで却下した理由の一部は、この計測が答えている）。

**公開アドレスは据え置きにした。** `isekai_p2p::public` には renewal も
health check も意図的に無く、events チャネルが閉じるとループを抜けて終わる
だけで、何も記録せず何も開き直さない。レグの短気さを与えると数秒の瞬断で
公開リスナーが静かに終わり、解決はするが何も答えないアドレスが残る。
`Liveness::PublicAddress` はそのための分岐である。

**ハンドシェイクも短くなる。** `DisconnectTimeoutMs` はハンドシェイク完了を
条件にしていない（loss detection のタイマは「未 ACK のパケットがあるか」しか
見ない）ので、レグのハンドシェイク予算は `HandshakeIdleTimeoutMs` の既定
10 秒ではなく **6 秒**になる。1 往復＋再送なら通常の経路では収まるが、
極端に遅い・損失の多い経路では収まらないことがあり、そこは置き換えの 8 回の
試行が受け持つ。

#### そして 3 つの欠陥が実機で分離した

検知だけ速くして（msquic 修正・リレー修正なし）3 回:

| | 検知 | 貼り直し | 生存 | リレー取りこぼし |
| --- | --- | --- | --- | --- |
| d1 | 8.1 s | ✅ | **✅ プローブ 0 失敗** | なし |
| d2 | 8.0 s | ❌ `RELAY_PATH_PATIENCE` 満了 | ❌ | **2 回（19:14:03）** |
| d3 | 8.0 s | ✅ | **✅ プローブ 0 失敗** | なし |

**その時間帯のリレー取りこぼしは d2 のウィンドウにしか無い。** 落ちた 1 回は
§7.5.1 のリレーのバグで完全に説明がつく。

#### 両方入れて 4 回連続で生き残った

リレー修正（link-server#284）と検知の修正を両方入れて 4 回:

| | 検知 | 貼り直し | 接続が死んだか | プローブ失敗 |
| --- | --- | --- | --- | --- |
| c1 | 8.1 s | ✅ | **なし** | **0** |
| c2 | 9.5 s | ✅ | **なし** | **0** |
| c3 | 7.6 s | ✅ | **なし** | **0** |
| c4 | 7.6 s | ✅ | **なし** | **0** |

**4 回すべて、転送ポートはリレー再起動を通して 1 度も落ちなかった。**
これが P5 の目標である。

> **msquic の CID 修正は入っていない。** 検知が速いと貼り直しが
> server の path id 0 退役より先に終わるので、§7.5.2 のバグに当たらなく
> なるらしい。**4 回での観測であり、CID のバグが消えたわけではない** —
> 予算を人為的に 60 秒に延ばすと確実に噛む（§7.5.2 の対照）。
> msquic#108 は依然として正しい修正である。

### 7.6 したがって直すべきものは 4 つある（4 つとも入った）

| | どこ | |
| --- | --- | --- |
| 1 | **msquic** ✅ | `QuicPathIDSetTryFreePathID` が 1 本の path id を畳むときに、その binding の**全** path id の source CID を消す（§7.5.2）。seera-msquic#109 で狭めて解消。**ただしその狭め方が退行を残した** — 広い呼び出しは「他のどのパスもその binding を持たないとき」には依然必要で、#111 の前提コミットが条件付きで戻している（§7.7） |
| 2 | **リレー**（`axum_masque`） ✅ | context 登録の競合で 1 個落とす。貼り直しに限らず、新しい送信元の最初のデータグラムが落ちうる。link-server#284 で解消 |
| 3 | **msquic** ✅ | 健全なパスがあるのに 1 本の loss detection で接続を閉じる（`loss_detection.c:2049`）。seera-msquic#111 で解消し、本書では #262 で取り込んだ（§7.7）。**challenge を再送しない方は直っていない** — が、パスが明示的に放棄されるようになったので、残っても接続を落とさない |
| 4 | **本書の前提** ✅ | §7.4 の「検知 18 秒 vs 予算 16 秒」は §7.5.3 で解消（8 秒）。§1.3・§7.4・§7.3 の記述は §7.7 に合わせた |

**どれも P4 の中の間違いではない。** P3・P4 は設計どおり動いており
（§7.1）、足りないのはその下の層である。

### 7.7 死んだパスは接続ごと殺さなくなった（2026-10-05）

**見つけたのはリレー再起動ではない。** ssh を転送してログインしたまま放置すると
inner QUIC が切れる、という別口の報告から入った。2 回とも
`QUIC_STATUS_CONNECTION_TIMEOUT` で、**27.6 秒**と**53.2 秒**。どちらもリレーは
死の瞬間まで両方向にデータグラムを運んでおり（リレー側のログで確認）、レグ自身の
統計も増え続けていた。**つまり外では何も壊れていない。**

client の per-path 統計がそのまま機構を名指しした。

| | path id 0（リレー） | path id 1（直接経路） |
| --- | --- | --- |
| +0.0 s | `in_flight=1467` | 在る。`rtt_us=333000`、**`min_rtt_us=0`** |
| +1.0 s | `in_flight=0` | **`in_flight=1220`** |
| +3.0 s | `in_flight=0` | **`in_flight=1220`** |
| +4.0 s | `in_flight=0` | **`get_path_statistics` から消える** |
| … +53 s | 毎秒 `in_flight=0` | — |

`min_rtt_us=0` は **RTT 標本を一度も取れていないパス**、つまり探査されて一度も
答えが返らなかった直接経路である。これがパス MTU までパディングされた
`PATH_CHALLENGE` を抱え、`QuicConnPathValidationTimeout` が数秒後に**パスだけ**を
外して **path id を残した**。送る先も ACK される見込みも無いパケットが
`SentPackets` に居残り、`loss_detection.c` のヒューズ（`QUIC_STATUS_CONNECTION_TIMEOUT`
の発生箇所は msquic 全体で 1 箇所）がそれを見て接続を閉じる。パスが外れてから
死ぬまで、path id 0 は毎秒 `in_flight=0`、接続は `send_lost=0` — **未 ACK
パケットを持っていたのは消えた path id だけ**である。

**16 秒ぴったりにならない理由も同じところにある。** `QUIC_CONN_TIMER_LOSS_DETECTION`
は検出が path id ごとなのに**接続に 1 本しかない**共有タイマーで、各 path id の
更新がそれを上書きする。孤児になった path id の期限は「そのタイマーが次に
その path id へ配られたとき」にしか評価されない。だから 27 秒と 53 秒だった。

> **最初の仮説は path keepalive で、それは外れだった。** 書いておくのは、
> §7.5.3 で keepalive を触った直後であり、`QuicSendPathKeepAlives` が
> 「そのパスが実際に運んでいるか」を**問わずに** ack-eliciting な PING を送るのが
> いかにもヒューズに見えるからである。`GotValidPacket` で門を付けて対照を取ると
> **何も変わらなかった** — 検証タイムアウトが、最初の keepalive が出る前に
> そのパスを片付けてしまうからで、残るのは challenge の方である。
> **機構を読んだだけで時刻が合ったことを根拠にしてはいけない**（§0.1.1）。

**上流の修正は seera-msquic#111（`f88d4b7`）。** multipath で、かつ送信側が実際に
選ぶパスが他に在るなら、接続を閉じる代わりに **path id を放棄して相手に伝える**。
あわせて `QuicConnPathValidationTimeout` も黙ってパスを落とすのをやめ、
`draft-ietf-quic-multipath-21` §3.1 の「the endpoint MUST explicitly close the
path」どおり明示的に閉じるようになった。本書では **#262 でサブモジュールごと
取り込み**、**放置した ssh セッションが 5 分以上保つ**ことを実機で確認した —
27 秒と 53 秒で死んでいたものである。

本書への帰結が 3 つある。

| | |
| --- | --- |
| **§7.4 の前提が回復した** | 「直接経路に乗ったセッションはリレーのレグが死んでも動き続ける」は本当になった。`Paths::removed` が `Removed::TheRelay` を返す経路（P4 のレビュー修正）と、initiator のレグ watch による貼り直しは**既に揃っており**、#262 はそれを初めて到達可能にした |
| **`PathRemoved` が 1 本につき複数回来る** | 1 回の放棄で 3 回観測した。#111 は「相手発の流れでは以前からそうだった」と記録している（放棄で 1 回、その ACK で 1 回）。`Paths::removed` は冪等 — 集合からの削除と、2 回目以降は `preferred` が一致しない — なので**デバッグログが 3 行出るだけ**である。per-path の状態を解放する処理をここに足すなら、先にこれを思い出すこと |
| **§0.2 B は変わっていない** | listener が「レグは死んだが inner QUIC は生きている」を知らないのは依然そのままで、直ったのは client 側の寿命だけである |

**回帰テストは `multipath_spike` の質問 7 に入れた。** 束ねられて一度も読まれない
UDP ソケット宛にパスを開き（データグラムは届くので ICMP で早期に畳まれず、
答えも永久に来ない）、90 秒見る。**生存だけを見ても検査にならない** — 修正前の
ループバックでも通る。孤児になった path id の期限が評価されるかは共有タイマーの
配り方次第で、ループバックでは当たらないからである（30 秒窓・90 秒窓のどちらも
通ったのに、現場は 53 秒で死んでいた）。だから質問 7 は **msquic が「そのパスを
諦めた」と言うこと**も要求する。そこが動いた部分で、修正前は `PathRemoved` が
一度も来ない。

### 7.8 4 枠は同時数ではなく、失敗したパスの分だけ減る（2026-10-05）

§0.3 は「`remove_path` は即座には空けない」と書いた。**空かない。** §5-8 を
`multipath_spike` の質問 8 で測った結果である。

| 測ったこと | 結果 |
| --- | --- |
| 質問 7 が開く前 → msquic が放棄した後のパス数 | **2 → 3** |
| `remove_path(0.0.0.0:0, remote)`、パスが**在るうち** | **受理される** |
| その後パス数が戻るか（10 秒、別の回で 20 秒） | **戻らない**（3 → 4 のまま） |
| 4 に達した後の `add_path` | **`QUIC_STATUS_OUT_OF_MEMORY`**、待っても回復しない |
| `remove_path`、パスが**無い**とき | `QUIC_STATUS_NOT_FOUND` |

**放棄は path id を畳むが、`Connection->Paths` の枠は返さない。**
`PATH_ABANDON` を送り `PathRemoved` を 3 回出したパスが、`get_path_statistics`
に依然として並ぶ。数え方は上限と同じものを見ている —
`QuicConnGetPathStatistics` は `Connection->Paths` を走査して
`InUse && PathID != NULL` を数え（`connection.c:9817`）、`add_path` の拒否は
`PathsCount == QUIC_MAX_PATH_COUNT`（`connection.c:7975`）である。枠が実際に
戻るのは path id が解放されるときで、`QuicPathRemove` はそこから呼ばれる
（`pathid_set.c:324`、`QuicPathIDSetTryFreePathID`）。

**記録していた `NOT_FOUND` は、別のことを言っていた。** ワイルドカードの
ハンドルは壊れていない — 在るパスには届き、受理される。`NOT_FOUND` が返るのは
そのパスがもう無いときで、**掃除できなかった証拠ではなく、掃除された（または
そもそも `add_path` が通っていない）証拠**である。P4 のコメントが心配していた
「忍耐切れのパスが枠を占める」は当たっていたが、理由は `remove_path` の失敗では
なく、**成功しても枠が戻らないこと**だった。

**検証されたパスかどうかで分かれる。そしてその片方はまだ揃っていない。**
§5-8 として残していた判別を `path_stats_wedge.rs` のプローブ 2・3 で測った
（どちらも、他に何もしていない接続の先頭で、60 秒窓）。

| | 3 回の実行 |
| --- | --- |
| **一度も検証されないパス**（msquic が自分で放棄する） | **60 秒で戻らない、3/3** |
| **検証されたパス**を `remove_path` で外す | **ばらつく** — 251 ms で戻った回と 60 秒戻らなかった回が各 1、残り 1 回は前段のエラーで未実行 |

**揃っているのは上の行だけである。** 下の行は、別の並び（wedge のプローブを
通した後）では 3/3 で 251 ms だった。

> **何に依存するのかは §7.10 で分かった: 相互放棄である。** 枠を開けるのは
> `QuicPathRemove` で、そこへ至る `QuicPathIDSetTryFreePathID` は
> `Abandoned && Closed` を要求し、`Abandoned` は「自分の放棄が ACK された」
> **かつ**「相手も放棄を送ってきた」でしか立たない。一度も検証されないパスは
> 相手側に `QUIC_PATH` が無いので相手が放棄を無視し、永久に立たない。

> **本節の結論は、これで 3 回書き直している。** 初版は「忍耐切れのパスが枠を
> 占める」、2 版は「検証に成功しても返らない」、いまは「分かれるが片方は未確定」
> である。**毎回、1 回の実行で結論を出したのが原因だった** — 15 秒窓で
> 「返らない」と書いた直後に、同じバイナリの次の実行が返すのを見た。§0.1.1 の
> 規律は自分にも適用する。
>
> 2 版で持ち出した「P5 と矛盾する」も**読み違いだった**。§7.5.3 の c1〜c4 は
> 4 回の別々の試行で、各試行はリレー再起動 1 回 — 追加したパスは 1 本なので、
> 上限には近づいていない。矛盾は無かった。

**貼り直しへの帰結。** リレーパス 1 + 直接経路 1 で 2 を使い、
**検証されない `add_path` 1 回が 1 枠を恒久的に取る**。だから
`REATTACH_ATTEMPTS` が 8 でも、**レグが立って貼り直しに失敗する**のは 2 回まで
で、3 回目は `add_path` 自体が `QUIC_STATUS_OUT_OF_MEMORY` になる（§3.3）。
**成功した貼り直しは枠を返す** — 相手にパスがあり放棄を返すからである
（§7.10）。したがって天井は「失敗 2 回」であって「開通 2 回」ではない。
**そしてその 2 回も、#119 が検証されないパスの枠まで返すようになって当たらなく
なった**（§7.11 で 3 回の再起動を実測）。

**P5 がこれに当たらなかったのは、試行ごとに再起動が 1 回だったからである。**
1 本のセッションでリレーが 3 回落ちる状況は測っていない。

> **質問 8 の中では測れず、切り出して測った。** 検証済みパスの削除を質問 8 に
> 置くと 2 回 wedge し（§7.9）、末尾へ移すと今度は非同期の削除を待たずに数を
> 読んでいて何も言えなかった。**測れていない段を残すより消す**方を採り、
> `path_stats_wedge.rs` という別の例でやり直した。そちらは
> **ブロッキング呼び出しを 1 本ずつ別スレッドに出して期限付きで待つ**ので、
> wedge がハングではなく 1 行の結果になる。
>
> **質問 8 は assert ではなく報告にした。** 最初の版は `add_path` に `?` を
> 付けていて、最初の `OUT_OF_MEMORY` で止まり「なぜ」を何も言わなかった。
> **拒否は測定結果であって失敗ではない。** いま落ちるのは接続自体が壊れたとき
> だけである。測りかけて何も言えなかった手順（検証済みパスの削除）は、
> 残すと誤読されるので**消した** — 測っていない段を残すより無い方が良い。

### 7.9 wedge を切り出した — そして再現しなかった（2026-10-05）

質問 8 の中で `get_path_statistics` が 2 回続けて返らなくなった件
（§7.8 の末尾）を、`camera-core/examples/path_stats_wedge.rs` として切り出した。

**この呼び出しは msquic のワーカーに操作を積んで、返るまで呼び出しスレッドを
止める。** だから wedge は普通に書くとランタイムごと巻き込む。ここでは
**ブロッキング呼び出しを 1 本ずつ別スレッドに出し、チャネルを期限付きで待つ。**
止まったスレッドは止まったままだが、プロセスは「止まった」と言って次へ進める
— これが `gdb` でできないことである: `ptrace_scope` が 1 なので、後から兄弟
プロセスにアタッチできない。

各プローブは `get_path_statistics` を 3 回続けて呼ぶ（wedge は最初の呼び出しでは
起きなかったので、1 回では足りない）。

| # | 直前にしたこと | 結果 |
| --- | --- | --- |
| 1 | 何もしない（静かな接続） | 3 回とも 50〜80 µs |
| 4 | Pending の `poll_event` を timeout でキャンセル | 3 回とも 30 µs 前後 |
| 5 | 見捨てられるパスを開き、イベントを読み切る | 3 回とも 100 µs 前後 |
| 6 | 同じく、ただしイベントを**読まない** | 3 回とも 100〜150 µs |
| 7 | **2 本の接続**を `select!` + `timeout` で 10 秒回す（質問 7 の形） | 3 回とも 90〜180 µs |

（2 と 3 は wedge のプローブではなく、§7.8 の枠の計測である。枠は先に測る —
下のプローブはパスを置き去りにするので。）

**どれも再現しなかった。** `remove_path` も検証済みパスに対して 69〜97 µs で
受理されている。したがって原因は、キャンセルされた `poll_event` そのものでも、
未読のイベントでも、2 本の接続を `select!` で回すことでも、パスの削除でもない。
残る差は質問 8 がその前に通っていたもの — 60 秒の無音窓（質問 5）、90 秒の窓
（質問 7）、リレーブリッジと 2 本のレグ接続、`set_path_status` — のどれかか、
その組み合わせである。

**分かったのは「何ではないか」だけで、それは書き残す価値がある。** とくに
`portal_core::path` が同じ 2 つの呼び出しを 1 つのループから行っていることへの
懸念 — tick 腕が勝つと半分ポーリングした `poll_event` が落ち、そのまま
ブロッキング呼び出しに入る — は、プローブ 2 と 5 が**そのままの形で否定して
いる**。出荷側のループがこの理由で止まることはない。

この例はそのまま残す。再び wedge を見たときに、まず走らせるものがあるという
ことである。

### 7.10 枠が開く条件は「相互放棄」だった — LTTng で確定（2026-10-05）

§7.8 で「検証済みパスは枠を返す回と返さない回がある」まで測って止めていた。
**枠を開けるのは `QuicPathRemove` であり、それが呼ばれたかどうかは
`ConnPathRemoved`（`"[conn][%p] Path[%hhu] Removed"`、`path.c:82`）が出るかで
直接分かる。** `path_stats_wedge` を LTTng 下で 1 回走らせ、見捨てられたパスと
検証済みパスの両方が同じトレースに入った（前者は 60 秒戻らず、後者は 252 ms で
戻った）。

| 時刻 | 事象 |
| --- | --- |
| 40.691636 | `ConnPathValidationTimeout` path 1 — 見捨てられたパス |
| 40.691653 | `IndicatePathRemoved`、`ConnSetTimer` 5 = **PATH_CLOSE** |
| 40.691726 | PATH_ABANDON **送信** |
| **43.767523** | `ConnPathIDCloseTimerExpired` — **その後、何も続かない** |
| 42.816227 | `ConnPathIDCloseTimerExpired`（検証済みパス） |
| 42.816230 | → `ConnPathIDRemove` → `BindingCleanup` → **`ConnPathRemoved`** |

**両方とも close タイマーは発火している。** 違いはその先の
`QuicPathIDSetTryFreePathID` で、最初の 2 行がすべてを決めている。

```c
if (!PathID->Flags.Abandoned || !PathID->Flags.Closed) {
    return;
}
```

`Closed` は close タイマーが立てた。したがって偽だったのは **`Abandoned`** で、
これが立つ箇所は 2 つしかなく、**どちらも相互放棄を要求する**:

| | 条件 |
| --- | --- |
| `connection.c:5625`（相手の PATH_ABANDON を受けたとき） | **自分の放棄が既に ACK されている**なら立てる |
| `loss_detection.c:671`（自分の PATH_ABANDON が ACK されたとき） | **相手が既に閉じている**なら立てる |

つまり「自分が放棄して ACK された」**かつ**「相手も放棄を送ってきた」の両方が
要る。フレームの向きを数えると、そこが分かれている:

| | client TX | server RX | **server TX** | client RX |
| --- | :---: | :---: | :---: | :---: |
| 見捨てられたパス | 2 | 2 | **0** | 0 |
| 検証済みパス | 2 | 2 | **2** | 2 |

**相手は見捨てられたパスの放棄に返事をしない。** 理由は受信側の早期 return で
ある（`connection.c:5610`）:

```c
if (PathID->Path == NULL) {
    // The peer referenced a path id whose QUIC_PATH is not (yet) bound ...
    // Ignore the frame.
```

**一度も検証されないパスは、相手側に `QUIC_PATH` が束ねられていない** — その
パスでは何も届いていないのだから当然である。だから相手は PATH_ABANDON を
無視し、`RemoteClose` を立てず、自分の放棄も送らない。こちらの `Abandoned` は
永久に false、`QuicPathIDSetTryFreePathID` は毎回 early return、
`QuicPathRemove` は呼ばれず、**枠は接続が終わるまで戻らない。**

**これはバグである。** `draft-ietf-quic-multipath-21` §3.4 は path **ID** の
再利用を禁じているが、`Connection->Paths` の**枠**は別物で、相手が知りもしない
パスのために 4 枠のうち 1 つを恒久的に失う理由は無い。直し方は 2 通り考えられ、
どちらも上流の判断である。

| | |
| --- | --- |
| **送り手側** | 自分の放棄が ACK されたなら、相手の放棄を待たずに解放する（`loss_detection.c:671` の `RemoteClose` 条件を外す／緩める）。相手が知らないパスに相手の同意を待つのは筋が通らない |
| **受け手側** | `PathID->Path == NULL` でも `RemoteClose` を立てて放棄を返す。早期 return のコメントは「まだ束ねられていない」場合を想定しており、「ついに束ねられない」場合を想定していない |

**§7.8 の下の行への答えでもある。** 検証済みパスが枠を返したのは、相手に
`QUIC_PATH` があり放棄を返したからである。返らなかった回を直接トレースして
いないので、「相手側のパスが既に無くなっていれば返らない」は**この機構からの
予測であって測定ではない**。

#### 直した（seera-networks/msquic#119）

受け手側を直す案を採った — **`PathID->Path == NULL` でも放棄を返す。**
そのために 3 つ必要で、#119 はこの 3 つをそのまま保っている。

| | |
| --- | --- |
| `SendAbandon` を `QUIC_PATH` → `QUIC_PATHID` へ | パスを持たない path id こそが放棄を運ぶ側で、パス上には記録場所が無い |
| `send.c` を `Connection->Paths` ではなく **path ID 集合の走査**に | パスを持たない path id はその配列に居ないので、放棄を持っているか訊かれてすらいなかった。既存の `QuicPathIDSetWriteNewConnectionIDFrame` と同じ型に揃えた |
| `QuicPathIDSetTryFreePathID` がパス無しを許容 | binding 解放と `QuicPathRemove` を飛ばし、`QuicPathIDFreeSourceCids` は無条件に実行（全 path id の CID が全 binding に載っているため） |

> **ここは本書が最初に書いた版（#118）とは違う。** #118 はこの作業から出した
> もので、クローズされて #119 が採られた。**訂正されたのは解放の時機である。**
> #118 は「パスが無いのだから 3 PTO の close タイマーが守る対象は無い」として
> 返答が ACK された時点で即解放したが、`draft-ietf-quic-multipath-21` §3.4 の
> その窓は**相手に発行済みの connection ID と番号空間**のためにある。パスを
> 持たない path id も `PATH_NEW_CONNECTION_ID` で CID を配っており番号空間も
> 持つので、窓は等しく適用される — 認識されない遅延パケットは Stateless Reset
> を誘発する。#119 は close タイマーに解放を任せ、draft が数える「受信から
> 3 PTO」の位置でそれを張る。
>
> **#118 が足した `loss_detection.c` の 2 つのガードは落とされた。** #117 が
> ack ハンドラをパス参照の引き直しと、内側条件の外での release に組み替えて
> いたため不要になり、#118 の 2 コミット目が部分的にそのために存在していた
> 参照リークも同時に消えた。#119 のレビューはさらに、close タイマーの飢餓
> （`QuicConnTimerSetEx` が上書きするため最も早い期限から張り直す）、
> detach 済み path id の stale な `PathID->Path` を読む再送ハンドラ、
> 死にかけの path id にパスを付け得る `QuicConnGetPathForPeer`、そして #118 が
> 入れた未チェックの `Path->PathID` を拾っている。

**測定（#118 のビルドで各 3 回。出荷された #119 でも同じ値が出る）:**

| | 修正前 | 修正後 |
| --- | --- | --- |
| 一度も検証されないパスの枠 | 60 秒で戻らない 3/3 | **6.29 秒で戻る 3/3** |
| 検証済みパスを `remove_path` | 251 ms / 戻らない回あり | 252 ms ×2、3.27 s ×1（戻らない回なし） |

そしてトレースに、本節が探していた並びが出る:

```
35.993413  PATH_ABANDON  server TX     ← 返答（修正前は無かった）
39.068992  ConnPathIDCloseTimerExpired  pathid 1
39.068994  ConnPathIDRemove             pathid 1
39.069414  ConnPathRemoved              Path[1]   ← QuicPathRemove が走った
```

`multipath_spike` の質問 8 も動いた — 放棄後のパス数が 3 → **2**、
`remove_path` 後の枠の復帰が None → **3.27 秒**。回帰は無し（557 テスト、
スパイク 8 問）。質問 7 の報告が `[2, 2, 2]` → **`[2]`** になったのは #117 で
ある。

#### そして修正が別の不具合を踏んだ（msquic#122 → #123）

**close タイマーの飢餓を直したことで、以前は発火しなかった解放が走るように
なり、debug ビルドが abort した。** `send.c:327` の
`HasAckElicitingPacketsToAcknowledge` で、`QUIC_CONN_TIMER_PATH_CLOSE` →
`QuicPathIDSetTryFreePathID` → `QuicLossDetectionReset` という経路である
（`path_stats_wedge` で 5 回中 3 回、前リビジョンでは 3/3 クリーン）。

> **本書が #122 で推定した機構は外れていた。** 327 行は `QuicSendValidate` の
> 3 番目ではなく **2 番目**の分岐 — 遅延 ACK タイマーが張られているのに ACK
> 対象が無い — で、bugcheck の `Expr` が否定されていないことがそれを示す。
> 推定した「死にかけの path id がまだ数えられている」は起こり得ない:
> `QuicPathIDSetTryFreePathID` は `QuicLossDetectionReset` より前にテーブルから
> 外すので、その時点で既に数に入らない。**真因は、ACK 状態が接続全体のもので
> ありながら、それが表すパケットは path id ごとに数えられていること**で、
> 集合から path id を外すと答えが変わるのに突き合わせが無かった。#123 が
> `QuicSendUpdateAckState` をその後に呼ぶ。**由来の記述（#119 の再アームが
> 到達可能にした）は正しいと確認された。**

#125 が ACK フレームの書き出しも `Connection->Paths` から path ID 集合の走査へ
移し、#119 の PATH_ABANDON と同じ形に揃えている。

#### 報告されない枠を占めていたのは path ID だった

本節の初版は「スパイクの後段で `get_path_statistics` が 2 を報告しているのに
`add_path` が `QUIC_STATUS_OUT_OF_MEMORY` を返す。残りを何が占めているかは
追っていない」と書き、§5 の未確認項目に挙げた。その項目は解けたので外した。**占めていたのはパスではなく path ID である。**
解放は `CurrentPathIDCount` を下げ、それが `MaxPathID` を上げて MAX_PATH_ID を
送らせる。応答側が使用済み path ID を抱えたままだと相手の
`QuicPathIDSetNewLocalPathID` が `QUIC_STATUS_PATHID_LIMIT_REACHED` を返し、
**報告上はまだ空きがあるのに `add_path` が通らない。** 出荷された版では
質問 8 の (c) と (d) がどちらも `add_path` 受理・枠は 6.28 秒で復帰・再度の
`add_path` も受理を示す。

**ただし計測の注意は残る。** `QUIC_PARAM_CONN_PATH_STATISTICS` が数えるのは
`PathsCount` が縛るのと同じ配列の `InUse && PathID != NULL` だけなので、
上限そのものではなく**下限**である。本書が「枠」として挙げた数値はすべて
この下限で読んでいる。

> **ユーザーの指示どおりの手順で、推論は 1 段で済んだ。** `QuicPathRemove` が
> 呼ばれたかを `ConnPathRemoved` で見る、という見方を与えられた時点で、
> 「枠が開かない」は「`QuicPathRemove` が呼ばれない」に、そこから
> 「`Abandoned` が立たない」に、そこから「相手が放棄を返さない」に、
> 一直線に降りられた。**§7.8 を 3 回書き直した 1 回の実行からの推測とは、
> 証拠の質が違う。**

### 7.11 1 本のセッションでリレーを 3 回落とした（2026-10-06）

§5-9 が問うていた「3 回目に何が見えるか」を実機で測った。1 本のセッション、
75 秒間隔で `relayctl.sh restart` を 3 回、現在の main（サブモジュール
`edbf99b`）、debug ビルド、転送には 2 秒ごとのプローブ。

**枠の天井はもう当たらない。**

| | |
| --- | --- |
| `add_path` | **3 回とも受理**。`QUIC_STATUS_OUT_OF_MEMORY` は一度も出ない |
| プローブ失敗 | **0** — 転送ポートは 3 回を通して一度も落ちない |
| 検知 | 8.1 秒（§7.5.3 の 7.6〜9.5 秒と一致） |
| 新しいレグが立つまで | 約 2 秒 |

§7.8 と §3.3 が書いていた「失敗 2 回で枠が尽きる」は、#119 が検証されない
パスの枠まで返すようになったことで**解消している**。両節に追記した。

**§5-1 と §5-2 も 3 回を通して再確認できた。** §7.1 で既に答えが出ていた
（§5 のリストに残っていたのは手落ちで、そこも直した）が、同じことが毎回起きる:

```
13:49:41.0816  [server] Unbound { connection_id: "conn_-kVC10wcJiby" }   ← 古い ID
13:49:41.0816  [server] Bound   { connection_id: "conn_Sh189Dc4p8-U" }   ← 新しい ID
13:49:41.1414  [server] a peer is reaching this leg peer=127.0.0.1:42449
```

クライアントの新しいレグが立ってから **60 ms 以内**に、古い ID が `Unbound`、
新しい ID が `Bound` になり、そのレグに相手が届いている。

#### しかし貼り直したパスが検証されない — 3 回とも

```
13:49:41.109  a replacement relay leg is up; opening a path ... waiting up to 10s
13:49:44.185  a path this connection was not using was removed path_id=2 remote=127.0.0.1:44521
13:49:51.110  ERROR the path opened to the replacement relay leg was never validated within 10s
13:49:51.110  WARN  could not abandon a path ... (QUIC_STATUS_NOT_FOUND)
```

`add_path` は通り、path id も付く（`path_id=2`）。**検証タイムアウトが約 3 秒で
それを外し**、`portal_core::path` は来るはずのない `PathAdded` を忍耐が切れる
10 秒まで待って error を出す。最後の `NOT_FOUND` は §7.8 のとおり「もう無い」の
意味で、整合している。

challenge は相手に届いている。リレーのログに、`add_path` の 42 ms 後、サーバの
ランデブー宛に 1220 バイトのパディング済みデータグラムが出ている:

```
13:49:41.151  1220B ctx0 -> 127.0.0.1:30004     ← PATH_CHALLENGE
13:49:41.306  1192B ctx2 -> 127.0.0.1:42449
13:49:41.370  1220B ctx2 -> 127.0.0.1:42449
```

**サブモジュール更新による退行ではない。** 同一期間の対照として、更新前の
`5168d9d2` で portal を建て直して同じ 3 回を走らせると、**同じく 3/3 で検証
失敗**し、プローブ失敗も 0 だった（対照側は同一 path id の `PathRemoved` が
2〜3 回出ており、library が本当に入れ替わっていることの裏も取れている — #117
前の挙動である）。

**P5 では通っていた。** §7.1 は `add_path` → `PathAdded` を **64 ms** と測り、
`the relay is back on a path of its own, held as backup path_id=2` を記録し、
`RELAY_PATH_PATIENCE` の満了は 1 度も起きていないと書いている。つまり
2026-10-02 から今日までの間、またはビルドプロファイルの差で、**貼り直しは
フォールバックを復旧しなくなった。**

#### そして差は debug と release だった

release で建て直して同じ 3 回を走らせると、**3 回とも検証される**:

```
14:26:27.885  a replacement relay leg is up; opening a path ... waiting up to 10s
14:26:27.948  the relay is back on a path of its own, held as backup  path_id=2   ← 63 ms
14:27:44.259 → 14:27:44.322                                                        ← 64 ms
14:29:01.800 → 14:29:01.863                                                        ← 64 ms
```

§7.1 が P5 で測った **64 ms と一致する。** 3 回目のあとも設計どおりで、古い
リレーパス（path_id=3）が畳まれ、新しいリレー（path_id=4）と直接経路
（path_id=1）が残る。

| 実行 | ビルド | サブモジュール | 検証された | 10 秒で諦めた |
| --- | --- | --- | :---: | :---: |
| rel2 | **release** | `edbf99b` | **3** | **0** |
| d3 | debug | `edbf99b` | 0 | 3 |
| ctl | debug | `5168d9d2` | 1 | 3 |

**つまり「貼り直しがフォールバックを復旧しない」は debug ビルドの産物で、
製品の退行ではない。** P5 の結論は立っている。debug では検証タイムアウト
（約 3 秒）までに challenge の往復が returns しない — なぜそこまで遅いのかは
別の問いだが、運用に乗るのは release である。

> **本書の他の時間も debug で測ったものである。** §5-4 の 6.29 秒 /
> 252 ms〜3.27 秒 と §5-5 の 2.08〜2.26 ms は `path_stats_wedge` と
> `multipath_spike` の値で、どちらも debug ビルドである。release ではより
> 速いはずで、**測り直していない**。
>
> **そしてこの節は 1 回、汚染された実行で書きかけた。** release の最初の走行は
> 起動直後にセッションが閉じた — 前の debug 実行の portal が 26 分生き残り、
> **同じ Endpoint 鍵を共有していた**。ハーネスが自分のプロファイルしか kill
> しないためで、両方を落として走り直したのが上の結果である。d3 と ctl は
> 互いに kill し合っているので清浄だった。**二重起動はこのセッションで 3 度
> 目である。** ハーネスは両プロファイルを落とし、終了時に自分も片付けるように
> した。

#### §5-6: 2 度目の `advertise` は走らない

§2.2-3 は「listener 側で `advertise` がもう一度走り、`add_bound_addr` が同じ
アドレスに `ADDRESS_IN_USE` を返す。新しいレグの binding は別アドレスなので
通るはずだが、**それは 2 本目の直接経路候補を増やすこと**でもあり上限 4 に
効く」と心配していた。**走らない。**

`direct_path::advertise` は一度適用したら `break` する（`direct_path.rs:130`）
— 理由はコメントが既に書いている通りで、binding はその時点で接続に付いて
おり、2 度目の `add_bound_addr` は `QUIC_STATUS_ADDRESS_IN_USE` になる。
`advertise` は peer connection ごとに一度 spawn されるので、レグが繋ぎ直して
も再広告されない。

**spike では `ListenerSession` を使っていないので未確認だった分を、実機で
確かめた。** 上の release 実行（本物の `ListenerSession`、貼り直し 3 回）で:

| | 回数 |
| --- | :---: |
| server: `advertised a direct path to the peer` | **1** |
| server: `ADDRESS_IN_USE` / 2 度目の `add_bound_addr` 警告 | **0** |
| client: `offered direct-path candidates` | **1** |
| client: `a direct path validated` | **1** |

候補は増えず、枠も増えない — 3 回目のあとのパス集合は新しいリレーと直接経路の
**2 本**である。コメントが言う「相手は検証したパスを持ち続ける」もそのとおりで、
直接経路（path_id=1）は 3 回を通して生きていた。

> **1 回だけ、検証されたリレーパスが 3 秒後に放棄された。** 3 回目の
> `path_id=4` が 14:29:01.863 に検証され backup になった **3.04 秒後**、
> 14:29:04.908 に `PathRemoved` が来た。直前のサンプルでそのパスは健全
> （`rtt_us=32388 in_flight=0`）で、レグ自身の統計も続いており、こちらからは
> 畳んでいない — **相手が PATH_ABANDON を送った**形である。1 回目と 2 回目では
> 起きていない。**3 回中 1 回なので、本書の規律（§0.1.1）では findings では
> ない。** §5-13 として残す。

> **§5-9 が心配していた形は、debug ではそのまま起きた。** プローブ失敗 0、
> 転送は生きたまま、ログに error が 3 行 — 運用から見れば何も起きていない。
> release では起きないが、**この形で壊れうること自体は変わらない**: 貼り直しが
> どんな理由で失敗しても、見えるのはログの 1 行だけである。

---

## 5. 確かめていないこと

**msquic についての未知は尽きていない。** **5 が残る**（7・8・10・12・13）。
残りは消し線で、どこで答えが出たかを書いてある — 本書の後半は測った順に
積んであるので、ここが索引になる。

**12 は新しい**（§7.11）: debug ビルドでは貼り直しのパスが検証タイムアウトに
間に合わない。release では 63 ms で通るので運用には出ないが、**本書の時間の
多くは debug で測っている。**

1. ~~**新しい `connection_id` で入り直したとき、listener 側が本当にレグを貼るか**~~
   → §7.1 で答えが出ており、ここに残っていたのは手落ち。**貼る。**
   §7.11 で 3 回の再起動を通してもう一度確かめた — 古い ID が `Unbound`、
   新しい ID が `Bound` になるのは、クライアントの新しいレグが立ってから
   **60 ms 以内**である
2. ~~**古い `connection_id` のエッジを client が畳めるか**~~ → 同じく §7.1。
   **畳める** — `Unbound` が届くので枠は食わない（§7.11 で再確認）
3. ~~**MASQUE の `Forward` モードが、再起動したリレーをどう扱うか。**~~
   **読んで答えが出た。** 転送ソケットは `(StreamId, 送信元アドレス)` ごとに
   `UdpSocket::bind("0.0.0.0:0")` で新しく開かれ、その表は `MasqueClient` の中に
   ある（`from_quic_to_udp.rs:581`）。リレーの再起動は H3 接続ごと、つまり
   `MasqueClient` ごと消すので、**新しいレグは必ず新しい送信元アドレスを
   見せる。** 心配していた「古いソケットが残る」は起こらない
4. ~~**`PATH_ABANDON` が完了して `PathsCount` が減るまでの時間**~~ → 測った
   （§7.8 / §7.10）。**一度も検証されなかったパスは 6.29 秒**（3/3）、
   **検証済みパスを `remove_path` したときは 252 ms〜3.27 秒**。どちらも
   「10 秒以内」よりは具体的で、前者は検証タイムアウト約 3 秒 + 相互放棄の
   往復 + 3 PTO の close タイマーという内訳が付く
5. ~~**`add_path` から `PathAdded` まで**~~ → 測り直した。**2.08 〜 2.26 ms**
   （3/3、`path_stats_wedge`）。旧記述の **214 µs 〜 1.2 ms は確かに下限**で、
   時計が `add_path` の後から始まり誰もイベントを drain していなかった分だけ
   短く出ていた。いまは **呼び出しの前からイベントを読むタスクを回し、時計も
   呼び出しの直前に置く**。`PathAdded` は検証を待つので PATH_CHALLENGE の
   往復を含む — ループバックではそこは µs 台である
7. ~~**新しい path id 用の CID をどう手に入れるか**~~ → §0.1.1。**本番では
   既に持っている。** 残るのは「確立直後にリレーが落ちた」狭い窓だけで、
   そこは検知して報告する（§0.1.1 の末尾）。**その窓に入ったセッションが
   実際にどれくらいあるかは測っていない**
6. ~~**listener 側で `advertise` が 2 度目に何をするか**~~ → 答えが出た
   （§7.11）。**2 度目は走らない。** `advertise` は一度適用したら `break` し、
   peer connection ごとに一度しか spawn されないので、レグが繋ぎ直しても
   再広告されない。実機の 3 回の貼り直しを通して、広告は 1 回、
   `ADDRESS_IN_USE` は 0、候補も枠も増えない
7. **貼り直しが実配備で通る率。** §0.1.1 の CID の窓は spike では狙い撃ちに
   なっており、本番で当たるのは「確立直後にリレーが落ちる」場合だけのはず
   である。**その「はず」は測っていない** — 当たれば
   `RELAY_PATH_PATIENCE` 満了の error が出る（P5）
8. **検証済みパスが枠を返さなかった回の機構。** 条件は §7.10 で分かった
   （相互放棄）が、**返らなかった回そのものはトレースしていない。**
   「相手側のパスが既に無ければ返らない」はその機構からの予測である
9. ~~**1 本のセッションでリレーが 3 回落ちたときに何が見えるか**~~ → 測った
   （§7.11）。**枠は尽きない**（#119 以降、`add_path` は 3 回とも通る）が、
   **貼り直したパスが 3 回とも検証されず**、フォールバックは復旧しない。
   プローブ失敗は 0 なので、運用からは何も起きていないように見える
10. **§7.9 の wedge の原因。** プローブで再現しなかったので、分かっているのは
    「**何ではないか**」だけである
11. ~~**貼り直したパスが検証されなくなったのは何のせいか**~~ → 測った
    （§7.11）。**debug ビルドである。** release では 3 回とも 63〜64 ms で
    検証され、P5 の 64 ms と一致する。製品の退行ではない
12. **debug ビルドで challenge の往復が検証タイムアウト（約 3 秒）に
    間に合わないのはなぜか**（§7.11）。release との差が 63 ms 対 3 秒超という
    のは、最適化の有無で説明するには大きい。**本書の時間の多くは debug で
    測っている**（§5-4・§5-5、`path_stats_wedge` と `multipath_spike`）ので、
    どこまでが debug の遅さなのかを知っておく価値がある
13. **検証されたリレーパスが 3 秒後に相手から放棄された 1 回**（§7.11 末尾）。
    3 回中 1 回で、そのパスは健全、レグも生きており、こちらからは畳んでいない。
    **1 回では findings ではない**（§0.1.1）。繰り返して率を見るのが先で、
    起きるなら貼り直しの耐久性そのものに関わる

---

## 6. この計画で解かないもの

1. **リレー自身の冗長化。** 別のリレーへ張り替えるのは
   `relay_proximity_client.md` の続きであって、本書は「同じ相手にもう一度」だけ
   を扱う
2. **listener 側から貼り直しを起こすこと。** listener は「レグが死んだが QUIC は
   生きている」を知らない（§0.2 B）
3. **直接経路が落ちたときの再探索。** 本書はフォールバックを取り戻すだけで、
   直接経路をもう一度 punch する話はしない
