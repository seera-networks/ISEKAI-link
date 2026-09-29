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

> 以下、`§n` は本書の節。msquic の核は `submodules/msquic-async-rs/seera-msquic`
> を指す。

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
| `add_path` | **○** | ✕ `INVALID_STATE` | `QuicConnAddPath`（client は `ServerMigrationEnabled` も `Negotiated` も偽のときだけ通る／server は `Negotiated` が真のときだけ） |
| `remove_path` | **○** | ✕ | `QuicConnRemovePath` |
| `add_bound_addr` | ✕ | **○** | `QuicConnAddBoundAddress` |
| `remove_bound_addr` | ✕ | **○** | `QuicConnRemoveBoundAddress`（加えて `HandshakeConfirmed` が要る） |
| **受信パケットから新しいパスを作る** | ✕ | **○** | `path.c:358` |

読み方は 2 つある。

1. **client は自分でパスを足すしかない。** 受信からパスは生えないので、新しい
   レグが張れても、client がそこへ `add_path` しない限り何も起きない。
2. **server は自分でパスを足せない。かわりに、受信すれば勝手に生える。**

提案はこの 2 行そのものである。

### 0.2 壊れているのは client 側だけ、のはずである

| | いま何が起きるか |
| --- | --- |
| **client** | `dial` が `set_remote_addr(127.0.0.1, ConnectRelay::local_addr のポート)` で**最初のパスの宛先を固定**する。レグが死ぬとその UDP ソケットの相手が居なくなり、送り先が消える。新しいレグを開いても**新しいポート**なので、inner QUIC は古い宛先に送り続ける |
| **server** | `ListenerSession` の `forward_to` は**セッション不変**で、`poll_and_bind` が同じ `connection_id` にレグを貼り直す。新しいレグから届くパケットは同じ `forward_to` に入り、**送信元ソケットだけが変わる** — §0.1 の 5 行目により、server 側はそれだけで新しいパスを作る |

つまり **server 側は何もしなくてよい可能性がある。** これが最初に測ることであり
（§4 P0）、もしそうなら `add_bound_addr` の分の作業は丸ごと消える。

> **`add_bound_addr` が要るとすれば理由は 1 つだけ**である: `forward_to` が
> リスナの共有バインディングを指しているために、**そこへ届いたパケットが
> どの接続のものか DCID だけで決まる**こと。接続ごとに専用のバインディングを
> 持たせたいなら `add_bound_addr` になる。**要ると分かってから足す。**

### 0.3 上限は 4 で、片付けは任意ではない

`QUIC_MAX_PATH_COUNT` は **4**（`quicdef.h:398`）。リレーパス 1 + 直接経路 1 で
既に 2 で、**貼り直すたびに 1 つ増える**。2 回目の再接続で上限に当たる。

`QuicConnAddPath` は上限で `QUIC_STATUS_OUT_OF_MEMORY` を返す。受信側
（`path.c`）は「同じ remote address の非 active なパス」を rebind とみなして
掃除するが、**貼り直したレグの remote address は毎回違う**ので当たらない。

したがって **`remove_path` は機能の一部**であって後始末ではない。そして
§0.1 の表により、**それを呼べるのは client だけ**である。server 側で
溜まったパスをどうするかは §3.4。

---

## 1. いま何が起きているか

### 1.1 client のリレーパスは「最初のパス」である

```rust
// peer.rs: dial
conn.set_remote_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
```

`port` は `ConnectRelay::local_addr` のポート、すなわち**この プロセスが開いた
loopback UDP ソケット**で、MASQUE クライアントがその両端を面倒みている。inner
QUIC から見れば、リレーは「loopback の相手」でしかない。

`direct_path::prepare` が `share_binding(true)` / `unconnected_socket(true)` /
`set_local_addr(127.0.0.1:0)` を立てているので、**`add_path` に必要な前提は
すでに揃っている**（`add_path` の doc: unconnected socket ではローカルアドレスを
具体的に指定すること、ポートは 0 でよい）。

### 1.2 レグが死んでも、誰も貼り直さない

`InitiatorSession` は `open_connect_relay` を**一度だけ**呼ぶ。`RelayLegLease`
はリースを延長するが、**レグそのものを作り直す口は無い**。プロキシがレグを
忘れた場合は `handle.shutdown_token()` を引いて畳む側に回る。

### 1.3 `path.rs` は「リレーのペアは不変」を前提に書かれている

```rust
let relay = match (conn.get_local_addr(), conn.get_remote_addr()) { ... };
```

`keep_on_the_best_path` は起動時に一度読んで、以後 `Paths::relay` として
**定数のように扱う**。リレーパスが移動すると:

- `Paths::added` が新しいリレーのペアを「リレーではない」＝直接経路の候補として
  扱う
- 直接経路が停まったときの `prefer_path(&conn, relay, relay, …)` が**死んだ
  パスを指す**
- `report_paths` の `preferred == None` は「リレーに乗っている」を意味する —
  どのリレーに、が変わる

**ここが一番作業量の読みにくい場所である。** §4 P4 で扱う。

---

## 2. 形

```text
レグが死ぬ
   │
   ├─ client: 新しい peer_connect →  新しい ConnectRelay（新しい loopback ポート）
   │            │
   │            ├─ conn.add_path(127.0.0.1:0, 新しい local_addr)
   │            │      → PATH_CHALLENGE が新しいレグを通って出ていく
   │            │
   │            ├─ PathAdded（path_id 付き）を待つ
   │            │      → Paths::relay を差し替える
   │            │
   │            └─ conn.remove_path(旧 local, 旧 remote)
   │
   └─ server: poll_and_bind が同じ connection_id にレグを貼り直す（既存）
                └─ 届いたパケットから新しいパスが生える（§0.1、要測定）
```

### 2.1 `add_path` のローカルアドレス

`127.0.0.1:0` を渡す。`add_path` の doc によれば、具体アドレスを渡したパスは
**接続のバインディングを共有する** — つまりローカルポートは既存パスと同じに
なる。新しい 4 タプルは `(同じ local, 新しい remote)` で、remote が違うので
別のパスになる。

**`ADDRESS_IN_USE` は起きない**（`QuicConnAddPath` の重複判定は 4 タプル一致）。

### 2.2 「新しい peer_connect」なのか「同じ connection_id の貼り直し」なのか

レグを開くには**チケット**が要り（§8.14）、チケットは `peer_connect` の応答に
乗ってくる。リレーが死んだとき、

- **同じ `connection_id` のまま新しいチケットを取れる**なら、貼り直しは安い
- 取れない（プロキシ側でエッジごと消えている）なら、**`peer_connect` をやり直す**
  ことになり、`connection_id` が変わる。すると server 側の `poll_and_bind` は
  **別の接続として**レグを貼る — inner QUIC は同じなのに

**これは Proxy 側の契約の問題であって、クライアント側だけでは決まらない。**
§5-1 に挙げる。

---

## 3. 決めなければならないこと

### 3.1 「リレーが落ちた」をどう知るか

3 つの候補がある。

| | いつ分かるか | 誤検知 |
| --- | --- | --- |
| `ConnectRelay` の H3 接続が終わる | 即座 | 無い。**これが第一候補** |
| `RelayLegLease` の更新が `connection-not-found` を返す | 1 リース TTL 以内 | 「プロキシが忘れた」と「落ちた」の区別が要る |
| `path.rs` の失速ウォッチドッグ | `STALLED_GRACE` 後 | 直接経路に乗っている間は**そもそもリレーに何も流れない**ので当たらない |

3 つ目が当たらないことが重要である。**直接経路に乗っているセッションは、リレー
パスが死んだことを自力では気づけない。** 気づく口は 1 つ目しかない。

### 3.2 直接経路に乗っているときも貼り直すか

**貼り直す。** それがこの機能の目的である — 直接経路が生きているうちは通信に
影響が無く、だからこそ「フォールバックが消えている」ことに誰も気づかない。
気づくのは直接経路が切れた瞬間で、そのときにはもう遅い。

### 3.3 何回、どれくらいの間隔で

リレーの再起動は数秒から数十秒で終わる。**指数バックオフで上限を持ち、
諦めたら言う。** 諦めた後のセッションは「直接経路だけで動いている」状態で、
それは**動いてはいるが一本足である**ことを運用者が知るべき状態である。

### 3.4 server 側に溜まったパスをどうするか

server は `remove_path` を呼べない（§0.1）。呼べるのは `remove_bound_addr` で、
これはバインディングを解放し source CID を外すが、**`Connection->Paths[]` の
エントリを消すとは書かれていない**。

- `add_bound_addr` が不要（§0.2）なら、そもそも `remove_bound_addr` も不要で、
  この節は消える
- 必要なら、**上限 4 に当たるのが先か、`remove_bound_addr` が効くのかを測る**

---

## 4. 段取り

| # | やること | 出口 |
| --- | --- | --- |
| **P0** | **spike。** リレーを殺して、client 側だけを手で貼り直す最小の実験。server 側が何もせずに新しいパスを受け入れるか（§0.2）、`add_path` が loopback 宛に通るか（§2.1）、`PathAdded` が来るかを見る | **server 側の作業が要るかどうかが決まる。** ここで形が半分になりうる |
| **P1** | レグの死を検知して報告する。貼り直しはまだしない（§3.1） | 「フォールバックが消えた」が**ログに出る**。いまは無音 |
| **P2** | 貼り直し — 新しいチケット／`peer_connect` を取り、新しい `ConnectRelay` を開く（§2.2） | 新しいレグが立つ。inner QUIC はまだ使わない |
| **P3** | `add_path` と `PathAdded` 待ち、`remove_path` で古いものを外す（§0.3） | **inner QUIC が新しいリレーを使う** |
| **P4** | `path.rs` が「リレーのペアは動く」を知る（§1.3） | 直接経路が落ちたとき、**生きているリレー**に戻る |
| **P5** | 実配備でリレーを再起動して端から端まで | — |

**P0 が本当の分岐点である。** §0.2 が当たっていれば P3 は client 側だけの話に
なり、外れていれば `add_bound_addr` と forward 先の付け替えが P3 の前に入る。

**P1 は単独で価値がある。** いまは「フォールバックが永久に失われた」ことを
誰も知らない。貼り直しが入る前でも、それが**見える**ようになるだけで、
一本足で走っているセッションを運用者が数えられる。

---

## 5. 確かめていないこと

1. **`peer_connect` をやり直さずに新しいチケットが取れるか**（§2.2）。取れない
   なら `connection_id` が変わり、server 側は**別の接続として**レグを貼る。
   inner QUIC の同一性と `connection_id` の同一性がここで離れる
2. **server 側が受信だけで新しいパスを作るか**（§0.2）。核の条件（`path.c:358`）
   は許しているが、`forward_to` が共有バインディングであることの影響は読んで
   いない
3. **`remove_bound_addr` がパスのエントリまで消すか**（§3.4）
4. **`add_path` が返った後、`PathAdded` はどれくらいで来るか。** 直接経路では
   796 ms だった（`portal_agent_plan.md` §5）が、リレー越しの検証は往復が違う
5. **MASQUE の `Forward` モードが、同じ送信元から来る新しいレグをどう扱うか。**
   サーバ側は送信元アドレスごとに UDP ソケットを開く。リレーが再起動しても
   **リレーのアドレスは同じ**なので、古いソケットが残っていると新しいレグの
   パケットが古いソケットから出る可能性がある — そうなると server から見た
   remote address が変わらず、**新しいパスが生えない**
6. **4 パスの上限に、実際の運用でどれだけ近づくか**（§0.3）

> 5 は、当たっていれば §0.2 の楽観がそのまま崩れる。**P0 で最初に見るのは
> これである。**

---

## 6. この計画で解かないもの

1. **リレー自身の冗長化。** 別のリレーへ張り替えるのは
   `relay_proximity_client.md` の続きであって、本書は「同じ相手にもう一度」だけ
   を扱う
2. **listener 側からの貼り直しの起点。** `poll_and_bind` は既にある
3. **直接経路が落ちたときの再探索。** 本書はフォールバックを取り戻すだけで、
   直接経路をもう一度 punch する話はしない
