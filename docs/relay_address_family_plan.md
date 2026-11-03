---
title: 両端のリレーレグを同じアドレスファミリーに揃える — 実装計画
version: 0.2
status: draft
related: relay_proximity_client.md, p2p_mode_migration_plan.md §2.2.3, p2p_connect_spec.md（ISEKAI-link-server 側）§8.4・§8.10
---

# 両端のリレーレグを同じアドレスファミリーに揃える

> **0.2 で何が変わったか。** 0.1 は「既存の `GET /health` 測定をファミリーごとに
> 行う」と書いていた。**それは測る対象を間違えている**（§3 Q2）。測定経路は
> *接続済み*ソケットで、レグは*未接続*ソケットを使い、CLAT ではその二つが違うことが
> 文書化されている。測定は未接続ソケットで行わなければならない。実装順もそれに伴って
> 変わった（§5）。§2 の事実表にも誤りがあったので直した。

## 1. 要求

**P2P の両端が別のアドレスファミリーでリレーに繋ぐと、direct path が成立しない。**

例: `portal-server` が IPv6 でリレーに繋ぎ、`portal-client` が IPv4 で繋ぐ。
セッションはリレー経由で成立するが、direct path は一度も張られない。

これを、**制御プレーンが両端に共通のファミリーを選んで通知する**ことで解く。
共通のファミリーが無い場合は通知せず、各端が今日どおり自分で選ぶ（= direct path
は成立しない。それが正しい答えである — §3 Q5）。

---

## 2. いま何がどこにあるか（確認した事実）

| | 事実 |
| --- | --- |
| observed address の出どころ | **リレーレグの QUIC 接続上の `OBSERVED_ADDRESS`**。msquic が `ConnectionEvent::NotifyObservedAddress` として surface し、`observed.rs` が `ObservedAddress { local, observed }` にする。HTTP の応答ではない |
| direct path の候補 | **そのレグ自身の unconnected/shared binding から開かれる**。つまり **1 レグ = 1 binding = 1 ファミリー = 候補 1 つ** |
| ファミリーを決めている場所 | **`H3MsQuicAsyncConnector::connect` の中**（`h3-util/src/msquic_async/client.rs`、`first_routable(dns_resolve(…))`）。`bind::relay_connector` は connector を**構築するだけ**で、`first_routable` を呼ぶ箇所は `rust/` 以下に無い |
| その選択が走る条件 | **`if self.is_unconnected`（client.rs:125）の中だけ。** 未接続モードでなければ msquic が `start` で自分で解決する |
| 測定の実体 | `relay_rtt::probe` が `MasqueH3Transport::connect` 経由で H3 `GET /health`。**その transport は `is_unconnected = false`**（`transport.rs`）なので、上の選択ブロックを通らない |
| リスナーの報告経路 | `PUT /v1/peer-listeners/{listener_id}/relay-rtt`、本体 `{"relay_rtt": [RelayRttSample]}` に段 3 で `relay_reach` が加わる（`proxy.rs::report_relay_rtt`）。**両端の積を取るので、これが listener 側の唯一の口である**（§4-4）|
| initiator の報告経路 | connect の本体。**2 つある** — `peer_connect_measured`（capability 認可）と `peer_connect_with_grant_measured`（grant 認可）。`initiator.rs` が `Authorization` で振り分ける |
| 測定の入口 | `relay_rtt::measure_for_connect`（`initiator.rs` から呼ばれる）|
| 制御プレーンの応答 | `RelayInfo { masque_uri, … }` が `PeerConnection.relay: Option<RelayInfo>` に入る。**`relay_base_url` はそれとは別の、`PeerConnection` 直下のフィールド**で、listener は `relay_base_url` しか読まない（`listener.rs:771`）|
| リレーを選ばない配備 | `dp_id` が無い形は正式に対応済み（`bind::relay_target` の「No relay chosen」、`relay_rtt` の「this proxy does not choose relays」）|

### 2.1 これは 0.8.2 の退行ではない

0.8.2（tonic-h3 `a43760a`）**以前**は、デュアルスタックのレグ自体が成立していなかった
— ローカルアドレスを片方のファミリーに固定しながら msquic が `start` で別を選び、
何も送れずハンドシェイクがタイムアウトし、**observed address を持たないまま** QMUX に
落ちていた。つまり以前は「デュアルスタック = direct path なし」である。

0.8.2 でそのレグが初めて動くようになり、**新しく到達したその状態を direct path 層が
想定していなかった**、というのが今回である。混在ペアの結果（direct path なし）は
以前と同じで、理由が変わった。**悪化はしていないが、閉じるべき穴が残った。**

---

## 3. 設計判断

### Q1. 報告は既存の 2 経路に乗せる。新しいハンドシェイクは作らない

`RelayRttSample` は per-relay の到達性をすでに運び、両端ともそれを**リレー選択より前**
に送っている（リスナーは PUT、initiator は connect の本体）。制御プレーンは既に両側を
突き合わせてリレーを選んでいるので、選ぶ対象が `(relay)` から `(relay, family)` に
増えるだけである。

> **順序の問題が自然に解ける。** 「リレーが決まる前にファミリーを申告する」必要が
> あるが、この 2 経路はどちらもその位置にある。別途の capability 交換を作ると、
> 既にある順序を自分で作り直すことになる。

**ただし運ぶ中身と測り方は 0.1 から変わった** — Q2・Q3。

### Q2. 測定は**未接続ソケット**で行う。既存の `/health` 経路では測る対象が違う

**0.1 の誤り。** 0.1 は「既存の `relay_rtt::probe` をファミリーごとに 1 回ずつ」と
書いた。しかしその probe は `MasqueH3Transport`（`is_unconnected = false`）を使う。
つまり:

1. ファミリー選択のブロック自体を通らない（`if self.is_unconnected` の中）。
   **ファミリーを指定する口を足しても、この経路には届かない**
2. そして、より重要なことに、**測る対象が違う。** レグは未接続/共有バインドの
   ソケットを使う。`is_clat_stub` の doc が明言しているとおり、**接続済みソケットは
   CLAT の変換器を通り、未接続ソケットは通らない**（isekai-link#213）。接続済みで
   測れば「v4 は使える」と答え、レグは同じ v4 で**使えない**

したがって測定は**レグと同じソケットモードで**行う。要求元の当初案「unconnected な
ソケットで relay に接続しに行くものを別途作る」は、ここで正しい。

**これは #213 の帰結をそのまま引き継ぐ**: CLAT のホストでは v4 が未接続ソケットで
使えないと測られ、制御プレーンはそれを共通ファミリーに選ばない。「ファミリーを
固定すると新たに CLAT フォールバックへ誘導してしまう」という危険も、これで閉じる。

> 何を叩くかは `/health` でよい — 認可も不要で、既に存在する。**変わるのは叩き方
> （ソケットモード）であって、叩く先ではない。**

### Q3. 申告は**肯定のみ**。「使えないファミリー」は送らない

0.1 は `rtt_ms: null` を「そのファミリーで測って応答が無かった」に使うと書いた。
**initiator の経路ではその null が届かない。**

`initiator_defaults()` は `per_relay: 1200ms` / `budget: 1500ms` で、
`measure_for_connect` は測定側に `budget / 2 = 750ms` を渡す一方 `per_relay` は
1200ms のままである。`measure_with` の収集ループは `timeout_at(deadline)`（750ms）で
打ち切るので、**1200ms で初めて確定する「到達不能」のサンプルは捨てられ、省略に
なる**。省略は「未測定」なので、IPv4-only の initiator は「v6 は使えない」と**言えない**。

そこで、否定的証拠に依存しない形にする:

```json
"relay_reach": [
  { "dp_id": "dp_1", "families": ["v6", "v4"] },
  { "dp_id": "dp_2", "families": ["v6"] }
]
```

- **列挙されたファミリーは「測って使えた」の意味だけを持つ**
- 制御プレーンは両端の集合の**積**を取る。空なら省略（Q5）
- 間に合わなかった測定は単に列に入らない。**取りこぼしは積を小さくするだけ**で、
  嘘にはならない — 最悪の結果は「今日の挙動」である
- `relay_rtt` は**今日のまま**。旧い制御プレーンは `relay_reach` を無視する

> **予算の按分は別途決める必要がある**（§8-6）。1 リレーの `per_relay` を 2 ファミリーで
> 分け合うのか、ファミリーごとに取るのか。前者だと死んだ v6 が生きた v4 の機会を
> 食い尽くし、v4 が未報告になる。肯定のみの設計なので**安全側に倒れる**が、
> 揃う機会を失うのは惜しい。

### Q4. 答えは **2 箇所**に載せる。listener は `relay` を読まない

initiator は `PeerConnection.relay: Option<RelayInfo>` を見るが、**listener は
`PeerConnection.relay_base_url`（直下）しか読まない**（`listener.rs:771`）。
したがって片方に載せるだけでは listener に届かない。

```json
{
  "relay": { "masque_uri": "https://…", "family": "v6" },
  "relay_base_url": "https://…",
  "relay_family": "v6"
}
```

- `RelayInfo.family` — initiator 用
- **`relay_family`（`PeerConnection` 直下）** — listener 用、`relay_base_url` の隣

どちらも `serde(default)`。0.1 は「同じものを載せる」と書いただけで**名前を決めて
いなかった** — サーバとクライアントが別々に名前を発明する余地を残していた。

### Q5. 共通のファミリーが無ければ「通知しない」。それが正しい答えである

共通のファミリーが無いなら、両端は互いに**直接到達できない**。穴あけのしようがないので
direct path は原理的に不可能であり、リレー継続が正しい。

制御プレーンは `family` / `relay_family` を省略し、各端は今日どおりに選ぶ。
**クライアント側に「不一致時の特別な処理」は要らない** — 省略 = 無制約 = 今日の挙動。

> 要求の「マッチしない場合はそれぞれが使用可能なものを伝える」は、この形では
> **何も伝えないことと同じ**になる。各端はもともと自分が使えるものを選ぶので、
> 伝え返す情報が無い。省略で足りる。

### Q6. 適用点は **tonic-h3 の中**。こちらの `bind.rs` では閉じない

ファミリーを選んでいるのは `H3MsQuicAsyncConnector::connect` の中であり、`bind.rs` は
connector を**構築する**だけである。したがって connector にファミリーの指定を受ける
口が要る — `with_peer_certificate_callback` と同じ builder の形で、**tonic-h3 側の
変更**になる（§7.1）。

> **IP リテラルの URI を渡して迂回する手は使えない。** 名前の代わりにアドレスを
> 渡せば解決は起きないが、`refuse_other_hosts(host)` は証明書を**dial したホスト名**
> と照合しており（#134）、`conn.start` はその名前を SNI にも使う。アドレスを渡すと
> 証明書検証と SNI の両方が壊れる。

絞った結果 routable なものが無い場合は、**無制約に戻して続ける**（失敗させない）。
報告した時点では使えていたのだから、ここに来るのは経路が変わった後であり、
リレーに繋がらないより繋がった方が良い。

### Q7. ファミリーは**引数として**レグまで運ぶ。`RelayOptions` には載せない

`RelayOptions` は 7 箇所で**全フィールドを明示して**構築されている（`portal-core`
×3、`camera-core`、`camera-client`、`isekai-client-ffi`、例 1 件）。
`..Default::default()` を使っていないので、フィールドを足すと全部が壊れる。

そして**そもそも載せられない** — ファミリーは connect の**応答**で届くのに、
`RelayOptions` はアプリがその前に組み立てている。したがって
`open_connect_relay` と listener の `bind` の**引数**として渡す。§4 の 6・6b は
その署名変更を含む。

### Q8. camera 側にも同じだけ効く

機構は `isekai-p2p` / `isekai-p2p-core` にあるので、`camera-server` / `camera-client`
も同じ経路を通る。**ただし Q7 のとおり署名が変わるので、呼び出し側の修正は要る** —
0.1 の「portal 固有の変更は無い」は「portal だけの話ではない」の意味であって、
「どこも直さなくてよい」ではない。

### Q9. msquic の単一候補はこの計画では直さない

`QUIC_ADD_ADDRESS_NAT_TRAVERSAL` では msquic は候補リストの**先頭しか読まない**
（`QuicConnProcessAddAddress` が `CandidateAddresses.Flink` を取る。msquic 自身の
`TODO - Use the correct local address based on the observed address` 付き。詳細は
`direct_path.rs` の注記）。

**だから「両ファミリーの候補を集めて両方広告する」は今日は効かない。** この計画は
それを**回避する**ものであり、直すものではない（§8-1）。

---

## 4. 変更一覧

| # | 変更 | 場所 |
| --- | --- | --- |
| 1 | **connector がファミリーの指定を受ける**（builder）。指定があれば `first_routable` に渡す前に解決結果を絞る | **tonic-h3**: `h3-util/src/msquic_async/client.rs`（§7.1）|
| 2 | **未接続ソケットでの測定経路**。`MasqueH3Transport` は `is_unconnected = false` なので、測定用に未接続の口が要る（Q2）| `isekai-p2p-core/src/transport.rs`, `isekai-p2p/src/relay_rtt.rs` |
| 3 | ファミリーごとの測定と `families` の算出（肯定のみ、Q3）| `isekai-p2p/src/relay_rtt.rs` |
| 4 | `RelayReach { dp_id, families }` と送信。**報告経路は 3 つあるので全部** — initiator の connect 本体 2 つ（`peer_connect_measured` と `peer_connect_with_grant_measured`）と、**listener の PUT（`report_relay_rtt`）**。§7.2-2 が両端の積を取るので、listener の口を落とすとその側は永久に空になり、「共通ファミリーが無い」と区別が付かない | `isekai-p2p-core/src/proxy.rs` |
| 5 | `RelayInfo.family` と `PeerConnection.relay_family` を読む（`serde(default)`、Q4）| `isekai-p2p-core/src/proxy.rs` |
| 6 | 指定を connector に渡す。`open_connect_relay` / `bind` の引数として運ぶ（Q7）| `isekai-p2p-core/src/bind.rs`, `isekai-p2p/src/{initiator,listener}.rs` |
| 6b | 署名変更の呼び出し側 | `portal-core/src/session.rs`, `camera-core/src/server.rs`, `camera-client`, `isekai-client-ffi` |
| 7 | 文書 | `docs/relay_proximity_client.md`、本書（仕様 `p2p_connect_spec.md` は ISEKAI-link-server 側）|

---

## 5. 実装順

**0.1 の順序は誤りだった。** 「ファミリーごとの測定を最初に、単独で出せる」と書いたが、
測定を正しく行うには未接続の経路（4-2）と connector の口（4-1）が先に要る。

1. **tonic-h3 に指定の口（1）。** 使う側はまだ無い。**別リポジトリなのでここが
   最も歩調の遅い部分**であり、だから最初に置く
2. **未接続の測定経路（2）と、ファミリーごとの測定（3）。** 送信はまだしない。
   ログだけで、**デュアルスタックのホストでリレーが本当に両方の未接続ソケットで
   応答するのかが分かる** — この計画全体が立つかどうかの前提
3. **`relay_reach` の送信（4）。** 旧い制御プレーンは無視するので安全。この時点で
   制御プレーン側が判断材料を得る

   > **送るのは listener の半分だけになる。** 測定は 2 段目で listener の経路にしか
   > 載せていない。initiator は 1 回の connect に 1500ms しか無く、ファミリー間の
   > 予算の分け方は §8-6 が「段 2 の実測を見てから決める」としている。肯定のみの
   > 設計なので、initiator が空を送るのは「未測定」であって害は無い（積が空 =
   > 省略 = 今日の挙動、Q5）。**ただし片側だけでは機能は効かない** — initiator の
   > 測定が入るまで、共通ファミリーは選ばれない
4. **応答の読み取りと適用（5・6・6b）。** サーバがまだ返さないなら省略 = 今日の挙動
5. **制御プレーン側**（§7.2）。ここで要求が満たされる
6. **文書（7）**

> **3 段目を 2 段目より先に出してはならない。** 測っていない値を送ることになる。

> **4 段目を 3 段目より先に出してもよい**が、意味が無い（誰も返さない）。

---

## 6. テスト

### 測定（段 2）
- A と AAAA の両方を持つ名前で、**両方のファミリーが未接続ソケットで測られる**こと
- **接続済みでは測らない**こと — CLAT のホストで v4 が `families` に入らないのが
  この設計の要点である（Q2）
- 片方しか応答しないリレーで、応答した側だけが `families` に入ること
- 予算を使い切ったとき、入らなかったファミリーが**嘘にならない**こと
  （肯定のみなので、入らない = 主張しない）

### ワイヤ（段 3）
- `relay_reach` が無い要求（旧クライアント相当）を制御プレーンが今日どおり扱えること
- `relay_rtt` の内容と意味が**変わっていない**こと
- **grant 認可の connect でも送られる**こと（`peer_connect_with_grant_measured`）
- **listener の PUT でも送られる**こと（`report_relay_rtt`）。両端の積を取る設計
  （§7.2-2）なので、ここが落ちると listener 側が永久に空になり、「共通ファミリーが
  無い」と区別が付かない
- ファミリーが 1 つも測れなかったラウンドで、**`relay_reach` を省略する**こと
  （空配列を送らない）。どの口も送れば保存集合を置き換えるので、空を送ると以前に
  測れていた集合を消してしまう。RTT は接続済みソケットで QMUX フォールバックも
  通るが、ファミリーは未接続バインドでしか数えないので、**RTT は良好でファミリーが
  空というラウンドは普通に起こる**
- families が空のエントリを**送らない**こと（`dp_id` だけのエントリに意味は無く、
  「どちらのファミリーも駄目」と読まれる余地だけが残る）

### 適用（段 4）
- `family: "v6"` を受けたとき、解決結果の IPv4 を**使わない**こと
- `relay_family` を受けた **listener** が同じく従うこと（`relay` を読まないため、
  ここが独立に壊れる）
- 省略されたとき、今日と同じ選択になること（回帰）
- 指定されたファミリーに routable なものが無いとき、**失敗せず**無制約に戻ること

### 揃うこと（段 5 以降、結合）
- デュアルスタックの listener と IPv4-only の initiator で、**両端が IPv4 を使い
  direct path が成立する**こと。これが要求そのものである
- IPv6-only と IPv4-only の組で省略され、**リレー継続で成立**すること
- **CLAT のホスト**と v6 対応のピアで、v6 が選ばれ direct path が成立すること
  （v4 を選ばれると CLAT フォールバックで observed address を失う — Q2）

---

## 7. 他のリポジトリへ依頼すること

### 7.1 tonic-h3

**`H3MsQuicAsyncConnector` にファミリーの指定を受ける口**（Q6）。
`with_peer_certificate_callback` と同じ builder の形で、指定があれば
`first_routable` に渡す前に解決結果を絞る。指定が無ければ今日のまま。

**これが無いと §4 の 6 以降が書けない** — 選んでいるのが connector の中だからで
あり、こちら側からは渡す先が無い。

> 未接続の測定経路（4-2）も、`is_unconnected = true` の transport をこちらで
> 作れるかどうかに依る。`H3MsQuicAsyncConnector::new` は既に引数で取るので
> **こちら側で閉じる見込みだが、段 2 の最初に確かめること**。

### 7.2 ISEKAI-link-server

1. **`relay_reach` を読む**（Q3 の形）。無ければ今日どおり `relay_rtt` だけで選ぶ

   > **省略と空配列を区別すること。** フィールドが**無い**のは「今回は報告が無い」で
   > あり、保存済みの集合は**そのまま残す**。クライアントは、ファミリーを 1 つも
   > 測れなかったラウンドでは送らない（段 3 で実装済み）。RTT は接続済みソケットで
   > 測り QMUX フォールバックも通るのに、ファミリーは未接続バインドでしか数えないので、
   > 「RTT は良好・ファミリーは空」は普通に起こる状態である。ここを「空で置き換え」と
   > 実装すると、UDP を塞ぐ網に移動したホストが**以前測れていた集合を消す**
2. **両端の `families` の積を取り**、接続応答に `RelayInfo.family` と
   `PeerConnection.relay_family` の**両方**を載せる（Q4）。積が空なら**省略する**（Q5）
3. リレー選択が `(relay)` から `(relay, family)` になる

どれも**クライアントが先に出ても壊れない**（`relay_reach` は追加フィールド、
省略は今日の挙動）。**サーバが先に出ても壊れない**（`serde(default)`）。

---

## 8. この計画で解けないもの

1. **両ファミリーの候補を同時に広告すること**（Q9）。ICE の答えであり将来は正しいが、
   msquic が先頭候補しか読まない間は集めても無駄で、`seera-msquic` の
   `QuicConnProcessAddAddress` の TODO が解消されてからの仕事である
2. **両端が別ファミリーしか持たない場合の direct path**。原理的に不可能であり、
   リレー継続が答えである（Q5）
3. **リレーを選ばない配備**（`dp_id` が無い形。`bind::relay_target` の
   「No relay chosen」）。`relay_reach` は `dp_id` で引くので**報告する先が無く、
   選ぶ対象も無い**。両端は制御プレーン自身のデータパスを dial し、§1 の食い違いは
   同じように起こる。**この計画では覆えない** — 別の持ち場（制御プレーン自身の
   アドレス選択）の話になる
4. **同一 LAN の direct path**。#293 で失われたままで、本件とは独立
5. **経路が後から変わった場合**。`family` はセッション開始時の判断で、途中で
   使えなくなっても再交渉しない。Q6 のフォールバックがあるので「繋がらない」には
   ならないが、**その場合 direct path は再び揃わない**
6. **1 リレーの測定予算をファミリー間でどう分けるか**（Q3 の注記）。肯定のみの
   設計なので安全側に倒れる（取りこぼし = 主張しない = 今日の挙動）が、
   **揃う機会を失う**。`per_relay` をファミリーごとに取るのか分け合うのかは、
   段 2 の測定で実際の所要時間を見てから決める

---

## 9. 参照

- `rust/isekai-p2p-core/src/observed.rs`（`OBSERVED_ADDRESS` と
  `ObservedAddress { local, observed }`）
- `submodules/tonic-h3/h3-util/src/msquic_async/client.rs`（`first_routable` の
  呼び出し、`is_clat_stub`、`if self.is_unconnected` の境界 — **ファミリー選択は
  ここにあり、`bind.rs` には無い**）
- `submodules/tonic-h3/h3-util/src/client.rs`（`first_routable` の定義、RFC 6724）
- `rust/isekai-p2p-core/src/bind.rs`（`relay_connector` が connector を構築する箇所、
  `RelayOptions`、`relay_target` の「No relay chosen」）
- `rust/isekai-p2p-core/src/transport.rs`（`MasqueH3Transport` が
  `is_unconnected = false` を渡す箇所 — Q2）
- `rust/isekai-p2p/src/relay_rtt.rs`（`probe` の `GET /health`、
  `measure_for_connect`、`initiator_defaults` の `per_relay` と `budget` — Q3）
- `rust/isekai-p2p-core/src/proxy.rs`（`RelayRttSample`、`report_relay_rtt`、
  `peer_connect_measured` と `peer_connect_with_grant_measured`、`RelayInfo`、
  `PeerConnection.relay` と `PeerConnection.relay_base_url`）
- `rust/isekai-p2p-core/src/hostname.rs`（`refuse_other_hosts` — IP リテラルで
  迂回できない理由、Q6）
- `rust/isekai-p2p/src/direct_path.rs`（msquic が先頭候補しか読まないことの注記）
- `rust/isekai-p2p/src/peer.rs`（`AddAddressMode::NatTraversal` を設定している箇所）
- `docs/relay_proximity_client.md`（測る側の既存計画）
- `p2p_connect_spec.md` §8.4・§8.10（**ISEKAI-link-server 側**。本書で仕様を直す
  対象ではない）
