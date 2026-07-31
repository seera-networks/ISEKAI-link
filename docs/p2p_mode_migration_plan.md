# P2P モードへの接続経路 migration 拡張 実装計画書

`camera-client` / `camera-server` の **接続経路 migration（リレー経路 ⇄ 直接経路の切り替え）** は、現状 **Direct モードのみ**で動作します（#59）。本計画書は、これを **P2P モード**（P2P Connect + MASQUE リレー）にも拡張するための実装方針・API 変更・フェーズ分割・検証方法をまとめたものです。

対象コミット: `427d963 feat(camera): Direct-mode connection path migration (#59)` 時点の `main`。

---

## 0. ゴールと非ゴール

> **達成状況（2026-08-01）**: 下記ゴールはすべて実装・実測済み。
> 別ネットワークに置いた実機 2 台で、NAT 越えの直接経路への切り替えと
> 切替後のデータ継続を確認した（§6.2）。

### ゴール

- P2P モード（`Mode::P2p`）で確立した映像 QUIC 接続（ALPN `sample`）を、**リレー経路**（MASQUE トンネル経由）から **直接経路**（NAT traversal で穴あけした peer 間の直結パス）へ、接続を切らずに切り替えられるようにする。
- 逆方向（直接経路 → リレー経路）へも戻せる。
- `camera-client` の「Migrate to P2P / Migrate to Isekai Link」ボタンと RTT グラフを P2P モードでも有効にする。
- 直接経路が取れない環境（対称 NAT 等）では **リレー経路のまま動き続ける**（デグレードであってエラーではない）。

### 非ゴール（本計画の範囲外）

- 自動的な経路選択（RTT を見て自動で migrate する等）。今回は手動トリガのまま。
- iOS (`isekai-client-ffi`) への migration UI 露出。API が壊れないことだけ担保し、露出は後続（§8 の Phase 7）。
- 制御プレーン（`/v1/peer/connections/{id}/state` の `candidates` / `peer_candidates`）を使った候補交換の本格導入。今回は QUIC レベルの NAT traversal 拡張のみを使い、制御プレーン方式は将来オプションとして §3.5 に記載。
- `Mode::Direct` 側の挙動変更。

---

## 1. 現状整理

### 1.1 Direct モードの migration が成立している仕組み（#56〜#59）

**サーバ側 (`rust/camera-server/src/main.rs::run_isekai_connection`)**

1. 映像 QUIC listener を `127.0.0.1:0` に bind（`make_msquic_async_listener`, ALPN `sample`）。
2. `create_masque_channel(..., is_unconnected = true, Some(conn_tx))` でリレー（プロキシ）への MASQUE H3 接続を張る。
   - `is_unconnected = true` により `H3MsQuicAsyncConnector` が
     `set_share_binding(true)` + `set_unconnected_socket(true)` を行い、
     「ターゲットへ `connect()` した捨て UDP ソケットの `local_addr` を `set_local_addr()` で pin する」ことで、
     **実インタフェース上の共有・非接続バインディング L_s** を確保する（`submodules/tonic-h3` の `a68d128`）。
   - `conn_tx` によって、この H3 接続の生 `msquic_async::Connection` が呼び出し元へ返る。
3. その接続の `poll_event` で `ConnectionEvent::NotifyObservedAddress { local_address, observed_address }` を受け取り、`(L_s, O_s)` を `migrating_addr` に保持。
4. `listener.accept()` した**各クライアント接続**に対し `add_bound_addr(L_s)` / `add_observed_addr(L_s, O_s)` を適用 → クライアントに「自分は `O_s` でも到達できる」と広告する。
5. `set_udp_mode("dedicated")`（#58）でリレー側に専用 UDP ポートを要求。

**クライアント側 (`rust/camera-client/src/main.rs::connect_direct`)**

1. **Phase 1**: リレー（`tokyo.link.isekai.tools:8443`, ALPN `h3`）へ接続し、`NotifyObservedAddress` から自分の `(L_c, O_c)` を得て、**接続を drop**（`std::mem::drop(conn)`）。
2. **Phase 2**: サーバの公開アドレス（= リレーのエッジアドレス）へ ALPN `sample` で接続。`start()` の**前**に `add_candidate_addr(L_c, O_c)`、設定で `AddAddressMode::NatTraversal` + `ReceiveObservedAddressReports` を有効化。
3. 接続直後の `(get_local_addr, get_remote_addr)` を `isekai_link_path`（初期＝リレー経路）として記録。
4. `poll_event` の `PathValidated { local_address, remote_address }` が初期経路と異なれば、それを `p2p_path`（直接経路）として記録。
5. UI のボタン → `migrate_tx` → `conn.activate_path(local, remote)` で経路を切り替え。

### 1.2 P2P モードの現状経路

**サーバ側 (`camera_core::spawn_p2p_server`)**

```
camera 映像 → serve_frames → video listener (127.0.0.1:V, ALPN sample)
                                     ↑ loopback UDP
                        MasqueClient (Forward mode) ← MASQUE bind leg (H3 → proxy)
                                     ↑
                                  リレーエッジ (proxy が bind した公開ソケット)
```

- `open_bind_session`（`isekai-p2p-core/src/bind.rs`）が bind レグを張る。
- **`H3MsQuicAsyncConnector::new(..., is_unconnected = **false**, ...)`** → 共有バインディングも非接続ソケットも使わない。
- 生 `Connection` を呼び出し元に返す仕組み（`with_channel`）を使っていない。
- `make_client_config`（`isekai-p2p-core/src/transport.rs`）に **`set_ReceiveObservedAddressReports()` が無い** → observed address 報告そのものが来ない。
- `ListenerSession::bind()` は `BindSession` を drain タスクに投げ捨てており、イベントは `tracing::debug!` されるだけ。

**クライアント側 (`InitiatorSession` + `camera_core::receive_frames`)**

```
video QUIC client (msquic) ── loopback UDP ──▶ tokio UdpSocket (127.0.0.1:R)
                                                      │  CONNECT-UDP capsule
                                                      ▼
                                          MASQUE connect leg (H3 → proxy) ──▶ リレーエッジ
```

- `open_connect_relay` も `is_unconnected = false`、`with_channel` 未使用。
- 映像 QUIC は `receive_frames` 内で `Connection::new(reg)` → `dial_video(host = video_host FQDN → 127.0.0.1, port = R)`。
  **local / remote とも loopback**。
- `video_client_config` は NAT traversal も observed address 報告も有効化していない。
- `receive_frames` は経路イベントを外へ出す口も、`activate_path` を叩く口も持たない。
- registration も分散している（`camera-client` は `receive_frames(None, ...)` で新規生成、`isekai-p2p-core` は自前の `shared_registration()`、`camera-server` は `main` で生成した 1 個）。

### 1.3 そのままでは migrate できない理由

1. **観測アドレスが取れない** — P2P 側のリレーレグは `ReceiveObservedAddressReports` 未設定で、生 `Connection` も外に出ていない。
2. **公開マッピングを持つバインディングが無い** — `is_unconnected = false` なので、リレーレグの UDP ソケットは接続済みソケットであり共有されない。映像 QUIC 接続がそのバインディングから穴あけパケットを送る手段がない。
3. **映像 QUIC 接続が loopback に閉じている** — クライアントの初期経路は `127.0.0.1 → 127.0.0.1`。直接経路の候補となる実アドレスを一切知らない。
   ただし問題なのは **local が loopback であること**だけで、remote が loopback であること自体は支障にならない（§2.2.1）。
4. **制御の口が無い** — `receive_frames` / `serve_frames` は経路イベントも `activate_path` も外に出していない。
5. **registration が分かれている** — バインディング共有を確実にするには、リレーレグと映像 QUIC が同一 msquic registration 上にあることが望ましい。

---

## 2. 設計方針

### 2.1 基本アイデア：Direct モードの構造を P2P に写す

Direct モードの**サーバ側**は、すでに
「loopback 上の映像接続に、別の実バインディング L_s を `add_bound_addr` で後付けし、その公開マッピング O_s を `add_observed_addr` で広告する」
という形になっている。これは P2P モードのサーバ側とほぼ同じ構造（映像 listener は loopback、リレーレグは別ソケット）なので、**ほぼそのまま移植できる**。

**クライアント側の要点**は、「映像 QUIC の *remote* が loopback（`127.0.0.1:R` = CONNECT-UDP ブリッジソケット）であることと、*local* が loopback であることは無関係」という点にある。
現状は msquic が dial 先に合わせて loopback にバインドしているだけで、**ローカルアドレスを実インタフェースのアドレス L_c に固定したまま `127.0.0.1:R` へ dial できる**（§2.2.1 で実測確認済み）。
したがってクライアントは Direct モードの `connect_direct` と**同一の 2 フェーズ構成**をそのまま使える:

1. リレーへ一時接続して自分の `(L_c, O_c)` を得る、
2. 映像 QUIC 接続のローカルアドレスを L_c に固定して `127.0.0.1:R` へ dial し、`start()` 前に `add_candidate_addr(L_c, O_c)` を呼ぶ。

`add_bound_addr` によるバインディング後付けは**クライアント側では不要**になる。

### 2.2 採用案と代替案

| | 案A: 追加バインディング (`add_bound_addr`) | **案B: ローカルアドレス固定 (`set_local_addr`) ← 採用** |
| --- | --- | --- |
| 映像 QUIC の local | `127.0.0.1:x` のまま | **L_c**（実インタフェース） |
| 映像 QUIC の remote | `127.0.0.1:R` | `127.0.0.1:R`（**変更なし**） |
| 直接経路の生やし方 | `add_bound_addr(L_c)` + `add_candidate_addr(L_c, O_c)` | `add_candidate_addr(L_c, O_c)` のみ |
| 証明書検証 / `video_host` | 影響なし | **影響なし**（dial 先は loopback FQDN のまま。変わるのは local だけ） |
| リレー Forward 先 | 影響なし | **影響なし**（サーバ側 `127.0.0.1:V` のまま） |
| Direct モードとの実装共有 | 別実装が必要 | **`connect_direct` とほぼ同一** |
| 未検証点 | クライアント接続での `add_bound_addr` に実績が無い | 実 IP ⇄ loopback の UDP 疎通（**§2.2.1 で実測済み**）と `set_local_addr` の binding 参加 |

→ **案B を採用**。当初 §2.2 で案B を「dial 先が実 IP になり SNI と解決先の分離が必要」として退けていたが、これは誤りだった。変えるのは **local アドレスだけ**で、dial 先（`video_host` → `127.0.0.1`）は一切変わらないため、証明書検証にもリレーの forward 先にも影響しない。

なお **サーバ側は案A のまま**とする。サーバの公開マッピング O_s は bind レグ H3 接続のローカルポートに対して観測されたものなので、映像 listener 自身のバインディングに読み替えるには結局バインディング共有（= `add_bound_addr`）が要る。ここは Direct モードの実装をそのまま移植する。

> **重要（Phase 0 の実測を受けて）**: 上表の案B（映像接続を L_c に pin する）は **Linux / macOS でのみ成立**する。
> Windows は特定の非 loopback アドレスに bind した socket から `127.0.0.1` へ送信できない
> （`WSAEADDRNOTAVAIL`, §2.2.2）。
> **最終的に採用するのは §2.2.3 の案C** — 映像接続は loopback のまま動かさず、
> `add_candidate_addr` に MASQUE レグの `(L_c, O_c)` を**名指しするだけ**にする。
> `add_candidate_addr` は未 bind のローカルアドレスを受け付けるので pin が要らず、
> Windows が拒む「実 IP → loopback」の送信がどこにも現れない。

#### 2.2.1 実測による裏付け（Linux / 2026-07-30）

案B の前提「実インタフェースのアドレスを local に持ったまま loopback の相手と UDP 疎通できる」を、実際のトポロジ（`run_bridge` の `recv_from` → `last_src` → `send_to` 方式）を模したソケットで検証した。

検証手順:

1. UDP ソケットをリレーのエッジアドレスへ `connect()` してローカルアドレス `L_c` を得る（パケットは飛ばない）→ `192.168.1.59:41241`。ソケットは close。
2. `127.0.0.1:0` にブリッジソケットを bind（= `open_connect_relay` のブリッジ）→ `127.0.0.1:41382`。
3. 別ソケットを **`L_c` に再 bind**（`SO_REUSEADDR` なし）し、`127.0.0.1:41382` へ `connect()`（msquic 既定の connected ソケット相当）。
4. 上り／下りの疎通と、第三者からの受信可否を確認。

結果:

| 確認項目 | 結果 |
| --- | --- |
| probe を close した後に `L_c` へ再 bind できるか | **可**（`SO_REUSEADDR` 不要） |
| 上り: src=`192.168.1.59:41241` → dst=`127.0.0.1:41382` | **到達**。ブリッジ側の `recv_from` は src を `192.168.1.59:41241` として観測 |
| 下り: ブリッジが `last_src`（=実 IP）へ `send_to` | **到達** |
| connected ソケットが第三者（直接経路の相手）からのパケットを受けるか | **受けない**（タイムアウト） |

- 環境: Linux 6.16、`net.ipv4.conf.all.rp_filter = 2`、`net.ipv4.conf.lo.rp_filter = 0`、`net.ipv4.conf.lo.route_localnet = 0`（いずれも既定値のまま。特別なチューニングは不要）。
- `run_bridge`（`rust/channel-masque/src/masque/connect_udp.rs:70`）は送信元アドレスを一切検証せず `last_src` にそのまま追従するため、**ブリッジ側の改修は不要**。
- 4 点目は重要で、**直接経路のパケットを同じソケットで受けるには `set_unconnected_socket(true)` が必須**であることを示す。`msquic-async` のドキュメント上、これは `set_share_binding(true)` が前提。

> 上記は開発機（Linux）での手元計測。プラットフォーム差は §2.2.2 で CI により確認した。

#### 2.2.2 Phase 0 の CI 実測結果（2026-07-30）

`rust/camera-core/examples/migration_spike.rs` を `.github/workflows/migration-spike.yml` で
ubuntu-latest / macos-14 / windows-latest の 3 面に流した結果。スパイクは P2P のリレー経路を
loopback ソケット 2 個のブリッジで再現し、各側の直接経路アドレスは MASQUE レグに見立てた
**別の生存中の共有バインディング**から取る（プロキシもリレーも NAT も無し）。

| # | 問い | Linux | macOS 14 | Windows |
| --- | --- | --- | --- | --- |
| 1 | 実 IP に **アドレス固定**した socket ⇄ loopback の疎通 | PASS | PASS | **FAIL** |
| 1b | **wildcard bind**（ポートのみ固定）で 1 ソケットが両経路を捌けるか | PASS | PASS | **PASS** |
| 2 | `set_local_addr(実IP)` した msquic クライアントが `127.0.0.1` へハンドシェイク | PASS | PASS | **FAIL** |
| 3 | 生存中の共有バインディングへの相乗り（リスク #1b） | PASS | PASS | **FAIL** |
| 4 | `set_local_addr` + `add_candidate_addr` の併用 | PASS | PASS | **FAIL** |
| 5 | サーバ側 `add_bound_addr` / `add_observed_addr` の遅延呼び出し | PASS | PASS | FAIL† |
| 6a | 直接経路の `PathValidated` → `activate_path`（listener 現行設定） | PASS | PASS | FAIL† |
| 6b | 同上（listener に NAT traversal 設定を追加） | PASS | PASS | SKIP |
| **7b** | **[採用] 映像接続を pin せず候補を名指しするだけ**（§2.2.3） | **PASS** | **PASS** | **PASS** |

**確定した答え**

- **リスク #1b は解消**。`set_share_binding(true)` + `set_unconnected_socket(true)` + `set_local_addr(L)` で、
  **生存中の**共有バインディングに 2 本目の接続が相乗りできる（check 3）。
  よって Phase 4-5 は «相乗り方式» を採れ、リスク #13（NAT マッピングが更新されない）も
  リレーレグを L_c 上に生かしておくことで回避できる。
- **`add_candidate_addr` は `set_local_addr` と併用できる**（check 4）。案B の呼び順が成立する。
- **サーバ側の遅延広告は可能**（check 5）。accept 後・データ往復後に現れたバインディングでも
  `add_bound_addr` / `add_observed_addr` とも成功する。P2P の「bind が後から来る」順序に耐える。
- **#59 の caveat は不要だった**（check 6a/6b）。listener は**現行の設定のまま**で直接経路が
  `PathValidated` され、`activate_path` 後もアプリケーションデータが流れ続ける。
  NAT traversal / observed address の設定を listener に足しても結果は変わらない。
  → Phase 3-3（listener 設定のチューニング）は**不要**。
- **Linux では案B が端から端まで成立**している（check 6a が実際に経路を切り替えて往復を確認）。

**Windows: アドレス固定は使えない（新規の重大事項）**

check 1 は Windows で **step 3** — `10.1.0.10:58696` から `127.0.0.1:58698` への送信 — が
`WSAEADDRNOTAVAIL (os error 10049)` で失敗する。Windows では特定の非 loopback アドレスに
bind した socket から `127.0.0.1` へは送信できない。**案B をそのまま Windows に持ち込むことはできない。**

一方 check 1b は **3 プラットフォームすべてで PASS**した。`0.0.0.0:P` に wildcard bind した
1 個のソケットが、

- リレー経路（→ `127.0.0.1:R`）ではカーネルが送信元を `127.0.0.1:P` に選び、
- 直接経路では同じソケットが `<実IP>:P` 宛のデータグラムを受け取る。

この時点では「固定すべきはアドレスではなくポート（wildcard bind）」が移植可能な形に見えたが、
実際にはもっと素直な解があった — **そもそも映像接続を固定しなくてよい**（§2.2.3 の案C）。
なお wildcard は非接続ソケットが受け付けない（`QUIC_STATUS_INVALID_PARAMETER`）ので、
check 1b の形をそのまま msquic に持ち込むことはできない。

Windows の check 2〜6a は msquic レベルでも同じ結論を裏づけた。いずれも
`QUIC_STATUS_CONNECTION_IDLE` でハンドシェイクが成立しない —
`10.1.0.101:P` に pin したクライアントが `127.0.0.1:R` へ dial しても、
OS が送信を拒む（check 1 と同じ `WSAEADDRNOTAVAIL`）ため 1 パケットも出ていかないからである。
**新しい問題ではなく、check 1 の結果が msquic レベルに現れたもの。**

† Windows の check 2〜6a の FAIL は、いずれも check 1 の結果が msquic レベルに現れたもの
（実 IP に pin したクライアントが `127.0.0.1` へ dial しても 1 パケットも出ていかない）。
**採用形の 7b は Windows でも PASS しており**、これらは不採用となった案B の記録として残してある。

> 当初 macOS の check 5 / 6a / 6b も FAIL していたが、原因は**スパイク側のハーネス**だった。
> リレーレグ代役が実 IP に pin したまま *loopback* のプロキシ代役へ dial していた
> （本番の MASQUE レグは実プロキシへネットワーク越しに繋ぐので両端とも実 IP）。
> プロキシ代役を実インタフェースアドレスに移したところ macOS は全項目 PASS になった。
> リスク #15 はこれで解消。

#### 2.2.3 採用: 映像接続は動かさず、候補アドレスだけを名指しする（案C）

§2.2.2 の Windows 問題は、**映像 QUIC 接続を実インタフェースのアドレスに pin したこと**から来ていた。
だが `add_candidate_addr` は、**その時点で bind されていないローカルアドレスでも受け付ける** —
相手から ADD_ADDRESS フレームが届いた時点で、そのローカルアドレスのパスを作る。
したがって映像接続を動かす必要はまったくない:

1. リレーへの MASQUE 接続を `set_share_binding(true)` + `set_unconnected_socket(true)` +
   `set_local_addr(L_c)` で張る（`is_unconnected = true` の `H3MsQuicAsyncConnector` が
   既にやっていること）。そこから `(L_c, O_c)` を得る。
2. 映像 QUIC 接続は **loopback のまま** `127.0.0.1:R` へ dial する。
   ただし `set_share_binding(true)` + `set_unconnected_socket(true)` +
   `set_local_addr(127.0.0.1:0)` は必要（下記 7a/7b）。
3. `add_candidate_addr(L_c, O_c)` で候補を名指しするだけ。

**これが Windows でも成立する形**である。映像接続自身のソケットは loopback に bind されるので
ブリッジと会話でき、直接経路は実 IP ⇄ 実 IP になる。
**実 IP から `127.0.0.1` へ送るという、Windows が拒む操作がどこにも現れない。**

##### 実測（submodule `0d04ccb` / seera-msquic `ddc9b2c`）

| # | 映像接続の bind | Linux | macOS 14 | Windows |
| --- | --- | --- | --- | --- |
| 7a | 素の接続（share / unconnected なし）+ `add_candidate_addr(L_c, O_c)` | FAIL | FAIL | FAIL |
| 7b | `set_share_binding(true)` + `set_unconnected_socket(true)` + `set_local_addr(127.0.0.1:0)` + `add_candidate_addr(L_c, O_c)` | **PASS** | **PASS** | **PASS** |

7a はいずれのプラットフォームでも 15 秒以内に `PathValidated` が来ない。
7b はいずれでも、リレー経路が `127.0.0.1 → 127.0.0.1` のまま直接経路 `L_c → L_s` が検証され、
`activate_path` 後もアプリケーションデータの往復が成立する。
**3 プラットフォームで揃って成立した唯一の形**であり、CI はこの 7b を必須チェックとして
ゲートするようにしてある（案B の前提だった check 1 / 2 は、不採用の記録として残すが
ビルドを落とさない）。

- **共有・非接続ソケットの設定は省略できない**（7a の FAIL）。
- ローカルアドレスは **loopback を明示指定**する。非接続ソケットは
  「具体的な（ワイルドカードでない）ローカルアドレス」を要求するため
  （`0.0.0.0` / `::` は `QUIC_STATUS_INVALID_PARAMETER`）。ポートは 0 でよい。
- submodule の更新（`0d04ccb`）が前提。seera-msquic `ddc9b2c` の
  「unconnected socket の要件を追加パスにも適用」が入る前は、
  `QuicConnOpenNewPath` が後から追加したパスに connected socket を割り当てていた。

##### 案B からの差分（実装への影響）

- クライアントは `set_local_addr(L_c)` **しない**。代わりに `set_local_addr(127.0.0.1:0)`。
- `add_candidate_addr(L_c, O_c)` は変わらず必要。`L_c` は MASQUE レグのアドレス。
- したがって `open_connect_relay` を `unconnected = true` で張り、
  そこから `(L_c, O_c)` を取り出す配線（Phase 1 / 2）が**必須**になる。
  Phase 4-5 の «相乗り方式 vs probe & drop» という選択自体が消え、**相乗り方式一択**になる
  （リレーレグが L_c を保持し続けるので、リスク #13 の NAT マッピング維持も同時に満たす）。
- サーバ側は案A のまま（`add_bound_addr` + `add_observed_addr`）で変更なし。

> 旧 §2.2.3 は「wildcard bind（ポートのみ固定）で Windows を回避する」案を残作業として挙げていたが、
> 案C はそれを不要にする。wildcard は非接続ソケットが受け付けない
> （`QUIC_STATUS_INVALID_PARAMETER`）ので、そもそも採れない筋でもあった。

#### 2.2.4 実プロキシでの端から端までの実測（2026-07-31）

`rust/camera-core/examples/relay_migration_e2e.rs` を
`https://tokyo.link.isekai.tools:8443` に対して実行し、**リレー経路 → 直接経路の切り替えが
成立することを確認**した（3 回連続で PASS）。

```
relay path:  127.0.0.1:58441 -> 127.0.0.1:60205      … 5 フレーム受信
direct path: 192.168.1.59:46316 -> 192.168.1.59:47220 … PathValidated
activated:   192.168.1.59:46316 -> 192.168.1.59:47220 … 切替後さらに 5 フレーム受信
```

観測アドレスは両レグとも取得できた（クライアント `192.168.1.59:46316` →
`42.125.235.37:46316`、サーバ `192.168.1.59:47220` → `42.125.235.37:47220`。
このプロバイダの NAT はポートを保存する）。

##### 判明した追加要件: ホスト候補も広告する

最初の実行では、機構がすべて動いている（両レグの observed 取得、`add_candidate_addr`、
サーバの `add_bound_addr` / `add_observed_addr`）にもかかわらず、
**30 秒待っても `PathValidated` が来なかった**。

原因は NAT のヘアピン非対応だった。独立に計測して確定させた:

| 送信 | 結果 |
| --- | --- |
| `192.168.1.59:A` → `192.168.1.59:B`（LAN 内） | 到達 |
| `192.168.1.59:A` → `42.125.235.37:B`（自分の公開アドレス宛 = ヘアピン） | **失敗（タイムアウト）** |

観測アドレスだけを広告していると、相手はそれ（＝自分たちの公開アドレス）へ穴あけを試みる。
同一 NAT 配下の 2 ピアではこれはヘアピンを要求し、大半の NAT は落とす。

対策として **ホストアドレス自体も候補として広告**するようにした
（ICE の host candidate + server-reflexive candidate に相当）:

- クライアント: `add_candidate_addr(local, observed)` に加えて `add_candidate_addr(local, local)`
- サーバ: `add_observed_addr(local, observed)` に加えて `add_observed_addr(local, local)`

`local == observed`（NAT 無し）のときは重複するので追加しない。
インターネット越しではホスト候補は検証に失敗し、観測アドレス側が採用されるだけなので、
**この追加に不利益はなく、同一 LAN では最短経路が取れる**という利点だけがある。

##### この実測が示していないこと

両ピアが同一ホストで動いているため、**NAT 越えの穴あけそのものは検証できていない**。
成立した直接経路は LAN アドレス間のものである。別ネットワーク間（§6.2 の環境マトリクス）は
実機 2 台での確認が必要で、未実施のまま残る。

#### 2.2.5 実機で判明した不具合と、その修正（2026-07-31 〜 08-01・解決済み）

Windows 実機（クライアント・サーバを同一マシンで実行、同一 LAN）で、
**直接経路への切り替えは成功するのに、切り替えた瞬間から双方向とも無通信になる**現象が発生した。
最終的に `QUIC_STATUS_CONNECTION_TIMEOUT` で接続が落ちる。

##### 症状（カウンタで確認）

| 観測 | 意味 |
| --- | --- |
| 切替後 `local/remote` が直接経路のペアに変化 | 切り替え自体は成功 |
| クライアントの `recv_packets` が完全に凍結 | 切替後に 1 パケットも受信していない |
| `send_packets` はごく僅かに増えるのみ | PTO 再送だけが出ている |
| `rtt_us=333000` で固定 | msquic の新規パス初期推定値。**一度も ACK されていない** |
| サーバも約 0.8 秒後に直接経路へ追随し、同様に停止 | 片側取り残しではない |
| `send_path_mtu` は前後で不変 | MTU は無関係 |

##### 原因（msquic ETW トレースで確定）

```
[bind] DROP packet Dst=192.168.1.223:59176 Src=192.168.1.223:55052
       Dest CID=0x0CF2A1F7F9DE78131F Reason=No matching client connection.
```

送信は正常で、パケットはホスト内を直接届いている。しかし**受信側のバインディングの
接続テーブルに宛先 CID が無く**、そこで破棄されていた。

seera-msquic 側の不具合であり、`910edff`（「Keep source connection IDs while a shared
binding is still in use」）で修正された。非接続バインディングはローカルポートだけで一致するため
一つの接続の複数パスが同じバインディングを共有するが、
`QuicConnProcessPathValidationTimerOperation` はパスを破棄するたびに
`QuicBindingRemoveAllSourceConnectionIDs` を呼んでおり、
他のパスがそのバインディングを保持しているかを見ていなかった。
結果、生きているパスが黙って受信できなくなっていた。

submodule を `msquic-async-rs` `9797d17` へ更新して適用済み。
**Windows 実機で直接経路の疎通を確認**（切替後もフレームが届き続ける）。

##### 設計は案C のまま

修正により、**リレーレグのバインディングを直接名指しする形（§2.2.3 の案C）がそのまま使える**。
クライアント側の 3 つの設定（`set_share_binding` / `set_unconnected_socket` /
`set_local_addr(127.0.0.1:0)`）は**直接経路が検証されるための必須条件**であり、
一つでも欠けると `PathValidated` 自体が上がらないことを実機で確認した。

##### 調査の過程で否定した仮説（記録）

ファイアウォール、フレームサイズ（30 KB）、候補が 2 つあること、候補の順序、
2 プロセスであること、`MaximumMtu(1200)`、`DestCidUpdateIdleTimeoutMs`、
`serve_frames_with` / `receive_frames_with` の実装、レグのバインディングを避けること
（probe & drop）。いずれも実機または Windows CI で否定された。

> 途中、`ISEKAI_MIGRATION_NO_CANDIDATE=1` で「映像が流れ続けた」ことを
> 「msquic 自前のバインディング上なら動く」と解釈し、そこから probe & drop 方式を実装したが、
> **これは誤読だった**。この設定では `DirectValidated` が上がらず migration 自体が起きておらず、
> 映像はリレー経路のまま流れていただけである。probe & drop は Windows で FAIL し、撤去した。
> 以後の検証では「Migrate ボタンが押せるか」と「押した後フレームが届くか」を分けて確認している。

##### 併せて入れた堅牢性: 自動フォールバック

原因とは独立に、**切り替えに失敗したときに接続ごと死ぬのは誤り**なので、
リレー経路から離れたあと `MIGRATED_PATH_GRACE`（5 秒）フレームが来なければ
自動でリレー経路へ戻すようにした。フレームが届くたびにタイマーはリセットされ、
リレー経路へ**戻る**移行は監視対象外。実機で期待どおり動作している。

計画書 §0 の「直接経路が取れない環境ではリレー経路のまま動き続ける」という要件そのものでもある。

##### 併せて入れた診断

`camera-core` の映像接続と `isekai-p2p-core` のリレーレグが、それぞれ毎秒
`local/remote` / RTT / `Send.PathMtu` / 送受信・ロストのカウンタを `debug` で出す。
今回の切り分けはこれ無しでは不可能だった。既定では出ないので残す。

##### 未解決（別件）

- `send_path_mtu` が一貫して **1248** で、`video_client_config` の `set_MaximumMtu(1200)` は
  msquic の既定 `MinimumMtu`（1248）に押し上げられて**効いていない**。
  リレートンネルに収める意図が達成されていないので `set_MinimumMtu` を明示して直すべき。
- 実機のリレー経路で `send_lost` が送信の約 18% に達していた。
  リレー経路自体は動作しているが、映像品質に効くので別途調査する価値がある。

---

## 3. 実装フェーズ

各フェーズは独立して `cargo check --workspace --examples` が通り、既定の挙動を変えない（オプトイン）ことを条件とする。

### Phase 0 — 前提整備と API セマンティクスの検証（spike）  … **完了**

**状況**: `rust/camera-core/examples/migration_spike.rs` +
`.github/workflows/migration-spike.yml` で自動化し、実測済み（結果は §2.2.2 / §2.2.3）。
Windows でスパイクを完走させるための PKCS#12 dev 証明書は対応済み
（`camera_core::tls::DevCert::pkcs12`, Windows 限定）。
**設計上の未解決点は無くなり、採用形は §2.2.3 の案C に確定**（3 プラットフォームで実測 PASS）。
リスク #15 も解消済み。**Phase 0 は完了**で、Phase 1 に進める。

**作業**

1. `git submodule update --init --recursive` で submodule を記録コミットに戻す。
   現在の作業ツリーは `msquic-async-rs` が `0644856-dirty`（記録は `b8a3111`）、`tonic-h3` が `e470be8`（記録は `a68d128`）で**ずれており、`is_unconnected` を含むコードがそもそも入っていない**。
2. **クライアント側（案B）の未検証点**を小さな msquic テストで確認する。
   - `set_local_addr(L_c)` を `start()` 前に呼んだ映像 QUIC 接続が、**remote = `127.0.0.1:R`** で正常にハンドシェイクできるか
     （OS レベルの疎通は §2.2.1 で確認済み。ここで見るのは msquic がその組み合わせを許すか）。
   - `set_share_binding(true)` + `set_unconnected_socket(true)` + `set_local_addr(L_c)` で、**生存中の**リレーレグ H3 接続のバインディングに
     **相乗りできるか**（`QuicLibraryGetBinding` が既存の共有バインディングを返すか）。できない場合は §3-Phase 4 の «probe & drop» 方式にフォールバックする（NAT マッピング維持とのトレードオフは §7-13）。
   - `add_candidate_addr(host, observed)` の `HostAddress` の意味（「host に bind せよ」なのか「既存バインディング host の公開マッピングが observed」なのか）。
     Direct モードは Phase 1 接続を drop してから同じ `local_address` を渡しており前者寄りに見えるが、案B ではすでに `set_local_addr` で bind 済みなので後者として振る舞う必要がある。
3. **サーバ側（案A）の未検証点**。
   - `add_bound_addr` / `add_observed_addr` が **ハンドシェイク完了後**にも呼べるか（P2P はリレー bind が後から来るためレースがある）。
   - loopback バインディングと実バインディングを 1 接続が同時に持てるか、その状態で `activate_path` が両方向に効くか。
   - #59 の caveat「listener 側の NAT traversal / address discovery チューニングが要るかもしれない」の実際の要否。
4. P2P モードで `udp_mode = "dedicated"` 相当の設定が必要かを確認する。P2P の bind レグは `seera-prefer-temporary-public-address: ?1` を送っており、Direct モード（#58）とは別経路。
5. §2.2.1 の実測を **Windows / macOS / iOS** でも再現する（§7-12）。

**受け入れ条件**: 上記の回答がドキュメント化され、案B（クライアント）+ 案A（サーバ）が成立することが確認できている。クライアント側が成立しない場合は案A（`add_bound_addr`）へ、サーバ側が成立しない場合は §2.5 の制御プレーン方式へ切り替える判断をここで行う。

### Phase 1 — `isekai-p2p-core`: 観測アドレスの取得基盤

**変更ファイル**: `rust/isekai-p2p-core/src/transport.rs`, `rust/isekai-p2p-core/src/bind.rs`, 新規 `rust/isekai-p2p-core/src/observed.rs`

1. `make_client_config` に `.set_ReceiveObservedAddressReports()` を追加（h3 / h3qx-01 両方）。
2. `RelayOptions` を新設（§4.1）。`open_bind_session` / `open_connect_relay` に `opts: RelayOptions` 引数を追加し、
   - `opts.registration` があれば `make_client_config` に渡す、
   - `opts.unconnected` を `H3MsQuicAsyncConnector::new` の `is_unconnected` に渡す、
   - 生 `Connection` を `with_channel(conn_tx)` で受け取る。
3. 新規 `observed.rs`: `spawn_observed_address_watch(conn_rx, shutdown) -> watch::Receiver<Option<(SocketAddr, SocketAddr)>>`。
   `poll_event` を回して `NotifyObservedAddress` を watch に publish する（Direct モードの `camera-server` にあるループの共通化）。
   `msquic_async::Connection` を外へ漏らさず、`SocketAddr` の組だけを公開するのが要点。
4. `BindSession` / `ConnectRelay` に `pub fn observed(&self) -> watch::Receiver<Option<(SocketAddr, SocketAddr)>>` を追加。

**受け入れ条件**: 既存呼び出し元（`isekai-agent`, examples）は `RelayOptions::default()`（= 現状と同じ挙動）でコンパイルが通る。

### Phase 2 — `isekai-p2p`: セッション API への露出

**変更ファイル**: `rust/isekai-p2p/src/listener.rs`, `rust/isekai-p2p/src/initiator.rs`

1. `InitiatorSession::connect_with_options(...)` / `ListenerSession::create_with_options(...)` を追加し、既存の `connect` / `connect_with_token` / `create` / `create_with_token` はデフォルトオプションで委譲する薄いラッパにする（**既存呼び出し元は無改修**）。
2. 両セッションに `pub fn observed_address(&self) -> watch::Receiver<Option<(SocketAddr, SocketAddr)>>` を追加。
   - `ListenerSession` はセッション寿命の `watch::Sender` を持ち、`bind()` のたびに新しい bind レグの watch を中継する（再 bind をまたいで受信側の `Receiver` が生き続けるようにする）。
3. `ListenerSession::bind()` の `drain_bind_events` は observed watch の publish も担う。

**受け入れ条件**: `camera-core` の examples（`relay_e2e`, `relay_gap_e2e`, `synthetic_server`）が無改修で通る。

### Phase 3 — `camera-core` サーバ側: 直接経路の広告

**変更ファイル**: `rust/camera-core/src/server.rs`, `rust/camera-core/src/video.rs`

1. `spawn_p2p_server` が `ListenerSession::create_with_options` を使い、
   `RelayOptions { unconnected: true, registration: Some(video_reg.clone()) }` を渡す。
   （registration は `bind_video_listener` が返すものと同一にする＝§2.4）
2. `serve_frames` に観測アドレスの watch を渡せるようにする（§4.2）。accept した各接続に対し:
   - watch に値があれば即 `add_bound_addr(L_s)` / `add_observed_addr(L_s, O_s)`、
   - まだ無ければ小タスクを spawn して `changed().await` 後に適用（**bind が accept より後に来るレースへの対応**）、
   - 失敗はログのみ（Direct モードと同じく致命的にしない）。
3. ~~`make_msquic_async_listener` 側の設定に NAT traversal 相当を追加~~ — **不要**。
   §2.2.2 の check 6a/6b で、listener は現行設定のまま直接経路が検証されることを確認した（#59 の caveat は空振り）。

**受け入れ条件**: P2P モードのサーバがリレー経由で従来どおり配信でき、ログに `observed address reported: ...` と `add_observed_addr` の成功が出る。

### Phase 4 — `camera-core` クライアント側: 候補登録と経路制御

**変更ファイル**: `rust/camera-core/src/video.rs`

1. `video_client_config(reg, verify, enable_natt)` に拡張。`enable_natt` のとき
   `.set_ReceiveObservedAddressReports()` と `.set_AddAddressMode(AddAddressMode::NatTraversal)` を付ける。
2. `receive_frames_with(host, port, frame_tx, shutdown, opts: VideoRecvOptions)` を新設（§4.3）。既存 `receive_frames` はデフォルトオプションで委譲。
3. 内部フロー（**案B**。Direct モードの `connect_direct` と同型）:
   - `opts.observed` が指定されていれば、**dial 前に**最大 `OBSERVED_ADDR_WAIT`（既定 3 秒）だけ観測アドレス `(L_c, O_c)` を待つ。
     取れなければ警告ログのみでリレー専用として続行（**フォールバック必須**）。
   - `Connection::new()` 後、`start()` の**前**に:
     1. `set_share_binding(true)`
     2. `set_unconnected_socket(true)` — 直接経路のパケットを同じソケットで受けるために必須（§2.2.1 の 4 点目）
     3. `set_local_addr(L_c)` — ローカルアドレスを実インタフェースに固定。**dial 先は `video_host` → `127.0.0.1:R` のまま**
     4. `add_candidate_addr(L_c, O_c)`
   - `add_bound_addr` はクライアント側では**呼ばない**。
   - `dial_video` 成功後、`(get_local_addr, get_remote_addr)` を `PathEvent::Relay` として通知。
     このとき local は `L_c`、remote は `127.0.0.1:R` になるはず（ログで必ず確認する）。
   - 受信ループを `tokio::select!` に拡張し、Direct モード (`connect_direct`) と同型にする:
     - `conn.poll_event` → `PathValidated` が初期経路と異なれば `PathEvent::DirectValidated` を通知、
     - `opts.migrate` 受信 → `conn.activate_path(local, remote)`、
     - 1 秒周期の `conn.get_stats()` → `opts.rtt` へ RTT(ms) を送出、
     - 既存の `accept_inbound_uni_stream` によるフレーム受信。
4. `dial_video` の長期ハンドシェイク（`HandshakeIdleTimeoutMs = 60_000`）と NAT traversal の相互作用に注意。リレーレグ確立待ちのリトライ経路では、`Connection` を作り直すたびに 3 の 1〜4 をやり直すこと。
5. **L_c を誰が押さえるか**（Phase 0-2 の結論で分岐）:
   - **推奨（相乗り方式）**: `open_connect_relay` を `unconnected = true` で張り、その H3 接続が L_c を保持し続ける。映像 QUIC は同じ L_c に相乗りする。
     H3 接続がプロキシへ通信し続けるので **L_c の NAT マッピングが維持される**（P2P では映像トラフィックが全て loopback で、NAT を一切通らないため、これが無いとマッピングが失効しうる。§7-13）。
   - **フォールバック（probe & drop 方式）**: Direct モードと同じく一時接続で `(L_c, O_c)` を得てから drop し、映像 QUIC が L_c を bind し直す。実装は単純だが NAT マッピング失効のリスクを負う。

**受け入れ条件**: P2P モードで従来どおり受信でき、`PathEvent::Relay` が出る。直接経路が張れる環境では `PathEvent::DirectValidated` が出る。

### Phase 5 — GUI 配線

**変更ファイル**: `rust/camera-client/src/main.rs`, `rust/camera-server/src/main.rs`

`camera-client`:
1. `MyApp` に `reg: Arc<Registration>` を追加し、Direct / P2P 双方で使い回す（§2.4）。
2. `connect_p2p` で `mpsc`/`watch` を作り `receive_frames_with` に渡す。既存の
   `is_isekai_link` / `isekai_link_path` / `p2p_path` / `migrate_tx` / `rtt_rx` を **モード共通の状態**に格上げする（現状は Direct 専用のコメントが付いている）。
3. Migrate ボタンの `self.mode == Mode::Direct` 条件を外し、両モードで「両経路が判明したら有効」にする。
4. RTT グラフを P2P モードでも描画（現状は Direct のみ RTT を流している）。
5. `disconnect()` の後始末に P2P 側の新チャネルを追加。

`camera-server`:
6. `p2p_status_ui` に観測アドレスと「クライアント接続に直接経路を広告したか」を表示（デバッグ性のため）。

**受け入れ条件**: P2P モードで接続 → ボタンが活性化 → 押下で RTT グラフが段差を作って下がる（直接経路のほうが低 RTT）。もう一度押すとリレー経路に戻る。

### Phase 6 — 検証・調整・ドキュメント  … **完了**

- §7 のリスク項目を棚卸しした。#2 / #5 / #6 / #7 / #10 / #11 / #16 は解消、
  #3 / #18 は対応済み、#17 / #19 が未解決として残る。
- `docs/Build.md` に「6. P2P mode and path migration」を追加
  （4 値の受け渡し手順、migrate の操作、直接経路が成立する条件、
  ログの読み方、トラブルシュート 2 件）。`README.md` には機能として 1 行追記。
- §6.2 の環境マトリクスを実測で埋めた。

**残った未解決事項**:

1. リレー経路の損失率（§7-19）。今回のスコープ外だが映像品質に効く。
2. 対称 NAT / CGNAT 環境での挙動（想定どおりリレー継続になるかの確認）。
3. 別ネットワーク間での RTT 改善の実測（§6.2）。

`MaximumMtu` の件（§7-7）は Phase 6 内で、
NAT 越えの検証（§7-17）は 2026-08-01 の実機 2 台試験で解消した。

### Phase 7（任意・後続）

- `isekai-client-ffi` に経路状態と migrate 操作を露出（UniFFI の enum/callback 追加）。
- §2.5 の制御プレーン candidates 方式の併用（対称 NAT 環境での候補追加）。
- RTT に基づく自動 migration。

---

## 4. API 変更案

### 4.1 `isekai-p2p-core`

```rust
// isekai-p2p-core/src/bind.rs（または新規 options.rs）

/// リレーレグ（bind / connect）の張り方。既定は現状どおりの挙動。
#[derive(Clone, Default)]
pub struct RelayOptions {
    /// 共有・非接続ソケットでレグを張る（= 経路 migration の前提）。
    pub unconnected: bool,
    /// 全接続で共有する msquic registration。None なら内部の共有 registration。
    pub registration: Option<Arc<msquic_async::Registration>>,
}

pub async fn open_bind_session(
    target: &str, endpoint_token: &str, key: &EndpointKey,
    connection_id: &str, forward_to: SocketAddr,
    opts: RelayOptions,                                   // ← 追加
) -> anyhow::Result<BindSession>;

pub async fn open_connect_relay(
    proxy_url: &str, endpoint_token: &str, key: &EndpointKey,
    connection_id: &str, masque_uri: &str, local_bind: SocketAddr,
    opts: RelayOptions,                                   // ← 追加
) -> anyhow::Result<ConnectRelay>;

impl BindSession   { pub fn observed(&self) -> watch::Receiver<Option<(SocketAddr, SocketAddr)>>; }
impl ConnectRelay  { pub fn observed(&self) -> watch::Receiver<Option<(SocketAddr, SocketAddr)>>; }
```

> 引数追加は破壊的変更になるが、呼び出し元は `isekai-p2p` の 2 箇所のみ（`listener.rs` / `initiator.rs`）なので影響は小さい。

### 4.2 `camera-core` サーバ側

```rust
// camera-core/src/video.rs
pub struct ServeOptions {
    /// 自分のリレーレグが報告した (local, observed)。accept した接続に
    /// add_bound_addr / add_observed_addr で適用し、直接経路を広告する。
    pub observed: Option<watch::Receiver<Option<(SocketAddr, SocketAddr)>>>,
}

pub async fn serve_frames_with(
    listener: Listener,
    frame_rx: mpsc::Receiver<Bytes>,
    shutdown: CancellationToken,
    opts: ServeOptions,
);
// 既存 serve_frames は ServeOptions::default() で委譲
```

### 4.3 `camera-core` クライアント側

```rust
// camera-core/src/video.rs

/// 映像 QUIC 接続の経路イベント。
#[derive(Debug, Clone, Copy)]
pub enum PathEvent {
    /// 接続確立直後の経路（= リレー経路）。
    Relay { local: SocketAddr, remote: SocketAddr },
    /// リレー経路と異なる経路が検証された（= 直接経路）。
    DirectValidated { local: SocketAddr, remote: SocketAddr },
    /// activate_path が成功した。
    Activated { local: SocketAddr, remote: SocketAddr },
}

#[derive(Default)]
pub struct VideoRecvOptions {
    pub registration: Option<Arc<Registration>>,
    pub verify: bool,
    /// 自分のリレーレグが報告した (local, observed) = (L_c, O_c)。あれば dial 前に
    /// set_local_addr(L_c) + add_candidate_addr(L_c, O_c) を行う（案B, §2.2）。
    pub observed: Option<watch::Receiver<Option<(SocketAddr, SocketAddr)>>>,
    /// 経路イベントの通知先。
    pub path_events: Option<mpsc::Sender<PathEvent>>,
    /// 経路切替の指示（(local, remote) をそのまま activate_path に渡す）。
    pub migrate: Option<mpsc::Receiver<(SocketAddr, SocketAddr)>>,
    /// 1 秒ごとの RTT サンプル（ミリ秒）。
    pub rtt: Option<mpsc::Sender<f64>>,
}

pub async fn receive_frames_with(
    host: &str, port: u16,
    frame_tx: mpsc::Sender<(u64, Bytes)>,
    shutdown: CancellationToken,
    opts: VideoRecvOptions,
) -> anyhow::Result<()>;
// 既存 receive_frames(reg, host, port, verify, tx, shutdown) は
// VideoRecvOptions { registration: reg, verify, ..Default::default() } で委譲
```

> `migrate` を `(SocketAddr, SocketAddr)` の生値にしておくと、`camera-client` 側の
> `migrate()` を Direct / P2P で完全に共通化できる（既存の `migrate_tx` と同じ型）。

### 4.4 影響を受ける既存呼び出し元

| ファイル | 対応 |
| --- | --- |
| `rust/camera-client/src/main.rs` | Phase 5 で改修 |
| `rust/camera-server/src/main.rs` | Phase 5 で改修（Direct 側は不変） |
| `rust/isekai-client-ffi/src/lib.rs` | ラッパ経由で無改修（Phase 7 で拡張） |
| `rust/isekai-p2p/src/bin/isekai-agent.rs` | `connect_with_token` のまま無改修 |
| `rust/camera-core/examples/{relay_e2e,relay_gap_e2e,synthetic_server}.rs` | 無改修 |
| `rust/camera-core/tests/video_loopback.rs` | 無改修（ラッパ維持の回帰テストとして機能） |

---

## 5. データフロー（変更後・P2P モード）

```
[camera-client]  … 案B                              [camera-server]  … 案A
 InitiatorSession                                    ListenerSession
   └ connect leg (H3, unconnected, binding L_c)        └ bind leg (H3, unconnected, 共有binding L_s)
        │ NotifyObservedAddress → (L_c, O_c)                 │ NotifyObservedAddress → (L_s, O_s)
        ▼ watch                                              ▼ watch
 receive_frames_with                                  serve_frames_with
   set_share_binding(true)                              accept ごとに
   set_unconnected_socket(true)                           add_bound_addr(L_s)
   set_local_addr(L_c)   ← local だけ固定                  add_observed_addr(L_s, O_s)
   add_candidate_addr(L_c, O_c)
        │
        ▼
  ┌── リレー経路: L_c → 127.0.0.1:R ─ MASQUE ─ proxy ─ MASQUE ─ 127.0.0.1:F → 127.0.0.1:V
  │              ^^^ 実 IP → loopback（§2.2.1 で疎通確認済み）
  └── 直接経路:   L_c → O_s  /  L_s → O_c        （NAT traversal で穴あけ後 PathValidated）
                     ▲
                     └ UI ボタン → activate_path(local, remote)
```

---

## 6. 検証計画

### 6.1 自動テスト

- `camera-core/tests/video_loopback.rs` — 既存。ラッパ API が壊れていないことの回帰。
- 新規ユニットテスト: `PathEvent` の判定ロジック（「初期経路と異なる `PathValidated` を直接経路とみなす」）を、`SocketAddr` の組を渡す純関数に切り出して単体テスト可能にする。
- `cargo check --workspace --examples` を各フェーズの完了条件に含める。

### 6.2 手動 E2E（実プロキシ必須）

`camera-core/examples/relay_e2e.rs` を雛形に `relay_migration_e2e.rs` を追加し、
「直接経路が検証されたら migrate → フレームが途切れないことを確認 → 戻す」を自動化する（実環境依存のため CI 対象外）。

**環境マトリクス**（2026-08-01 時点の実測）:

| 構成 | 直接経路の検証 | migrate 後のフレーム継続 | 備考 |
| --- | --- | --- | --- |
| 同一ホスト（Windows 実機、両アプリ同居） | **成立** | **継続** | 直接経路は LAN アドレス同士。seera-msquic `910edff` 適用後 |
| 同一ホスト（Linux、`relay_migration_e2e`） | **成立** | **継続** | 30 KB フレームでも確認。複数回再現 |
| 同一ホスト（Phase 0 スパイク, Linux / macOS / Windows） | **成立** | **継続** | プロキシ無しの単純化トポロジ。CI で常時実行 |
| **別ネットワーク（実機 2 台）** | **成立** | **継続** | **2026-08-01 実測。NAT 越えの穴あけが実際に成功した** |
| 別 NAT（symmetric） | 未検証 | 未検証 | 仕様上は不成立の見込み（リレー継続） |
| CGNAT | 未検証 | 未検証 | 同上 |

**別ネットワークに置いた実機 2 台で、Migrate ボタンが有効になり（＝直接経路が検証され）、
切り替え後もデータ送信が継続することを確認した。**
これで本計画の中核 — 「リレー経路で確立した接続を、NAT 越えの直接経路へ切らずに移す」 —
が実環境で成立することが実証された。同一ホストでの確認とは違い、
ここでは実際に双方の NAT を貫通している。

残るのは対称 NAT と CGNAT で、いずれも仕様上は不成立が想定される
（その場合はリレー経路のまま動作を継続する。§0 の非目標どおり）。

RTT の低下は未記録。同一ホストでは差が出ないため計測に意味が無かったが、
別ネットワーク間なら本来ここに効果が出るはずで、次に機会があれば記録したい。

### 6.3 観測ポイント

- `camera-client` の RTT グラフ（migrate の前後で段差が出るのが最も分かりやすい受け入れ信号）。
- ログ: `observed address reported`, `Validated P2P path`, `Migrating to path`, `Failed to activate path`。
- 既存の `proxy_*.log` / `relay_*.log` と突き合わせ、リレーエッジのトラフィックが migrate 後に止まる（＝本当に直接経路に移った）ことを確認する。

---

## 7. リスクと未確定事項

| # | 項目 | 影響 | 対策 |
| --- | --- | --- | --- |
| 1 | 実 IP を local、loopback を remote とする UDP 疎通の可否 | 案B が成立しない | **§2.2.1 で Linux 実測済み（成立）**。他 OS は §7-12 |
| 1b | ~~`set_local_addr` で**生存中の**共有バインディングに相乗りできるか~~ | — | **解消**: §2.2.2 check 3 で Linux / macOS とも相乗り可を確認。«相乗り方式» を採用 |
| 2 | ~~サーバ側で loopback バインディングと実バインディングの混在時の msquic の経路選択~~ | — | **解消**: 実機ログで両側の `(local, remote)` を毎秒記録するようにし、意図どおりの経路になっていることを確認 |
| 3 | 観測アドレスが来ない（プロキシが OBSERVED_ADDRESS を送らない / qmux フォールバックに落ちた） | migrate 不可 | **対応済み**: `OBSERVED_ADDRESS_WAIT`（3 秒）待って来なければリレー専用で継続。UI は Direct path 行を `not available` のまま表示し、Migrate ボタンは無効 |
| 4 | 対称 NAT では穴あけ不可 | 直接経路が張れない | 仕様上の制約として明示。リレー継続で機能低下なし |
| 5 | ~~bind タイミングのレース（accept が bind より先に来る）~~ | — | **解消**: セッション寿命の `watch` + 遅延適用タスクで実装。実機では bind が accept より後に来る順序が常態で、正しく広告されている |
| 6 | ~~registration 分散によりバインディング共有が効かない~~ | — | **解消**: `camera-client` / `camera-server` とも 1 プロセス 1 registration に統一済み（§2.4） |
| 7 | ~~`MaximumMtu(1200)` がそもそも効いていない~~ | — | **解消**: msquic は `QUIC_DPLPMTUD_MIN_MTU`（1248）未満の `MaximumMtu` を黙って 1248 に切り上げる（`core/settings.c`）。実測の `send_path_mtu` と一致。コードを `set_MaximumMtu(1248)` に改め、実際に適用される値を明示した（挙動は不変）。上限を掛ける目的自体は達成されている（既定の 1500 は使われない） |
| 8 | TLS は接続確立時のもので経路変更後に再検証されない | セキュリティ上の誤解 | 仕様として明記。`video_host`（loopback FQDN）証明書のまま直接経路を通るのは QUIC の設計どおり |
| 9 | submodule のチェックアウトが記録コミットとずれている | そもそもビルドできない | Phase 0-1 で `git submodule update --init --recursive` |
| 10 | ~~P2P モードで `udp_mode = dedicated` 相当が要るか不明~~ | — | **不要**: 設定せずに実機で直接経路が成立している。P2P の bind レグは `seera-prefer-temporary-public-address` を使う別経路で、Direct モード（#58）とは無関係 |
| 11 | ~~`dial_video` のリトライで `Connection` を作り直す~~ | — | **解消**: `dial_video` が試行ごとに `prepare_for_migration` を呼び直す |
| 12 | **Windows ではアドレス固定が使えない**（`WSAEADDRNOTAVAIL`） | 案B をそのまま Windows に持ち込めない | **解消**: §2.2.3 の案C（映像接続を pin せず候補を名指しするだけ）に切り替え。実 IP → loopback の送信が発生しなくなる |
| 13 | P2P では映像トラフィックが全て loopback を通り、**L_c の NAT マッピングが更新されない** | 穴あけ時にマッピングが失効・再割当されている | 相乗り方式でリレーレグ H3 接続に L_c を維持させる（Phase 4-5）。§2.2.2 check 3 でその方式が使えることを確認済み |
| 14 | `set_unconnected_socket` は `set_share_binding(true)` が前提（msquic-async のドキュメント） | 呼び順を誤ると `QUIC_STATUS_INVALID_STATE` | Phase 4-3 の順序（share → unconnected → local_addr → candidate）を厳守。§2.2.2 check 2/4 でこの順序が通ることを確認済み |
| 15 | ~~macOS でスパイクの check 5 / 6 がリレーレグ代役のハンドシェイク失敗で落ちる~~ | — | **解消**: 原因はハーネスだった（リレーレグ代役が実 IP に pin したまま loopback のプロキシ代役へ dial していた）。プロキシ代役を実アドレスに移し、macOS は全項目 PASS |
| 16 | ~~共有バインディング上の経路が検証は通るのにデータを運ばない~~ | — | **解消**: seera-msquic `910edff`。詳細は §2.2.5 |
| 17 | ~~NAT 越えの穴あけが未検証~~ | — | **解消**: 2026-08-01、別ネットワークに置いた実機 2 台で直接経路の検証と切替後のデータ継続を確認（§6.2） |
| 18 | 直接経路が無通信になったときに接続ごと落ちる | 映像が止まり復帰しない | **対応済み**: 5 秒フレームが来なければ自動でリレー経路へ戻す。実機で動作確認済み |
| 19 | リレー経路で `send_lost` が送信の約 18% に達する | 映像品質の低下 | **未解決（別件）**: 経路自体は動作しているが、CONNECT-UDP トンネルでの損失として別途調査の価値がある |

---

## 8. PR 分割と作業順序

| PR | 内容 | 対応フェーズ | 依存 |
| --- | --- | --- | --- |
| 0 | submodule 同期 + seera-msquic セマンティクス調査メモ | Phase 0 | — |
| 1 | `isekai-p2p-core`: `ReceiveObservedAddressReports` / `RelayOptions` / observed watch | Phase 1 | 0 |
| 2 | `isekai-p2p`: `*_with_options` + `observed_address()` | Phase 2 | 1 |
| 3 | `camera-core` サーバ側: `serve_frames_with` + `spawn_p2p_server` の unconnected 化 | Phase 3 | 2 |
| 4 | `camera-core` クライアント側: `receive_frames_with` + NAT traversal 設定 | Phase 4 | 2 |
| 5 | GUI 配線（`camera-client` / `camera-server`） | Phase 5 | 3, 4 |
| 6 | E2E example + 実測結果の反映 + ドキュメント更新 | Phase 6 | 5 |
| 7 | （任意）iOS FFI 露出 / 制御プレーン candidates / 自動 migration | Phase 7 | 6 |

PR 1〜4 はいずれも「既定の挙動を変えない」ため、途中で止めても `main` は安全な状態を保つ。

---

## 9. 参考コミット

- `ac85311` (#56) — camera-server がリレーから observed address を受け取る（`set_ReceiveObservedAddressReports` + `create_masque_channel` の `conn_tx`）。
- `e6a1632` (#57) — `is_unconnected` モードの導入（`set_share_binding` + `set_unconnected_socket` + `set_local_addr`）。submodule バンプ含む。
- `484a739` (#58) — camera-server がリレーに専用 UDP ポートを要求（`/udp_mode`）。
- `427d963` (#59) — Direct モードの経路 migration（クライアントの 2 フェーズハンドシェイク、`add_candidate_addr` / `add_bound_addr` / `add_observed_addr` / `PathValidated` / `activate_path`、Migrate ボタン）。
- `docs/p2p_library_plan.md` — P2P セッション API（`InitiatorSession` / `ListenerSession`）の設計背景。
