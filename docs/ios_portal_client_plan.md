# portal-client iOS 版 実装計画書

`portal-client`（NAT の向こうの TCP/UDP サービスを、手元のポートに引き出す側）を
iOS ネイティブアプリとして実装するための計画書。

デスクトップ版と同じ Rust コア（P2P / QUIC / MASQUE / portal のフレーミング）を
共有ライブラリとして再利用し、UI・鍵保管・認証を iOS ネイティブで実装する。
`docs/ios_camera_client_plan.md` と同じ方針であり、**同じ道が既に一度通っている**
ことが本計画の最大の前提である（§1）。

---

## 0. 結論を先に — この移植で難しいのは QUIC ではない

デスクトップの `portal-client` は 2 つのことをする。

1. **NAT 越しにサービスへ到達する**（Endpoint 登録 → grant → `peer_connect` →
   リレー脚 → 直接経路）
2. **それをローカルポートとして差し出す**（`--map 5432:db`）

**iOS へ渡らないのは 2 のほうである。** 1 は `isekai-client-ffi` が既に iOS で
動いており（§1）、移植の技術的リスクはほぼそこには無い。

iOS では「ローカルポートを開けて他のアプリに使わせ、その間ずっと動き続ける」が
プラットフォームの設計に正面から反する。**アプリはフォアグラウンドを離れると数秒で
サスペンドされ、「サーバを動かす」ための background mode は存在しない。** しかも
フォアグラウンドは同時に 1 つなので、「portal を前面に置く」ことは「使いたいアプリを
前面に置けない」ことと同義である。

したがって本計画は**消費のしかたを 3 段に分け、下の段から積む**。

| 段 | 誰がポートを使うか | 前提 | 動くか |
| --- | --- | --- | --- |
| **A** | **アプリ自身**（内蔵の WebView / コンソール） | 無し | **今日の技術で動く** |
| **B** | 同一端末の**他アプリ**、portal が前面のあいだ | 無し | 動くが**前面限定** |
| **C** | 端末全体、常時 | **Network Extension の entitlement**（Apple の審査）＋メモリ予算 | **未検証**（§7） |

**A を先に出す。** A は entitlement も審査も要らず、それでいて「NAT の向こうの
社内 Web を iPhone から見る」という最も多い用途をそのまま満たす。C は価値が最も
高いが、**Apple が entitlement を出すかと、NE のメモリ上限に収まるかの 2 つが
未知**であり、それに全体の完成を賭ける形にしてはならない。

---

## 1. 既に通っている道 — ここが出発点である

`ios/IsekaiCameraClient` が既に iOS 上で動いている。**そこで解けている問題を
数え上げておくことが、この計画の見積もりの土台になる。**

| 要素 | 実体 | portal 版で |
| --- | --- | --- |
| msquic / QUIC / MASQUE の iOS ビルド | `ios/build-rust.sh`（`aarch64-apple-ios` と `-sim` の xcframework） | **そのまま使う** |
| UniFFI による Rust ↔ Swift | `rust/isekai-client-ffi`（`uniffi::setup_scaffolding!`） | **同じ枠組みで別クレート**（§3） |
| Auth0 サインイン | `Auth0Client.swift` / `AuthStore.swift` / `Auth0TokenBridge.swift` | **再利用** |
| Endpoint 鍵の保管 | `EndpointKeyStore.swift` / `KeychainStore.swift`（Keychain） | **再利用** |
| ペアリングコードの読み取り | `QRScannerView.swift` | **再利用**（§5.2） |
| CI | `.github/workflows/ios-ffi.yml` | **同じ形を足す** |

**つまり「iOS で QUIC が動くのか」は本計画では未知数ではない。** 既に動いている。
残っているのは portal 固有の部分だけである。

---

## 2. 何を再利用し、何を作り直すか

| レイヤ | 実体 | iOS 方針 |
| --- | --- | --- |
| P2P 制御・QUIC・MASQUE | `isekai-p2p` / `isekai-p2p-core` / `channel-masque` | **そのまま**（クロスコンパイル） |
| portal のフレーミング | `portal-core::frame`（`Open` / `Status`）、`portal-core::udp` | **そのまま** |
| ローカルポートの受け口 | `portal_core::client::forward`（`TcpListener` を張る） | **段 A/B ではそのまま使える**（§4.1）。段 C では使わない |
| 認証 | `portal_core::login`（ブラウザ device flow、ファイル保管） | **使わない。** iOS の Auth0 実装に置き換え（§5.1） |
| サービスカタログ | `portal_core::config`（TOML） | **無関係**（server 側の話） |
| CLI 引数 | `portal-client/src/main.rs` | **SwiftUI で作り直す** |

> **`portal-core` は iOS でそのまま乗るか。** `client.rs` / `udp.rs` / `frame.rs`
> は tokio の TCP/UDP と QUIC しか使っておらず、iOS で動かない理由は無い。
> ただし `login.rs` はブラウザを開き、トークンをファイルに書く。**クレート全体を
> リンクするとこれも入る**ので、feature で切り分けるか、FFI からは
> `client` / `frame` / `udp` だけを呼ぶ形にする（§3.2）。

---

## 3. FFI の設計

### 3.1 別クレートにする — `portal-client-ffi`

`isekai-client-ffi` はカメラの形をしている（フレーム、カメラ一覧、映像シンク）。
portal はバイトストリームであり、**同じクレートに同居させると、どちらのアプリも
使わない API を半分ずつ抱える**ことになる。共有するのは `portal-core` と
`isekai-p2p` であって、FFI の面ではない。

### 3.2 公開する面

```
connect(config) -> Session          Endpoint 登録 → grant/capability → peer_connect
Session.services() -> [String]      到達できるサービス名（§5.3 で議論）
Session.map(service, local_port)    ローカルポートを張る（段 A/B）
Session.open(service) -> Stream     ポートを経由しない直結（段 A の別解、§4.2）
Session.status() -> Path/Relay      リレー経由か直接経路か
Session.close()
```

**`map` と `open` の両方を出す。** `map` は既存の
`portal_core::client::forward` をそのまま呼べる（WebView を向けるなら URL が要る）。
`open` はポートを介さずストリームを Swift に渡す（`URLProtocol` や独自コンソール
向け）。**どちらか一方に決め打ちしない**のは、段 A の 2 つの用途が別の形を
要求するからである。

### 3.3 UniFFI で非同期ストリームをどう渡すか

UniFFI は `async fn` を扱えるが、**バイトストリームの往復は Record では表せない**。
`Stream` は `uniffi::Object` として持ち、`read() -> Vec<u8>` / `write(Vec<u8>)` を
async で出す。**ここは実装前に小さく試す価値がある**（P0、§8）。

---

## 4. 段 A — アプリ自身が使う

### 4.1 ローカルポート＋内蔵 WebView（HTTP サービス向け）

最も多い用途がこれである: 社内の Web アプリを iPhone から見る。

```
Session.map("wiki", 18080)  →  WKWebView に http://127.0.0.1:18080 を読ませる
```

**ループバックは iOS でも普通に使える。** Local Network のプライバシー許可が
要るのは LAN であってループバックではないので、**追加のダイアログも entitlement も
出ない**。アプリは前面に居るので、サスペンドの問題も起きない。

> **確認事項（P0）。** `WKWebView` から `http://127.0.0.1:port` への平文アクセスは
> ATS（App Transport Security）の対象になる。ループバックは既定で許可される
> という理解だが、**`NSAllowsLocalNetworking` が要る可能性がある**ので実機で
> 確かめる。要るなら Info.plist に入れる — これは entitlement ではなく、審査上の
> 論点にもならない。

### 4.2 内蔵コンソール（任意 TCP 向け）

HTTP でないサービス（Redis、Postgres、独自プロトコル）に対しては、ポートを
経由せず `Session.open(service)` でストリームを取り、**バイトを送受信する画面**を
出す。実用というより**到達の確認**が目的で、「繋がっているか」を人が見られる
ことに意味がある（デスクトップ版の `--map` 後に `psql` を打つ動作に相当する）。

---

## 5. 認証・入り方・サービスの見つけ方

### 5.1 サインイン

`Auth0Client.swift`（PKCE + `ASWebAuthenticationSession`）を再利用する。
**デスクトップの `--login`（device flow）は使わない** — iOS には正しいやり方が
あり、既に実装されている。

Endpoint 鍵は `EndpointKeyStore` で Keychain に置く。**ファイルに 0600 で置く
デスクトップの流儀は持ち込まない。**

### 5.2 入り方 — ペアリングと ticket

デスクトップと同じ 3 通りを全部出す。

| 入り方 | iOS での姿 |
| --- | --- |
| `--pair K7QM-3XPD` | コード入力欄。**QR も読む**（`QRScannerView` を再利用） |
| `--redeem iskt1_…` | 貼り付け。**ticket は proxy を名指す**ので、設定中の proxy と違えば拒否する（デスクトップと同じ判断をそのまま移す） |
| 標準の grant | ペアリング済みなら何もしなくてよい |

> **秘密の取り違えに同じ防御を入れる。** デスクトップ版は「ペアリングコード欄に
> ticket や Enrollment Key を貼った」場合を prefix で検出して、**送る前に**止める。
> 貼り付けが主な入力手段になる iOS では、この防御は**デスクトップより重要**である。
> `isekai_p2p::agent::secret_prefix` をそのまま FFI に出す。

### 5.3 サービス名はどこから来るか

デスクトップでは人が `--map 5432:db` と打つ。名前はサーバの都合であり、
**線の上を流れない**（クライアントは名前を送るだけ）。

iOS では打たせたくない。しかし**「到達できるサービスの一覧」を返す API は
現状のプロトコルに無い**（カタログはサーバ側の秘密で、名前を知らない相手に
一覧を渡す設計になっていない）。

- **短期**: 名前は手で入力・保存する。ペアリングの相手ごとに覚えておく
- **中期**: サーバがペア相手に対してだけ名前を提示する経路を上流に提案する。
  **本計画ではプロトコルを勝手に足さない** — カタログを見せる範囲は
  `portal-server` 側の設計判断であり、ここで決めることではない

---

## 6. 段 B — 同一端末の他アプリ

段 A の `map` がそのまま他アプリからも使える。**ループバックはアプリ間で届く。**
足すのは機構ではなく**正直さ**である。

- **前面のあいだだけ動く**ことを画面に出す。「接続中」ではなく
  「**この画面を離れると止まります**」と書く
- サスペンドからの復帰で、張っていたポートと QUIC 接続を**畳んで張り直す**。
  黙って死んだ接続を残さない
- `beginBackgroundTask` で数十秒は延命できるが、**それは解決ではない**ので
  そう書く

**段 B に「頑張って生き延びる」実装を積まない。** iOS はそれを許さないし、
中途半端に延命すると「たまに動く」という最も悪い挙動になる。常時必要なら段 C である。

---

## 7. 段 C — Packet Tunnel Provider（未検証）

端末全体で、常時、他アプリから使えるようにする唯一の道。

```
NEPacketTunnelProvider（別プロセス、システムが生かす）
  → TUN から来たパケットを portal のストリームへ
```

**2 つの未知がある。着手前にこの順で潰す。**

1. **entitlement が下りるか。** `com.apple.developer.networking.networkextension`
   の `packet-tunnel-provider` は **Apple への申請と承認**が要る。これは技術では
   なく審査であり、**こちらの実装努力で確実にはできない**
2. **メモリに収まるか。** NE の拡張プロセスには**厳しいメモリ上限**がある
   （packet tunnel provider で概ね 50MB。歴史的にはもっと狭かった）。
   msquic + tokio + P2P スタックがそこに入るかは**測っていない**。
   入らなければ段 C は成立しない

> **1 より先に 2 を測る。** 申請は時間がかかるが、メモリは今日測れる。
> 入らないと分かってから申請するのは順序が逆である。測り方は、段 A の実機ビルドで
> 常駐時の RSS を見て、NE の予算に対する余裕を出す（P1、§8）。

段 C にはさらに、TUN のパケットを TCP ストリームに変換する層（ユーザ空間の
TCP スタック、あるいは宛先ごとの接続への振り分け）が要る。**これは portal が
今持っていない部品である。** 段 C に進むと決まってから設計する。

---

## 8. 段取り

| # | やること | 出口 |
| --- | --- | --- |
| **P0** | UniFFI で **async のバイトストリーム**を Swift に渡せるか、最小の往復で確かめる。同時に **ATS とループバック**を実機で確認 | どちらも「できる/できない」がはっきりする |
| **P1** | `portal-client-ffi` を作り、`connect` と `map` を出す。実機で 1 サービスに到達 | **iPhone から NAT 越しのサービスに繋がる**。ここが山 |
| | 併せて**常駐時のメモリを測る**（段 C の可否、§7-2） | 数字が出る |
| **P2** | SwiftUI: サインイン、ペアリング（QR 含む）、サービスの登録、状態表示 | 人が使える |
| **P3** | 内蔵 WebView と内蔵コンソール（段 A の 2 用途） | **entitlement 無しで完結した製品になる** |
| **P4** | 段 B の正直さ（前面限定の明示、復帰時の畳み直し） | 誤解を生まない |
| **P5** | UDP。TCP と別物なので分ける（`portal-core::udp` のセッション多重） | — |
| **P6** | 段 C。**P1 のメモリ実測が通っていれば**着手し、entitlement を申請 | 未定 |

**P3 で一度完成する。** P4 以降は無くても製品として成り立つ、という切り方に
してある。

---

## 9. この計画で解かないもの

1. **バックグラウンド常駐**（段 C 次第。§7）
2. **サービス名の発見**（プロトコルの追加が要る。§5.3）
3. **iOS を portal-server にすること。** 本計画は client 側だけである。
   端末上のサービスを外に出す話は、iOS のバックグラウンド制約に真正面からぶつかる
   ので、別に論じる
4. **`--version` すら無い問題。** デスクトップのバイナリが自分の版を言えないのと
   同様、iOS でも「どの版か」を出す口を最初から付ける（設定画面の末尾でよい）
