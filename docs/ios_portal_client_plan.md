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
iPhone のフォアグラウンドは同時に 1 つなので、**「portal を前面に置く」ことは
「使いたいアプリを前面に置けない」ことと同義**である。

したがって本計画は**消費のしかたを 3 段に分け、下の段から積む**。

| 段 | 誰がポートを使うか | 前提 | 状態 |
| --- | --- | --- | --- |
| **A** | **アプリ自身**（内蔵 WebView / コンソール） | 無し | **今日の技術で動く**。ただし HTTPS に判断が要る（§4.3） |
| **B** | 同一端末の他アプリ | **iPad の Split View / Slide Over のみ** | iPhone では**動かない**（§6） |
| **C** | 端末全体、常時 | NE entitlement（Apple の審査）＋メモリ予算＋不足部品 2 つ | **未検証**（§7） |

**A を先に出す。** A は entitlement も審査も要らない。ただし
「NAT の向こうの社内 Web を iPhone から見る」を**丸ごと満たすとは言えない** —
その用途の多くは HTTPS であり、ループバック転送は証明書の名前検証を壊す。
どこまでが A の守備範囲かは §4.3 に書く。

C は価値が最も高いが、**未知が 3 つある**（§7）。それに全体の完成を賭けてはならない。

---

## 1. 既に通っている道 — ここが出発点である

`ios/IsekaiCameraClient` が既に iOS 上で動いている。**そこで解けている問題を
数え上げることが、この計画の見積もりの土台になる。**

| 要素 | 実体 | portal 版で |
| --- | --- | --- |
| msquic / QUIC / MASQUE の iOS ビルド | `ios/build-rust.sh`（`aarch64-apple-ios` と `-sim` の xcframework） | **使う。ただし要改造**（§8.1） |
| UniFFI による Rust ↔ Swift | `rust/isekai-client-ffi` | **同じ枠組みで別クレート**（§3） |
| Auth0 サインイン | `Auth0Client.swift` / `AuthStore.swift` | **再利用。ただし redirect の登録が要る**（§5.1） |
| Endpoint 鍵の保管 | `EndpointKeyStore.swift` / `KeychainStore.swift`（Keychain） | **再利用** |
| ペアリングコードの読み取り | `QRScannerView.swift` | **再利用**（§5.2） |
| メモリ実測 | `ProcessStats.swift`（`phys_footprint`） | **再利用**（§7.2 で効く） |
| CI | `.github/workflows/ios-ffi.yml` | **同じ形を足す。実機ビルドは `main` 限定**（§8.1） |

**「iOS で QUIC が動くのか」は本計画では未知数ではない。** 既に動いている。

---

## 2. 何を再利用し、何を作り直すか

| レイヤ | 実体 | iOS 方針 |
| --- | --- | --- |
| P2P 制御・QUIC・MASQUE | `isekai-p2p` / `isekai-p2p-core` / `channel-masque` | **そのまま** |
| セッション確立 | `portal_core::session`（`connect`、`Reach`、`Connected`）、`transport`、`grant`、`path` | **そのまま** |
| portal のフレーミング | `portal_core::frame`（`Open` / `Status`）、`server::Protocol`、`udp`、`datagram` | **そのまま** |
| ローカルポートの受け口 | `portal_core::client::forward` | **段 A/B ではそのまま**（§3.2）。段 C では使わない |
| 認証 | `portal_core::login` | **使わない**（§5.1） |
| サービスカタログ | `portal_core::config`（TOML） | **無関係**（server 側） |
| CLI 引数 | `portal-client/src/main.rs` | **SwiftUI で作り直す** |

> **`portal-core` を「一部のモジュールだけ」使う、とは言えない。** `frame` は
> `crate::server::Protocol` に依存し、`connect` は `session` / `transport` /
> `grant` / `path` を引く。**クレートごと持っていく**のが実際の形である。
>
> `login` を避けたい理由は「リンクすると入ってしまうから」**ではない** —
> 参照されない `pub fn` は最終バイナリに入らない。理由は**依存とファイル書き込みの
> 面**である。`sign_in` はトークンをファイルに保存する（iOS では Keychain に置く
> べきもの）。なお `login` は**ブラウザを開かない** — 検証 URL とコードを標準出力に
> 印字して待つ device flow であり、iOS でそのまま動かす意味が無いのはそちらの理由による。

---

## 3. FFI の設計

### 3.1 別クレートにする — `portal-client-ffi`

`isekai-client-ffi` はカメラの形をしている（フレーム、カメラ一覧、映像シンク）。
portal はバイトストリームであり、同居させるとどちらのアプリも使わない API を
半分ずつ抱える。共有するのは `portal-core` と `isekai-p2p` であって FFI の面ではない。

### 3.2 公開する面

```
connect(config) -> Session               session::connect をそのまま
Session.map(service, port: u16) -> u16   ローカルポートを張り、実際に張れた番号を返す
Session.open(service) -> Stream          ポートを介さない直結
Session.path() -> Relay | Direct         いま relay か直接経路か
Session.remembered_services() -> [String]  この端末が覚えている名前（§5.3）
Session.close()
```

**`map` は張れた番号を返す。** `portal_core::client::forward` は実際に bind した
`SocketAddr` を返しており、段 A は WebView の URL を作るのにそれが要る。
さらに **port は 0 を渡して OS に選ばせる**: 固定番号にすると、§6 の
「復帰時に畳んで張り直す」で前のリスナが消えきる前に再 bind して `EADDRINUSE` に
なり、**利用者が対処のしようがない失敗**になる。

**`services()` とは呼ばない。** サーバに一覧を訊く経路は存在しない（§5.3）ので、
返せるのは**この端末が覚えている名前だけ**である。`services()` という名前は
持っていない知識を約束してしまう。

### 3.3 async をどう渡すか — 既に踏まれている地雷がある

`rust/isekai-client-ffi/Cargo.toml` の uniffi は `features = ["cli"]` だけで、
**`tokio` feature が入っていない。** msquic/tokio の I/O に触る `async fn` を
`#[uniffi::export]` するには `#[uniffi::export(async_runtime = "tokio")]` が要り、
それには uniffi の `tokio` feature が要る。無いまま出すと uniffi 自身の executor で
future が回り、**最初の I/O で「there is no reactor running」で落ちる。**

**そして既存クレートはこれを避ける形になっている。** `isekai-client-ffi` は
`Runtime` を自分で持ち、`#[uniffi::export(callback_interface)] FrameSink` で
データを Swift に**押し出して**いる（`src/lib.rs:192`）。**実機で動いている
実績のある形はこちらである。**

- 第一案: uniffi に `tokio` feature を足し、async で読み書きする
- 退避案: `FrameSink` と同じ callback interface。`StreamSink` を Swift 側に置き、
  Rust から押し出す

**P0 はこの二択の決着である**（§8）。退避案が既に動いているので、**P0 が失敗しても
計画は止まらない。**

---

## 4. 段 A — アプリ自身が使う

### 4.1 内蔵コンソール（任意 TCP）

`Session.open(service)` でストリームを取り、バイトを送受信する画面を出す。
到達の確認が目的で、「繋がっているか」を人が見られることに意味がある。
**証明書もホスト名も絡まないので、ここは素直に動く。**

### 4.2 平文 HTTP — ループバック＋WebView

```
Session.map("wiki", 0) -> 18080  →  WKWebView に http://127.0.0.1:18080
```

ループバックは iOS でも使える。Local Network のプライバシー許可が要るのは LAN で
あってループバックではないので、**追加のダイアログも entitlement も出ない。**

> **確認事項（P0）。** 平文ループバックが ATS に引っかかるか。既定で許可される
> という理解だが、`NSAllowsLocalNetworking` が要る可能性があるので実機で見る。
> 要っても Info.plist の一行で、審査上の論点にはならない。

### 4.3 HTTPS — ここが段 A の本当の境界

**「社内 Web を iPhone から」の多くは HTTPS であり、ループバック転送はそれを壊す。**

- サーバは `wiki.internal` の証明書を出す。`https://127.0.0.1:18080` は
  **名前検証で落ちる**
- `http://127.0.0.1:18080` は TLS リスナとそもそも話せない
- 通ったとしても、**絶対 URL のリダイレクト・Cookie の Domain・Origin 検査**が
  正規ホスト名に対して書かれているので順に壊れる

取りうる道は 3 つあり、**どれも「ポートを張って WebView を向ける」より重い**。

| 案 | 中身 | 評価 |
| --- | --- | --- |
| 名前検証を切る | `WKWebView` の server-trust delegate で上書き | **採らない。** 検証を切るのは審査でも設計でも説明が立たない |
| 平文だけ対象にする | 段 A は平文 HTTP と生 TCP に限る | **短期はこれ。** 正直で、実装が要らない |
| **アプリが TLS クライアントになる** | portal のストリームの上で、アプリが `wiki.internal` として TLS を張る。WebView へは `WKURLSchemeHandler` で応答を返す | **中期はこれ。** ホスト名が正しいまま検証でき、Cookie も Origin も壊れない。ただし HTTP を自前で話す層が要る |

**P3 では「平文だけ」で出す。** TLS クライアント案は P5 以降に置き、
**§0 の「段 A で製品として完結する」は平文 HTTP と生 TCP の範囲での話**である、
と書いておく。ここを曖昧にすると、最も多い用途で期待を外す。

---

## 5. 認証・入り方・サービス名

### 5.1 サインイン — 設定の段取りが 1 つある

`Auth0Client.swift`（PKCE + `ASWebAuthenticationSession`）を再利用する。
デスクトップの device flow は使わない（§2）。

> **`Auth0Config.swift` は `callbackScheme = "isekaiviewer"` を固定で持ち、
> これは `ios/project.yml` の `CFBundleURLSchemes` と Auth0 側の
> Allowed Callback URLs の両方に現れている。** 2 つ目のアプリは、
> **同じスキームを 2 アプリが登録する**（端末上で衝突する）か、
> **新しい redirect を Auth0 の管理画面に登録する**かのどちらかになる。
> **これはコード変更ではなく設定作業**であり、P2 を止めうるので先に手配する。

Endpoint 鍵は `EndpointKeyStore` で Keychain に置く。

### 5.2 入り方 — ペアリングと ticket

| 入り方 | iOS での姿 |
| --- | --- |
| `--pair K7QM-3XPD` | コード入力欄。**QR も読む**（`QRScannerView` 再利用） |
| `--redeem iskt1_…` | 貼り付け。**ticket は proxy を名指す**ので設定中の proxy と違えば拒否（`check_ticket` と同じ判断を移す） |
| 標準の grant | ペアリング済みなら何も要らない |

> **秘密の取り違えに同じ防御を入れる。** デスクトップ版はペアリングコード欄に
> ticket や Enrollment Key を貼った場合を prefix で検出し、**送る前に**止める。
> 貼り付けが主な入力手段になる iOS では**デスクトップより重要**である。
> `isekai_p2p::agent::secret_prefix` をそのまま FFI に出す。

### 5.3 サービス名 — 一覧を返す経路は無い

**名前は線の上を流れる。** `Open::Tcp { service }` がそれを運ぶ。流れないのは
**どのローカルポートがどの名前に対応するか**という対応表のほうで、それは
この端末の都合である（`client.rs` のコメントが言っているのはこちら）。

したがって名前は**サーバのカタログの鍵と一字一句同じ**でなければならない。
しかし**「到達できるサービスの一覧」を返す API は現状のプロトコルに無い。**

- **短期**: 手で入力し、ペア相手ごとに覚える（`remembered_services()`）
- **中期**: ペア相手にだけ名前を提示する経路を上流に提案する。
  **本計画ではプロトコルを足さない** — カタログを見せる範囲は `portal-server` の
  設計判断である

**この不在は段 C にも効く**（§7.3）。

---

## 6. 段 B — 他アプリから使う（iPad に限る）

**iPhone では成立しない。** §0 のとおり、他アプリを前面にした瞬間 portal は
背面に回ってサスペンドされ、リスナは accept を止め QUIC セッションも落ちる。
`beginBackgroundTask` で 30 秒ほど延びるだけで、**相手アプリから見ると
「繋がるが応答が来ない」**という最も分かりにくい壊れ方になる。

**成立するのは iPad の Split View / Slide Over だけである。** 両方が前面に
居るので、ループバックは素直に届く。段 B とはつまり **iPad マルチタスクの話**で
あって、「フォアグラウンド限定でどの端末でも」ではない。

やることは機構ではなく**正直さ**である。

- iPhone では段 B を**提示しない**。できないことを設定画面に並べない
- iPad では「**この画面を閉じると止まります**」と書く
- サスペンド復帰時に、張っていたポートと QUIC を**畳んで張り直す**
  （§3.2 のとおり port 0 で。固定番号だと再 bind が `EADDRINUSE` で失敗する）
- **「頑張って生き延びる」実装を積まない。** iOS は許さないし、中途半端な延命は
  「たまに動く」という最悪の挙動になる。常時必要なら段 C である

---

## 7. 段 C — Packet Tunnel Provider（未検証、不足部品あり）

端末全体・常時・他アプリから、を満たす唯一の道。**未知が 3 つあり、この順で潰す。**

### 7.1 entitlement が下りるか

`com.apple.developer.networking.networkextension` の `packet-tunnel-provider` は
**Apple への申請と承認**が要る。これは技術ではなく審査であり、**こちらの実装努力で
確実にはできない。**

### 7.2 メモリに収まるか — 測る数字は RSS ではない

NE の拡張プロセスには厳しいメモリ上限がある（packet tunnel provider で概ね 50MB）。
msquic + tokio + P2P スタックがそこに入るかは**測っていない。**

> **`phys_footprint` を測る。RSS ではない。** `ProcessStats.swift` が既にそう
> していて、理由もそこに書いてある — jetsam が見るのは footprint であって、
> 「アプリが代金を払っていないページまで数える」resident size ではない。
> NE の上限も footprint に対して効く。**RSS を測ると、判断に必要な数字とは別の
> 数字が出る。**
>
> 加えて、**段 A のアプリをそのまま測ると SwiftUI と WebView が混ざる。**
> 拡張が背負うのは Rust コアだけなので、**何を切り離して測ったのか**を明記する。

**申請より先に測る。** 入らないと分かってから申請するのは順序が逆である。

### 7.3 足りない部品が 2 つある

**どちらも今 portal が持っていない。**

1. **名前と宛先アドレスの対応。** TUN から来るのは `IP:port` 宛のパケットだが、
   portal のプロトコルが受け取るのは**サービス名**である（`Open::Tcp { service }`）。
   間を埋めるには、サービスごとに合成 IP を配る **DNS レスポンダ**のような層が要る。
   **そして §5.3 のとおり、名前の一覧を得る経路が無い** — 対応表を作る材料が
   無いということである。段 C は §5.3 の中期案に依存する
2. **portal 自身の QUIC をトンネルから除外すること。** パケットトンネルは端末の
   通信を捕まえるので、proxy へ向かう自分の QUIC も捕まえてしまう。除外ルートを
   設定するか、トンネル外に bind したソケットを使わないと、**トンネルが自分の
   足を食べて何も繋がらない。**

さらに TUN のパケットを TCP ストリームに変換する層（ユーザ空間 TCP スタック）が
要る。**段 C に進むと決まってから設計する。**

---

## 8. 段取り

| # | やること | 出口 |
| --- | --- | --- |
| **P0** | **async をどう渡すか決める**（§3.3 の二択）。併せて **ATS とループバック**を実機確認 | 決着する。退避案が既に動いているので**失敗しても止まらない** |
| **P1** | `portal-client-ffi` を作り `connect` / `map` / `open` を出す。実機で 1 サービスに到達 | **iPhone から NAT 越しのサービスに繋がる**。ここが山 |
| | 併せて **Rust コアの `phys_footprint` を測る**（§7.2） | 段 C の可否に使える数字が出る |
| **P2** | SwiftUI: サインイン、ペアリング（QR 含む）、名前の登録、経路表示 | 人が使える。**Auth0 redirect の手配を先に済ませる**（§5.1） |
| **P3** | 内蔵コンソールと、**平文 HTTP** の WebView | **entitlement 無しで完結する**（§4.3 の範囲で） |
| **P4** | 段 B — **iPad 限定**として出す。復帰時の畳み直し | 誤解を生まない |
| **P5** | HTTPS: アプリが TLS クライアントになる案（§4.3） | 社内 Web の大半が対象になる |
| **P6** | UDP（`portal-core::udp` のセッション多重） | — |
| **P7** | 段 C。**P1 の footprint が通り、§7.3 の部品を設計してから** | 未定 |

**P3 で一度完成する** — ただし §4.3 の範囲で、と断ったうえで。

### 8.1 ビルドと CI に要る手当て

- `ios/build-rust.sh` は `-p isekai-client-ffi`、`APP_DIR=.../IsekaiCameraClient`、
  `IsekaiClientFFI.xcframework` を**固定で持っている**。2 つ目の FFI クレートには
  **引数化（またはフォーク）**が要る
- `ios/project.yml` は単一アプリの構成なので、アプリを足すか別プロジェクトにする
- `.github/workflows/ios-ffi.yml` に path filter を足す。
  **実機ビルド（`ios-ipa`）は `main` と `workflow_dispatch` でしか走らない**ので、
  **ブランチではシミュレータまでしか確認できない** — P1 の実機確認は
  `workflow_dispatch` か手元の実機で行う

---

## 9. この計画で解かないもの

1. **iPhone でのバックグラウンド常駐**（段 C 次第。§7）
2. **サービス名の発見**（プロトコルの追加が要る。§5.3。**段 C の前提でもある**）
3. **HTTPS の完全な対応**（P5。§4.3）
4. **iOS を portal-server にすること。** client 側だけを扱う。端末上のサービスを
   外に出す話は iOS のバックグラウンド制約に真正面からぶつかるので、別に論じる
5. **版を名乗る口。** デスクトップのバイナリに `--version` が無いのと同じ問題を
   持ち込まないよう、設定画面の末尾に版を出す
