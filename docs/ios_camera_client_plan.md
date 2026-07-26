# camera-client iOS 版 実装計画書

`camera-client`（P2P Connect の **initiator = 映像ビューア**）を iOS ネイティブアプリとして実装するための計画書です。デスクトップ版と同じ Rust コア（P2P/QUIC/MASQUE）を共有ライブラリとして再利用し、UI・映像デコード・鍵保管・認証を iOS ネイティブで実装する方針を採ります。

> 対象は **ビューア側**（camera-server が配信する映像をリレー経由で受信して表示する側）です。iOS 端末をカメラ配信元（server 側）にする話は本計画のスコープ外とします（AVFoundation でのキャプチャ＋JPEGエンコード＋listener が別途必要）。

---

## 0. 現行 camera-client の要点（移植対象の把握）

デスクトップ版 `rust/camera-client`（egui GUI）がやっていること:

1. **P2P Connect 制御プレーン**: Auth0 アクセストークン → Identity API で Endpoint Token 発行 → Proxy に `peer_connect` して connection_id とリレー情報を取得（`camera_core::InitiatorSession::connect`）。
2. **リレー経由の映像受信**: `camera_core::receive_frames` が video QUIC（ALPN `sample`）をリレー越しにダイヤルし、**1 フレーム = 1 unidirectional stream の MJPEG**（JPEG バイト列）を受信。
3. **デコードと表示**: 受信 JPEG を OpenCV `imgcodecs` でデコード → egui テクスチャとして描画。
4. **鍵・設定**: Endpoint 鍵（ECDSA **P-256**、PKCS#8 PEM）をローカルファイル（0600）に保存。Identity/Proxy URL・protocol・capability・listener_id・Auth0 token を GUI で入力。

### 再利用できる層 / 作り直す層

| レイヤ | 実体 | iOS 方針 |
| --- | --- | --- |
| P2P 制御・QUIC・MASQUE | `camera-core` / `isekai-p2p` / `isekai-p2p-core` / `channel-masque` / `msquic-async`(+`seera-msquic`) | **そのまま再利用**（iOS 向けにクロスコンパイル） |
| UI（egui/eframe） | `camera-client` の GUI | **SwiftUI で作り直す** |
| 映像デコード（OpenCV） | `imgcodecs` | **ImageIO / UIImage に置換**（OpenCV 依存を排除） |
| 鍵保管（0600 ファイル） | `isekai-util secure_fs` | **iOS Keychain（将来 Secure Enclave）** |
| Auth0 トークン取得 | GUI に手貼り | **Auth0 ログイン（ASWebAuthenticationSession / Auth0.swift）** |

**朗報:** カメラ**キャプチャは不要**（ビューアのため）。OpenCV も JPEG デコードだけなので ImageIO に置換でき、重い依存を丸ごと外せます。

---

## 1. アーキテクチャ方針

**「Rust コア（静的ライブラリ）＋ SwiftUI」構成**を採用します。

```
┌──────────────────────── iOS App (Swift) ────────────────────────┐
│  SwiftUI 画面   … 接続設定 / ステータス / 映像表示             │
│  Auth0 ログイン (ASWebAuthenticationSession)  → access token   │
│  Keychain / Secure Enclave … Endpoint 鍵 (P-256)               │
│  ImageIO … JPEG(Data) → CGImage/UIImage 表示                   │
└───────────────▲───────────────────────────┬────────────────────┘
      Swift 呼び出し (UniFFI 生成バインディング) │ フレーム/状態コールバック
┌───────────────┴───────────────────────────▼────────────────────┐
│  Rust コア静的ライブラリ (libisekai_client.a, aarch64-apple-ios)│
│   FFI 薄層(UniFFI) → camera-core::{InitiatorSession,receive_    │
│   frames} / isekai-p2p(-core) / channel-masque                 │
│   msquic-async → seera-msquic(C, iOS ビルド) → quictls(OpenSSL)│
└─────────────────────────────────────────────────────────────────┘
```

- **Rust コアは「ヘッドレス」**に徹する: 制御プレーン・QUIC・リレー・JPEG フレームの受信までを担当し、**デコード/表示/UI/鍵保管/ログインは Swift 側**。
- Rust ↔ Swift の橋渡しは **UniFFI**（Mozilla）を第一候補とする。async 関数とコールバックインタフェース（フレームストリーム）に対応。手書き C FFI（cbindgen）は代替。
- **鍵の署名**は当面 Rust の `p256`（ソフトウェア鍵、Keychain に PKCS#8 で保管）。将来的に Secure Enclave（P-256 対応）へ寄せる場合は、署名を Swift の `SecKeyCreateSignature` に委譲し、Rust 側は「署名関数」をコールバックとして受け取る設計に切り替える（§7 参照。PoP と endpoint_id 導出が鍵実体に依存するため要注意）。

### なぜ egui-on-iOS ではなく SwiftUI か
`eframe`/`winit` は iOS でも一応動くが、①App Store 審査・UX がネイティブ前提、②映像表示・ログイン・Keychain 連携は結局ネイティブ API が要る、③OpenCV を持ち込みたくない、ため **SwiftUI + Rust コア**が本命。ただし「最短で疎通だけ確認したい」段階では egui-on-iOS を PoC に使う選択肢は残す（§6 Phase 0 の代替案）。

---

## 2. 技術的リスクと対応

| # | リスク | 対応 / 調査事項 |
| --- | --- | --- |
| R1 | **msquic の iOS ビルド**が最大の不確実性 | msquic には iOS 用 CMake ツールチェーン（`msquic/cmake/toolchains/ios.cmake`）が存在。TLS バックエンドに **quictls(OpenSSL 系)** を iOS 向けにビルドして静的リンクする必要。`seera-msquic` の build（CMake 呼び出し）を `aarch64-apple-ios` / `aarch64-apple-ios-sim` 向けに通すのが Phase 0 の主眼。Schannel は不可（Windows 専用）。 |
| R2 | **Rust ワークスペースの iOS クロスコンパイル** | `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios`。`ring`/`aws-lc-rs`/`p256` 等の暗号系が iOS ターゲットでビルドできるか確認（rustls は使っていないが依存グラフ要確認）。`cc`/CMake が Xcode の SDK/clang を使うよう環境変数を設定。 |
| R3 | **バックグラウンド動作 / ネットワーク制約** | iOS はバックグラウンドで UDP ソケットが停止。フォアグラウンド前提の設計にし、`scenePhase` で接続を suspend/resume。長時間視聴は「画面オン維持」も検討。 |
| R4 | **TLS 信頼**（本番は実証明書、開発は自己署名） | `ISEKAI_INSECURE_SKIP_VERIFY` は**開発専用**。本番は Proxy/Identity の正規証明書検証＋**per-endpoint relay 証明書**（loopback FQDN 検証）を有効に。iOS 側の証明書検証を msquic(quictls) に委ねるか、Swift 側でトラスト評価するか設計。 |
| R5 | **鍵の安全な保管** | Endpoint 秘密鍵は端末外に出さない。まず Keychain（`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`）。Secure Enclave 化は R7 の設計変更を伴う。 |
| R6 | **暗号輸出コンプライアンス（App Store）** | 標準暗号（TLS/ECDSA）利用のため通常は自己申告で足りるが、`ITSAppUsesNonExemptEncryption` 等の申告要否を確認。 |
| R7 | **Secure Enclave と PoP の整合** | endpoint_id は公開鍵 JWK のサムプリントから導出、PoP は秘密鍵署名。Secure Enclave 鍵にすると Rust の `p256` では署名できないため、署名を Swift に委譲する FFI 設計が必要。初期はソフトウェア鍵で回避。 |
| R8 | **msquic のスレッド/実行環境** | msquic は自前ワーカスレッドを持つ。iOS のプロセスライフサイクル（サスペンド）と相性を検証。teardown 時のクラッシュ回避（デスクトップ例では `_exit` で回避しているが、アプリでは正規の shutdown 手順が要る）。 |

---

## 3. コンポーネント別設計

### 3.1 Rust コア FFI 層（新規クレート `isekai-client-ffi`）
- `camera-core` に依存し、**ビューア API** を UniFFI で公開する薄いクレートを追加。
- 責務:
  - 設定（Identity/Proxy URL, protocol, capability, listener_id）と Auth0 token を受け取り、`InitiatorSession::connect` → `receive_frames` を駆動。
  - 受信 JPEG フレームを **コールバック（or async stream）**で Swift に渡す。
  - 接続状態（connecting / connected / streaming / error）を通知。
  - connection_id を Swift に返す（サーバ側 bind 用に人間が渡す/QR 等）。
- tokio ランタイムはコア内で管理（`Runtime` を FFI オブジェクトに内包）。
- **`dial_video` の 60 秒ハンドシェイク**（#47）により、connect 後すぐダイヤル→数秒後に相手が bind、の順序でも復旧する。iOS でも同挙動を活かす。

### 3.2 msquic の iOS ビルド
- `seera-msquic` の CMake 呼び出しを `-DCMAKE_TOOLCHAIN_FILE=.../ios.cmake -DPLATFORM=OS64`（デバイス）/ `SIMULATORARM64`（シミュレータ）で実行。
- quictls(OpenSSL) を iOS 向けに事前ビルドし、msquic の TLS backend に指定。
- 出力を **XCFramework もしくは静的 `.a`＋ヘッダ**として Rust の build から取り込み、最終的に Rust 静的ライブラリへ内包。

### 3.3 SwiftUI アプリ
- 画面: ①接続設定（Identity URL, Proxy URL, protocol, capability, listener_id, dev トグル）②「Show my Endpoint ID」③Connect/Disconnect ④接続ステータス ⑤映像ビュー。
- 映像表示: フレーム(Data) → `CGImageSourceCreateWithData`/`UIImage(data:)` → `Image`（または低遅延に `MTKView`/`CADisplayLink`）。
- 4 値交換（endpoint_id / capability / listener_id / connection_id）は当面テキスト手入力＋コピー。将来 **QR コード**でやり取り。

### 3.4 Auth0 ログイン
- `ASWebAuthenticationSession`（または Auth0.swift SDK）で access token を取得し、FFI に渡す。
- token の `iss`/`aud` は Identity の `AUTH0_ISSUER`/`AUTH0_AUDIENCE` に一致必須。

### 3.5 鍵保管
- 初期: Rust で P-256 鍵生成 → PKCS#8 を **Keychain** に保存（`ThisDeviceOnly`、非同期化不可設定）。
- 将来: Secure Enclave 鍵（署名を Swift 委譲、§7/R7）。

---

## 4. フェーズ計画

| Phase | ゴール | 主な作業 | 完了判定 |
| --- | --- | --- | --- |
| **0. 実現性検証** | Rust コア＋msquic が iOS 実機/シミュレータで QUIC 接続できる | msquic+quictls の iOS ビルド、Rust ワークスペースの `aarch64-apple-ios(-sim)` クロスコンパイル、ヘッドレスで `InitiatorSession::connect`→`receive_frames` を叩く最小 PoC | シミュレータ/実機で **1 フレーム受信**（ローカルスタック §8） |
| **1. FFI 層** | `isekai-client-ffi`（UniFFI）でビューア API を Swift から呼べる | FFI クレート新設、フレーム/状態コールバック、tokio ランタイム内包、Swift バインディング生成 | Swift の単体テストから connect→フレーム取得 |
| **2. SwiftUI スケルトン** | 手動トークンで映像表示（dev TLS スキップ） | 設定画面・Connect・ステータス・ImageIO デコード・映像ビュー | GUI で映像が表示される（happy path） |
| **3. 認証・鍵** | Auth0 ログイン＋Keychain 鍵 | ASWebAuthenticationSession、Keychain 保管、endpoint_id 表示、register/issue | 実 Auth0 でトークン取得→接続 |
| **4. 本番 TLS・堅牢化** | 実証明書検証・relay 証明書・再接続・バックグラウンド対応 | TLS 検証有効化、per-endpoint relay cert 検証、`scenePhase` 制御、reconnect | 自己署名スキップ無しで接続、視聴継続が安定 |
| **5. 仕上げ** | 配布準備 | QR 交換、エラー UX、暗号輸出申告、TestFlight | 実機ベータ配布 |

各フェーズは §8 のローカルスタック（Proxy/Identity/合成フレーム）に対して検証可能。

---

## 5. ディレクトリ構成案

```
ISEKAI-link/
  rust/
    isekai-client-ffi/        # 新規: UniFFI ビューア API（camera-core をラップ）
      src/lib.rs
      build.rs                # UniFFI scaffolding
    ...（既存クレート）
  ios/                        # 新規: Xcode プロジェクト
    IsekaiCameraClient/
      App/                    # SwiftUI アプリ
      Generated/              # UniFFI 生成 Swift バインディング
      Frameworks/             # Rust 静的ライブラリ / msquic XCFramework
    build-rust.sh             # cargo build --target aarch64-apple-ios(-sim) 一括
  docs/
    ios_camera_client_plan.md # 本書
```

---

## 6. FFI API 案（UniFFI, スケッチ）

```rust
// isekai-client-ffi/src/lib.rs（イメージ）

pub struct ClientConfig {
    pub identity_url: String,
    pub proxy_url: String,
    pub protocol: String,
    pub capability: String,
    pub listener_id: String,
    pub insecure_skip_verify: bool, // 開発時のみ true
}

pub trait FrameSink: Send + Sync {          // Swift 実装のコールバック
    fn on_frame(&self, jpeg: Vec<u8>, seq: u64);
    fn on_state(&self, state: ConnectionState, detail: String);
}

pub enum ConnectionState { Connecting, Connected, Streaming, Closed, Failed }

pub struct ViewerSession { /* tokio Runtime + タスク + shutdown を内包 */ }

impl ViewerSession {
    /// endpoint 鍵(PKCS#8 PEM)と Auth0 token を渡して接続開始。
    /// connection_id を返す（サーバ側 bind 用に人間へ提示）。
    pub fn connect(cfg: ClientConfig, endpoint_key_pem: String,
                   auth0_token: String, sink: Box<dyn FrameSink>)
        -> Result<String, ClientError>;
    pub fn disconnect(&self);
}

/// 鍵ユーティリティ（Keychain 保存は Swift 側、生成/導出は Rust）
pub fn generate_endpoint_key_pem() -> String;
pub fn endpoint_id_of(pem: String) -> Result<String, ClientError>;
```

- **Secure Enclave 対応版（将来）**: `endpoint_key_pem` の代わりに `signer: Box<dyn PopSigner>`（Swift が `SecKeyCreateSignature` で実装）と公開鍵 JWK を渡す形へ。endpoint_id 導出と PoP 署名がこのインタフェース経由になる（R7）。

---

## 7. 未決事項 / 要検討

1. **Secure Enclave を初手から入れるか**: セキュリティ上は理想だが FFI 設計が重くなる（R7）。初期はソフトウェア鍵＋Keychain、Phase 4 以降で判断。
2. **最低 iOS バージョン**: UniFFI async / SwiftUI / ASWebAuthenticationSession の要件から iOS 16+ を仮置き。
3. **映像表示のパイプライン**: UIImage 差し替えで足りるか、低遅延に `MTKView` が要るか（フレームレート・解像度次第）。
4. **4 値交換の UX**: 手入力 → QR → 将来的なシグナリング自動化のロードマップ。
5. **msquic teardown**: アプリ内での正規シャットダウン手順（デスクトップ例の `_exit` 回避策は流用不可）。
6. **CI**: iOS ビルド（msquic/quictls クロスコンパイル）を CI に載せるか、当面ローカル/手動か。

---

## 8. 検証方法（ローカル）

`ISEKAI-link-server/docs/p2p_local_testing.md` のローカルスタック（Proxy `:8443` / Identity `:9443` / Endpoint-Token JWKS `:8080`）をそのまま利用できる。

- **Phase 0–1**: ヘッドレス PoC / Swift 単体テストから `connect`→フレーム取得。相手側は `camera-server`（GUI）または `camera-core` の `relay_e2e` / `relay_gap_e2e` 例で合成フレームを配信。
- **相手役だけが欲しい場合**: `camera-core` の `synthetic_server` 例（OpenCV 不要・Windows 可）がサーバ半分だけを担い、生成した JPEG を流す。stdin で `issue`/`bind`、`--control <addr>` で同じコマンドを TCP から。既定は本番エンドポイント向きなので**同一 LAN である必要はない**（リレー経由のため）。iOS の `IsekaiCameraClientTests` はこれを相手に走る。
- **Phase 2 以降**: シミュレータは `127.0.0.1` に到達できる（同一 Mac 上のローカルスタック）。実機は同一 LAN 上のホストを指す。dev 期間は `insecure_skip_verify=true`。
- **ギャップ挙動**: connect 直後にダイヤル→数秒後に相手 bind、の順序でも #47 の 60 秒ハンドシェイクで復旧することを確認済み（iOS でも同経路）。

---

## 付録: スコープ外（将来の拡張）

- iOS を**配信元（camera-server 相当）**にする: AVFoundation キャプチャ → JPEG エンコード → video listener（`serve_frames`）+ P2P listener/capability 発行。別計画。
- Android 版: 同じ Rust コアを JNI/UniFFI(Kotlin) で共有可能。
- WebRTC リレーモード（ブラウザ相当）との統合。
