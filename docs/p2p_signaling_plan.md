# P2P 自動シグナリング 仕様案

現在の P2P 接続は、Listener ID・Capability・Connection ID・Endpoint ID の 4 値を
人間が手で運んでいる。本書はこれを **接続のたびには何も運ばなくてよい** 形に
置き換える設計案をまとめる。

対象は `isekai-p2p-core` / `isekai-p2p` / カメラアプリ、および **MASQUE プロキシの
制御プレーン**。プロキシ側はこのリポジトリに無いため、§6 以降の API は
**提案**であり、実装前に本体仕様（`spec §8`, `§13`）との突き合わせが必要。

---

## 1. 現状と、何が煩雑なのか

### 1.1 いま運んでいる 4 値

`docs/p2p_library_plan.md` §3.5 のとおり、接続 1 回につき 4 往復の手作業がある。

| 値 | 生成 | 消費 | 運ぶ方向 |
| --- | --- | --- | --- |
| クライアントの `endpoint_id` | クライアントの鍵 | サーバ（`issue_capability`） | client → server |
| サーバの `listener_id` | `ListenerSession::create` | クライアント（`connect`） | server → client |
| `capability` | サーバの `issue_capability` | クライアント（`connect`） | server → client |
| クライアントの `connection_id` | `InitiatorSession::connect` | サーバ（`bind`） | client → server |

**往復が 2 回ある**のが本質的に厄介な点である。とくに 4 番目は、クライアントが
接続を試みてからでないと値が存在しないため、**クライアントがリトライで待って
いる間に人間が値を運ぶ**という構造になっている。

この構造が実際に事故を起こした記録が `docs/p2p_mode_migration_plan.md` §7 #21 に
ある。手作業が 120 秒のリトライ期限に間に合わず、接続失敗として現れていた。

### 1.2 自動化してよいもの／人間に残すもの

4 値のうち、**セキュリティ上の判断はひとつしかない**。

> 「この Endpoint が、このカメラに接続してよい」

残りはすべて機械的な受け渡しである。したがって設計方針は次のとおり。

- **判断は人間に残す。ただし 1 回だけ**（=導入時）。
- **接続ごとの受け渡しはゼロにする**。

---

## 2. 設計原則

1. **認可の単位を変えない。** 現行はリレーエッジを Endpoint 単位で認可している
   （`spec §13`）。自動化しても、認可されていない Endpoint がリレーの bind を
   引き起こせてはならない。
2. **新しいベアラ秘密をデータ経路に増やさない。** 認証は現行どおり
   Endpoint Token + PoP。導入時のペアリングコードだけは例外だが、短命・単回・
   レート制限で封じ込める（§8.2）。
3. **プロキシは仲介であって信頼の起点ではない。** プロキシは「誰が誰に繋いで
   よいか」の記録を持つが、映像そのものは端点間の QUIC で保護される。
4. **既存の手動経路を壊さない。** 新方式は加算的に入れ、当面は併存させる。
5. **カメラ側に最終拒否権を残す。** 自動受理はカメラのローカル設定であり、
   プロキシが強制するものではない。

---

## 3. 全体像

### 3.1 現在

```
[client]                    [proxy]                    [camera]
   |                                                      |
   |  endpoint_id ──────────── 人間 ────────────────────> |
   |                                                      |── create listener
   |                                                      |── issue capability
   | <─────────── 人間 ──── listener_id + capability ──── |
   |                                                      |
   |── POST /v1/peer/connect ──>|                         |
   |<── connection_id ──────────|                         |
   |                                                      |
   |  connection_id ────────── 人間 ────────────────────> |
   |                                                      |── bind
   |<════════════ リレー経路が開通 ═══════════════════════>|
```

### 3.2 提案

**導入時（1 回だけ、人間）**

```
[client]                    [proxy]                    [camera]
   |                                                      |── create listener
   |                                                      |── ペアリングコード発行
   | <──────────── 人間（QR / 6 桁コード）──────────────── |
   |── POST /v1/peer/pair ─────>|                         |
   |                            |── grant を作成 ─────────>|（通知）
```

**接続時（毎回、全自動）**

```
[client]                    [proxy]                    [camera]
   |                            |<══ 通知チャネル（常時接続）══|
   |── GET /v1/peer/listeners ─>|                         |
   |<── 接続可能なカメラ一覧 ───|                         |
   |── POST /v1/peer/connect ──>|                         |
   |                            |── peer.connect.request ─>|
   |                            |                         |── bind（自動）
   |<── connection_id ──────────|<── bound ───────────────|
   |<════════════ リレー経路が開通 ═══════════════════════>|
```

**接続ごとに人間が運ぶ値は無くなる。**

---

## 4. 導入（ペアリング）の方式

用途が違うので 3 方式を用意し、カメラ側で選べるようにする。

### 4.1 方式 A — 同一アカウント自動許可（推奨・既定）

**自分のカメラを自分の端末から見る**という最も多い場合を、導入操作ゼロにする。

Endpoint は Identity API に登録される際、Auth0 のユーザ／テナントに紐づいている
（`register_and_issue`）。したがってプロキシは「両 Endpoint の所有者が同一か」を
判定できる。

- カメラのリスナに `owner_auto_grant: true`（既定）を設定
- 同一所有者の Endpoint からの `connect` は grant が無くても通す
- 監査ログには通常の grant と同じく記録する

**制約**: 所有者が別（家族・業務の相手）なら方式 B か C が要る。

### 4.2 方式 B — ペアリングコード / QR（推奨・他者への付与）

カメラがコードを表示し、クライアントがそれを読む。**値が一方向にしか流れない**
のが利点で、往復が消える。

- カメラ: `POST /v1/peer-listeners/{id}/pairing-codes` → 短命コードを取得して表示
- クライアント: コードを入力（または QR を撮影）して `POST /v1/peer/pair`
- プロキシ: コードを検証し、**クライアントの Endpoint ID に対する grant を作成**

QR に載せる内容（`isekai://pair?...`）:

```
proxy   プロキシのベース URL
code    ペアリングコード
exp     有効期限（UNIX 秒）
```

`listener_id` は載せない。コードから引ければ十分で、載せると失効後も
リスナ ID が残る。

### 4.3 方式 C — カメラ側での承認（最高保証）

共有秘密を一切作らない方式。クライアントが接続を要求し、カメラが可否を出す。

- クライアントは何らかの手段でカメラを特定（同一アカウント内の一覧など）し
  `POST /v1/peer/connect` を投げる
- grant が無い場合、プロキシは接続を **`pending_approval`** で保持し、カメラに
  `peer.approval.request` を通知
- カメラの UI に「Endpoint `ep_ab12…` からの接続要求。許可しますか」を表示
- 許可すると grant が作られ、その接続がそのまま進む

**制約**: カメラに人が居ることが前提。無人カメラでは使えない。

### 4.4 比較

| | 導入操作 | 他者へ付与 | 無人カメラ | 共有秘密 |
| --- | --- | --- | --- | --- |
| A 同一アカウント | 不要 | 不可 | 可 | 無し |
| B ペアリングコード | コードを 1 回運ぶ | 可 | 可 | 短命コード |
| C 承認プロンプト | 承認を 1 回押す | 可 | **不可** | 無し |

**既定は A + B**。C は任意で有効化する。

---

## 5. 実行時プロトコル

### 5.1 Grant — 認可の永続化

現行の `capability` は「1 接続ぶんの持ち出し可能なトークン」だった。これを
**リスナ上の永続的な許可リスト（grant）**に置き換える。

```jsonc
{
  "grant_id":        "gr_...",
  "listener_id":     "pl_...",
  "allowed_endpoint":"ep_...",   // 許可する Endpoint
  "protocol":        "mjpeg",
  "auto_accept":     true,        // カメラ側で自動 bind してよいか
  "created_at":      "...",
  "expires_at":      null,        // null = 無期限。運用で期限を切ってもよい
  "label":           "masa's iPhone"  // 人が見て分かる名前
}
```

`capability` は**廃止しない**。第三者への一時的な委譲（ゲスト共有、期限付き）に
は依然として有用なので、grant と並存させ、`connect` はどちらでも通す。

### 5.2 Discovery — クライアントは繋げる先を自分で知る

`listener_id` を運ばなくてよくなる。

```
GET /v1/peer/listeners
```

呼び出した Endpoint が grant を持つ（または同一所有者の）リスナだけを返す。

```jsonc
{ "listeners": [
  { "listener_id": "pl_...", "label": "居間のカメラ", "protocol": "mjpeg",
    "online": true, "last_seen": "2026-08-01T12:00:00Z" }
]}
```

`online` は §5.4 の通知チャネルが張られているかで決まる。**繋がらないカメラを
一覧で先に分からせる**ことが、失敗のわかりにくさを大きく減らす。

### 5.3 Connect — capability を省略可能にする

```jsonc
POST /v1/peer/connect
{ "listener_id": "pl_...", "protocol": "mjpeg", "candidates": [] }
// capability は任意。省略時は grant / 同一所有者で認可する
```

応答は現行の `PeerConnection` のまま。`state` に新しい値が入りうる（§7）。

### 5.4 通知チャネル — 本提案の中核

**現状これが存在しない。** リスナは `bind` のときに初めてリレーレグを開くので、
接続を待っている間プロキシからカメラへ何も送れない。ここを埋める。

#### 採用案: 制御プレーン上のイベントストリーム

```
GET /v1/peer-listeners/{id}/events
Accept: application/x-ndjson
```

長寿命のレスポンスボディに、1 行 1 イベントの JSON を流す。

- **認証は既存のまま**（Endpoint Token + PoP）。新しい認証経路を作らない
- **トランスポートは既存のまま**。`ControlPlaneTransport`（H3 over msquic）が
  そのまま使える。`h3-util` のストリーミングボディで実装できる
- **NAT を通る**。クライアント発の接続なので穴あけ不要
- **リレーのデータ経路と分離される**。シグナリングが映像の輻輳に巻き込まれない

イベント:

```jsonc
{"type":"peer.connect.request","connection_id":"conn_...","endpoint_id":"ep_...","grant_id":"gr_...","expires_at":"..."}
{"type":"peer.approval.request","connection_id":"conn_...","endpoint_id":"ep_..."}   // 方式 C
{"type":"peer.connect.cancelled","connection_id":"conn_..."}
{"type":"grant.revoked","grant_id":"gr_..."}
{"type":"keepalive"}
```

#### 取りこぼしへの対処: 再接続時に照合する

イベントログとカーソルを作るのは大げさで、壊れ方も分かりにくい。代わりに
**再接続のたびに現在の保留一覧を取り直す**。

```
GET /v1/peer-listeners/{id}/connections?state=pending_bind
```

プロキシ側は保留接続を TTL 付きで保持しているので（§7）、これで十分に収束する。
「ストリームは速い経路、照合が正しさの担保」という役割分担にする。

#### 代替案

| | 内容 | 不採用の理由 |
| --- | --- | --- |
| CONNECT-UDP bind セッションに相乗り | `channel-masque` の `MasqueClientEvent` は既に通知の仕組みを持つ | シグナリングがリレーのデータプレーンに結合する。現状 bind レグは接続ごとに開くので、常時接続化の改修が要る |
| ポーリング（`GET /v1/peer-listeners/{id}`） | 実装が最小 | 遅延と負荷。ただし**イベントストリーム未対応のプロキシに対するフォールバックとして残す価値はある**（§9） |
| WebSocket / WebTransport | 双方向 | 現状の制御プレーンが HTTP なので、片方向で足りるものに双方向を持ち込む理由が無い |

### 5.5 自動 bind とローカルポリシー

カメラは `peer.connect.request` を受けたら、**ローカルポリシーに照らして**
自動的に `bind` する。

```rust
pub enum AcceptPolicy {
    /// grant があれば無条件で受ける（既定）
    Auto,
    /// 受けるが、UI に表示して事後的に切断できる
    AutoNotify,
    /// 毎回確認する（方式 C 相当）
    Prompt,
    /// 自動受理しない（現行の手動 bind のみ）
    Manual,
}
```

`Auto` でも次は無条件にしない。

- **同時接続数の上限**（既定 4 程度）。超過分は拒否し、理由を返す
- **grant の失効確認**。プロキシ側でも見るが、カメラ側でも見る（多層防御）

---

## 6. API 変更案

### 6.1 プロキシ制御プレーン（提案）

| メソッド | パス | 用途 |
| --- | --- | --- |
| `POST` | `/v1/peer-listeners/{id}/pairing-codes` | ペアリングコード発行（方式 B） |
| `POST` | `/v1/peer/pair` | コードを提示して grant を得る（クライアント側） |
| `GET` | `/v1/peer-listeners/{id}/grants` | grant 一覧 |
| `DELETE` | `/v1/peer-listeners/{id}/grants/{grant_id}` | grant 失効 |
| `GET` | `/v1/peer-listeners/{id}/events` | **イベントストリーム** |
| `GET` | `/v1/peer-listeners/{id}/connections` | 接続一覧（`state` で絞り込み） |
| `POST` | `/v1/peer/connections/{id}/accept` | 保留接続の承認（方式 C） |
| `POST` | `/v1/peer/connections/{id}/reject` | 保留接続の拒否 |
| `GET` | `/v1/peer/listeners` | **クライアントが繋げるリスナ一覧** |
| `POST` | `/v1/peer/connect` | `capability` を任意化（既存の変更） |

### 6.2 `isekai-p2p-core::proxy`

```rust
impl<T: ControlPlaneTransport> ProxyClient<T> {
    // --- リスナ側 ---
    pub async fn create_pairing_code(&self, listener_id: &str, ttl: Option<u64>)
        -> Result<PairingCode, ProxyError>;
    pub async fn list_grants(&self, listener_id: &str)
        -> Result<Vec<Grant>, ProxyError>;
    pub async fn revoke_grant(&self, listener_id: &str, grant_id: &str)
        -> Result<(), ProxyError>;
    /// 長寿命ストリーム。切断されたら呼び直す（再接続は呼び出し側の責務）。
    pub async fn subscribe_events(&self, listener_id: &str)
        -> Result<impl Stream<Item = Result<ListenerEvent, ProxyError>>, ProxyError>;
    pub async fn list_connections(&self, listener_id: &str, state: Option<&str>)
        -> Result<Vec<PeerConnection>, ProxyError>;
    pub async fn accept_connection(&self, connection_id: &str) -> Result<(), ProxyError>;
    pub async fn reject_connection(&self, connection_id: &str, reason: &str)
        -> Result<(), ProxyError>;

    // --- クライアント側 ---
    pub async fn pair(&self, code: &str) -> Result<Grant, ProxyError>;
    pub async fn list_reachable_listeners(&self) -> Result<Vec<ReachableListener>, ProxyError>;
}
```

### 6.3 `isekai-p2p::ListenerSession`

自動応答は**セッションが自分で回す**。呼び出し側が通知を捌く必要は無くする。

```rust
impl ListenerSession {
    /// イベントを購読し、ポリシーに従って自動で bind し続ける。
    /// 再接続と保留照合はこの中で行う。`shutdown` で終わる。
    pub fn serve_signaling(
        &self,
        policy: AcceptPolicy,
        shutdown: CancellationToken,
    ) -> SignalingHandle;
}

pub struct SignalingHandle {
    /// UI 表示用。接続の受理・拒否・失敗が流れる。
    pub events: mpsc::Receiver<SignalingEvent>,
    /// `AcceptPolicy::Prompt` のときの応答口。
    pub decisions: mpsc::Sender<Decision>,
}
```

### 6.4 `isekai-p2p::InitiatorSession`

```rust
impl InitiatorSession {
    /// grant / 同一所有者による接続。capability を渡さない。
    pub async fn connect_to_listener(
        cfg: &P2pConfig,
        listener_id: &str,
        local_bind: SocketAddr,
        opts: RelayOptions,
    ) -> anyhow::Result<Self>;
}
```

### 6.5 アプリ

**camera-server**

- 「Bind Relay」ボタンは**既定で不要**になる（`AcceptPolicy::Manual` のときだけ残す）
- 追加: ペアリングコード表示（QR）、接続中の端末一覧、grant 一覧と失効ボタン
- `serve_signaling` を起動時に開始

**camera-client / iOS**

- Listener ID / Capability の入力欄を**接続可能なカメラの一覧**に置き換える
- 追加: QR 撮影またはコード入力によるペアリング
- 現行の手入力は「詳細」に残す（§9）

---

## 7. 接続の状態遷移

```
                  ┌─────────────────┐
   connect ──────>│ pending_bind    │──── リスナが bind ────> established
                  └─────────────────┘
                       │        │
       TTL 超過 ───────┘        └──── リスナが reject ─────> rejected
            ↓
         expired

  （方式 C のとき）
   connect ─────> pending_approval ──── accept ───> pending_bind
                        │
                        └──── reject / TTL ───> rejected / expired
```

| 状態 | 意味 | タイムアウト案 |
| --- | --- | --- |
| `pending_bind` | 認可済み。リスナの bind 待ち | 60 秒 |
| `pending_approval` | 人間の承認待ち（方式 C） | 120 秒 |
| `established` | リレー開通 | — |
| `rejected` / `expired` | 終了 | — |

**`pending_bind` の 60 秒はカメラがオンラインである前提の値**である。オフラインの
カメラに対しては、そもそも `connect` を `409 listener_offline` で即座に断る。
「待たせてから失敗する」のが一番わかりにくいので、分かる時点で分かる形にする。

クライアント側の待ち時間（`VIDEO_CONNECT_DEADLINE`）は、自動化後は人間の作業を
跨がなくなるので**短く戻してよい**（現行 900 秒 → 60 秒程度）。ただし手動経路を
選んだときは長いままにする。

---

## 8. セキュリティ考察

### 8.1 認可

- grant の検査は**プロキシで必ず行う**。カメラ側の検査は多層防御であって代替ではない
- 失効は即時反映する。`grant.revoked` を通知し、**確立済みの接続も切る**
- 同一アカウント自動許可（方式 A）は、Identity 側の所有者情報が信頼できることに
  全面的に依存する。アカウント乗っ取りは全カメラの侵害に直結するため、
  **リスナ単位で無効化できる**ようにする

### 8.2 ペアリングコードの扱い

コードは短期間だが本物のベアラ秘密になる。以下をすべて満たすこと。

- **有効期限 5 分以内**、**単回使用**、使用後は即座に無効化
- **エントロピー**: 表示用に短くする場合（6〜8 文字）は、**試行回数制限**で補う。
  リスナごとに 5 回失敗でそのコードを失効させる
- **列挙耐性**: 誤ったコードへの応答は一様にし、失敗理由を区別させない
- **スコープ**: コードは 1 リスナ・1 grant のみを生む。プロトコルも固定する
- QR に載せる場合も同じ扱い。**スクリーンショットが流出したら失効させる**運用を
  ドキュメントに書く

### 8.3 濫用

- 認可済み Endpoint による**接続の大量生成**: grant ごとの同時接続上限と
  レート制限。カメラ側にも上限（§5.5）
- **リスナの列挙**: `GET /v1/peer/listeners` は grant を持つものだけ返す。
  存在しない `listener_id` への `connect` は、認可が無い場合と同じ応答にする

### 8.4 プライバシ

- grant には `label`（端末名）を持たせるが、これは**所有者にしか見せない**
- 接続一覧に相手の Endpoint ID を出すのは所有者に対してのみ

### 8.5 変わらないこと

映像そのものの機密性・完全性は端点間の QUIC/TLS で保たれ、本提案は何も変えない。
プロキシは暗号文の中継のみを行う。

---

## 9. 互換性と移行

- **すべて加算的**。既存の `capability` + 手動 `bind` の経路はそのまま残す
- クライアントは `GET /v1/peer/listeners` が `404` を返すプロキシに対して
  自動的に手動モードへ落ちる（機能検出）
- リスナは `subscribe_events` が `404` の場合、**ポーリングへフォールバック**する
  （`GET /v1/peer-listeners/{id}/connections?state=pending_bind` を 5 秒間隔）。
  自動化の効果は保ったまま、プロキシ側の実装を待たずに進められる
- アプリの UI は「かんたん接続（既定）」と「手動（詳細）」の 2 モードにする

---

## 10. 実装フェーズ

各フェーズは単独でマージ可能・単独で価値がある形にする。

| Phase | 内容 | 依存 |
| --- | --- | --- |
| 0 | 本書のレビューと、プロキシ本体仕様との突き合わせ。§6.1 の確定 | — |
| 1 | **プロキシ**: grant / pairing code / `GET /v1/peer/listeners` / `connect` の capability 任意化 | 0 |
| 2 | `isekai-p2p-core::proxy` に §6.2 のクライアント側メソッド。単体テスト | 1 |
| 3 | **ポーリング版の自動 bind**。`ListenerSession::serve_signaling` をポーリングで実装 | 2 |
| 4 | カメラアプリ: ペアリング UI（QR 表示 / 撮影）、カメラ一覧、grant 管理 | 3 |
| 5 | **プロキシ**: イベントストリーム。リスナ側を購読へ切り替え（ポーリングはフォールバックとして残す） | 3 |
| 6 | 方式 C（承認プロンプト）と `AcceptPolicy` の残りの値 | 5 |
| 7 | 実機 E2E、`VIDEO_CONNECT_DEADLINE` の見直し、ドキュメント更新 | 6 |

**Phase 3 で手作業は実質的に消える。** イベントストリーム（Phase 5）は遅延と
負荷の改善であって、機能の前提ではない。この順序なら、プロキシ側の大きい改修を
待たずに体験を先に良くできる。

---

## 11. リスクと未確定事項

| # | 項目 | 影響 | 対策 |
| --- | --- | --- | --- |
| 1 | プロキシ本体仕様（`spec §8`）に grant 相当の概念が既にある可能性 | 二重実装 | **Phase 0 で確認する。** 本書はこのリポジトリから見える範囲だけで書いており、プロキシ実装は未確認 |
| 2 | Identity が Endpoint の所有者を制御プレーンに伝えているか不明 | 方式 A が成立しない | Phase 0 で確認。成立しない場合は方式 B を既定にする |
| 3 | H3 の長寿命レスポンスボディがプロキシ／中間装置のタイムアウトに耐えるか | イベントストリームが頻繁に切れる | `keepalive` イベントを 15 秒間隔。切断は異常ではなく通常として扱い、再接続＋照合で収束させる（§5.4） |
| 4 | ペアリングコードの短さと総当たり耐性のトレードオフ | 不正な grant | §8.2。**表示を短くするなら試行制限は必須**であり、任意にはしない |
| 5 | 自動受理により、意図しない接続が無言で成立する | プライバシ | 既定を `Auto` にしつつ、**接続中の端末を常に UI に出す**。`AutoNotify` を選べるようにする |
| 6 | カメラがオフラインのときのクライアント体験 | 分かりにくい失敗 | `online` を一覧に出し、`connect` は `409 listener_offline` で即断する（§7） |
| 7 | grant 失効が確立済み接続に伝わらない | 失効が効かない | `grant.revoked` 通知でカメラ側から切断。プロキシ側でもリレーを落とす |
| 8 | 同時接続数の上限をどこで持つか（プロキシ／カメラ） | 二重管理 | 両方。プロキシは課金・濫用対策、カメラは自機の負荷。値は別々でよい |
| 9 | 既存の手動フローとの UI 併存 | 複雑化 | 「かんたん」を既定、手動は詳細に畳む（§9） |
| 10 | iOS の QR 撮影にカメラ権限が要る | 権限拒否時に詰む | コード手入力を必ず併設する |

---

## 12. 検証計画

### 12.1 自動テスト

- grant の認可判定（許可／不許可／失効後／期限切れ）
- ペアリングコード: 単回使用、期限切れ、試行制限、リスナ跨ぎの拒否
- `serve_signaling`: ポーリング版・ストリーム版とも、保留接続を拾って bind する
- 再接続時の照合で、切断中に発生した接続を取りこぼさない
- `AcceptPolicy` の各値の挙動、同時接続上限

### 12.2 手動 E2E（実プロキシ）

`docs/p2p_mode_migration_plan.md` §6.2 の環境をそのまま使う。

1. 方式 A: 同一アカウントの iOS 端末から、**何も入力せず**カメラ一覧 → 接続 → 再生
2. 方式 B: 別アカウントの端末に QR でペアリング → 接続 → 再生
3. grant 失効中に接続が切れること
4. カメラをオフラインにして、一覧に `offline` が出て即座に断られること
5. 自動接続後も **Direct への切り替えが従来どおり動く**こと（migration との相互作用）

### 12.3 観測ポイント

- `connect` から `established` までの所要時間（手作業込みの現行と比較する）
- イベントストリームの切断頻度と再接続の収束時間
- ペアリング失敗の理由別カウント

---

## 13. 未解決の設計判断

本書で決め切っていない点。Phase 0 で結論を出す。

1. **grant を誰が持つか。** リスナ（カメラ）に紐づけるか、所有者アカウントに
   紐づけるか。後者ならカメラを買い替えても grant が残るが、リスナ単位の
   細かい制御ができなくなる。
2. **`capability` の将来。** grant で置き換わったあと、期限付き委譲の用途だけ
   残すのか、grant に `expires_at` を持たせて一本化するのか。
3. **複数カメラの扱い。** 1 台の端末が複数のリスナを持つ構成（多眼）を
   一覧でどう見せるか。
