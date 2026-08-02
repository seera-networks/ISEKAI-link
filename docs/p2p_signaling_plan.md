# P2P 自動シグナリング 仕様案

現在の P2P 接続は、Listener ID・Capability・Connection ID・Endpoint ID の 4 値を
人間が手で運んでいる。本書はこれを **接続のたびには何も運ばなくてよい** 形に
置き換える設計案をまとめる。

対象は `isekai-p2p-core` / `isekai-p2p` / カメラアプリ、および
**MASQUE プロキシの制御プレーン**（`ISEKAI-link-server`）。

§2 にプロキシ実装との突き合わせ結果を置く。**そこで見つかった防御境界により、
初版で既定にしていた方式を改めている**（§4.1）。

参照: `ISEKAI-link-server/docs/p2p_connect_spec.md`（以下「サーバ仕様」）、
`rust/isekai-link-server/src/p2p/`。

---

## 1. 現状と、何が煩雑なのか

### 1.1 いま運んでいる 4 値

`docs/p2p_library_plan.md` §3.5 のとおり、接続 1 回につき手作業が 2 往復ある。

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

さらに `capability` は **TTL 30〜300 秒・one-shot**（サーバ仕様 §8.3, §11.2）
である。設計上そもそも「今から接続する 1 回のための受け渡し用トークン」であって、
継続的な許可を表現する道具ではない。人手で運ぶ前提の値が、人手で運ぶには短い。

### 1.2 自動化してよいもの／人間に残すもの

4 値のうち、**セキュリティ上の判断はひとつしかない**。

> 「この Endpoint が、このカメラに接続してよい」

残りはすべて機械的な受け渡しである。したがって設計方針は次のとおり。

- **判断は人間に残す。ただし 1 回だけ**（=導入時）。
- **接続ごとの受け渡しはゼロにする**。

---

## 2. プロキシ実装との突き合わせ結果

初版で「Phase 0 で確認する」としていた 2 点を確認した。

### 2.1 grant 相当の概念は存在しない — 新設が必要

`p2p/mod.rs` の router にあるのは以下のみで、永続的な許可リストに相当するものは
無い。

```
POST   /v1/peer-listeners
GET    /v1/peer-listeners/{id}          DELETE /v1/peer-listeners/{id}
POST   /v1/peer-listeners/{id}/capability
POST   /v1/peer/connect
GET    /v1/peer/certificate
GET    /v1/peer/connections/{id}        POST /v1/peer/connections/{id}/state
```

`p2p.db` のテーブルも `peer_listeners` / `capabilities` / `peer_connections` /
`public_listeners` の 4 つで、grant に相当するものは無い（サーバ仕様 §10.2）。
**二重実装の心配は無く、新設して差し支えない。**

### 2.2 所有者情報は渡っている — ただし「使ってよい」とは書かれていない

Endpoint Token の claim に `sub`（`auth0|123456`）があり（サーバ仕様 §5.4）、
`peer_listeners` テーブルは **`owner_sub` を保持している**。
`store.rs` に `listener_owner_sub()` もあり、`peer_connect` から実際に呼ばれる。

**したがって技術的には所有者一致の判定ができる。** ただし ──

### 2.3 ★ 見つかった防御境界: 所有者一致で認可してはならない

サーバ仕様 §11.3 が、変更してはならない防御境界として明記している。

> **fail-closed なリレー認可**: Endpoint 単位。**ユーザー一致では通さない。**

§8.7 も同じことを繰り返している。

> リレーエッジを利用できるのは **当事者 Endpoint のみ**。判定は PoP で証明された
> Endpoint ID に対して行うため、**同一ユーザーの別デバイスは利用できない**（fail-closed）。

そして `handlers.rs` の `peer_connect` にあるコメントは、`sub` を保存する意図を
はっきり限定している。

```rust
// Capture each party's Auth0 sub for auditing and for correlation with the
// user-level records. Authorization of the relay legs is endpoint-scoped
// (`initiator_endpoint` / `target_endpoint`), not sub-scoped.
```

つまり `owner_sub` は **監査と相関のために保存されている**のであって、認可の
入力ではない。

**初版の方式 A（同一アカウントなら capability 無しで通す）は、この境界に
正面から反する。** データプレーンの認可は Endpoint 単位のままだとしても、
制御プレーンで `sub` 一致を認可に使えば、境界が意図している性質
── 認可されたのはこの端末であって、この人の全端末ではない ── が崩れる。

**§4.1 でこの方式を作り直した。** 「所有者一致を認可に使う」のではなく、
「所有者一致を **grant 自動作成のきっかけ** に使う」形にすれば、接続時の認可は
最後まで Endpoint 単位のままで、しかも失効と可視化ができる。

### 2.4 その他、設計に影響する実装事実

| 事実 | 出典 | 本書への影響 |
| --- | --- | --- |
| 接続は `POST /v1/peer/connect` の時点で作成され、状態は即 `relay`。`pending` に相当する状態は無い | §8.4, §8.5.2 | §7 の状態遷移を作り直した |
| 接続の TTL は既定 300 秒（`--p2p-connect-ttl-secs`） | §8.4 | これが「相手の bind を待てる時間」の上限になる |
| 接続状態は `relay` / `hole_punching` / `direct` / `closed` の 4 値 | §8.5.2 | 方式 C は**新しい状態の追加**を伴う。小さくない変更 |
| `permissions` は**完全一致のみ**、ワイルドカード不可 | §5.4 | 新 API には新しい permission 文字列が要り、**Identity API 側の発行にも手が入る** |
| `Idempotency-Key` を系統 B の POST が既にサポート | §5.5 | ペアリングはこれに乗せる |
| Listener に `metadata` object がある | §8.2.1 | ラベルは新フィールドを足さずここに置ける |
| Listener / Connection は当事者以外には常に `404`（存在の秘匿）も防御境界 | §11.3 | 一覧 API は grant を持つものだけ返す（§5.2）。境界と整合 |
| `p2p.db` は SQLite、Listener 削除時に FK カスケード | §10.2 | grant も `listener_id` FK でカスケードさせる |
| ストリーミング応答の実装は**存在しない** | 実装確認 | §5.4 は新規。Phase 5 に置いた理由でもある |

---

## 3. 設計原則

1. **認可の単位を変えない。** 接続時の認可入力は最後まで **Endpoint ID** であり、
   `sub` ではない（§2.3）。
2. **新しいベアラ秘密をデータ経路に増やさない。** 認証は現行どおり
   Endpoint Token + PoP。導入時のペアリングコードだけは例外で、短命・単回・
   試行制限で封じ込める（§8.2）。
3. **プロキシは仲介であって信頼の起点ではない。** 映像そのものは端点間の QUIC で
   保護される。
4. **既存の手動経路を壊さない。** 新方式は加算的に入れ、当面は併存させる。
5. **カメラ側に最終拒否権を残す。** 自動受理はカメラのローカル設定であり、
   プロキシが強制するものではない。

---

## 4. 導入（ペアリング）の方式

### 4.1 方式 A — 所有者一致による grant の自動作成（推奨・既定）

**自分のカメラを自分の端末から見る**という最も多い場合を、導入操作ゼロにする。
ただし §2.3 の境界を守るため、**認可の経路には `sub` を入れない**。

```
   端末を登録             ┌─────────────────────────────┐
   （Identity）      ───> │ プロキシ: owner_sub が一致   │
                          │ する listener に対して        │
                          │ grant(listener, endpoint) を  │
                          │ 自動作成                      │
                          └─────────────────────────────┘
                                      │
   接続時                             ▼
   POST /v1/peer/connect ───> grant があるか？（Endpoint 単位）───> 許可
```

差は小さく見えるが、性質がまるで違う。

| | 初版の方式 A（却下） | 改訂後 |
| --- | --- | --- |
| 接続時に見るもの | `sub` の一致 | **grant レコード（Endpoint 単位）** |
| 失効 | できない（アカウントごと消すしかない） | **grant を消せば即座に** |
| 可視化 | 一覧に出ない | **一覧に出る** |
| 監査 | 「同一ユーザーだったから」 | **どの grant で通ったか** |
| §11.3 との関係 | **反する** | 適合（認可は Endpoint 単位のまま） |

`sub` の一致は **grant を作るきっかけ**にすぎず、作られた grant は他の方式で
作られたものと完全に同じ扱いになる。

自動作成のタイミングは 2 案あり、Phase 1 で決める。

- **(a) 遅延作成**: `connect` 時に grant が無く、かつ所有者が一致する場合に
  grant を作ってから通す。実装が 1 箇所で済むが、「認可の直前に認可を作る」形
  になるため、監査ログ上で自動作成と通常許可の区別を明示する必要がある。
- **(b) 事前作成**: リスナ作成時／Endpoint 登録時に、同一所有者の既存 Endpoint
  との組み合わせぶんを作る。境界としてはこちらが素直だが、**Identity 側からの
  通知が要る**（新規 Endpoint 登録をプロキシが知る手段が現状ない）。

**当面は (a) を採り、監査ログで区別する。** リスナ単位で
`owner_auto_grant: false` にして無効化できるようにする。

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

`listener_id` は載せない。コードから引ければ十分で、載せると失効後もリスナ ID が
残る（存在の秘匿・サーバ仕様 §11.3 と整合させる）。

### 4.3 方式 C — カメラ側での承認（最高保証）

共有秘密を一切作らない方式。クライアントが接続を要求し、カメラが可否を出す。

**これは接続状態の追加を伴う。** 現状 `POST /v1/peer/connect` は接続を作って
即 `relay` を返す（§2.4）ので、「認可待ちで保留する」状態が新たに要る。
サーバ仕様 §8.5.2 の状態集合とリレーエッジ確保の順序に手が入るため、
**A・B より明確に重い**。Phase 6 に置いた理由である。

### 4.4 比較

| | 導入操作 | 他者へ付与 | 無人カメラ | 共有秘密 | 実装の重さ |
| --- | --- | --- | --- | --- | --- |
| A 所有者一致で grant 自動作成 | **不要** | 不可 | 可 | 無し | 小 |
| B ペアリングコード | コードを 1 回運ぶ | 可 | 可 | 短命コード | 中 |
| C 承認プロンプト | 承認を押す | 可 | **不可** | 無し | 大（状態追加） |

**既定は A + B**。C は任意。

---

## 5. 実行時プロトコル

### 5.1 Grant — 認可の永続化

`capability`（TTL 30〜300 秒・one-shot）を置き換えるのではなく、**その手前に
永続的な許可を置く**。

`p2p.db` に 1 テーブル追加する。既存の `capabilities` と同じく
`listener_id` の FK でカスケード削除させる。

| テーブル | 主なカラム |
| --- | --- |
| `peer_grants` | `grant_id`, `listener_id`(FK→cascade), `owner_endpoint`, `allowed_endpoint`, `protocol`, `auto_accept`, `origin`(`manual`/`pairing`/`owner_match`), `label`, `created_at`, `expires_at`(NULL 可), `revoked_at` |

`origin` は監査のために必須にする（§4.1 (a) の要請）。

`capability` は**廃止しない**。期限付きの一時委譲（ゲスト共有）には引き続き
適している。`connect` は grant / capability のどちらでも通す。

### 5.2 Discovery — クライアントは繋げる先を自分で知る

`listener_id` を運ばなくてよくなる。

```
GET /v1/peer/listeners
```

呼び出した Endpoint が **grant を持つ**リスナだけを返す。存在の秘匿（§11.3）と
整合する。

```jsonc
{ "listeners": [
  { "listener_id": "pl_...", "metadata": { "label": "居間のカメラ" },
    "protocol": "mjpeg", "online": true, "last_seen": "2026-08-02T12:00:00Z" }
]}
```

`online` は §5.4 の通知チャネルが張られているかで決まる。**繋がらないカメラを
一覧の時点で分からせる**ことが、失敗のわかりにくさを大きく減らす。

### 5.3 Connect — capability を任意化する

```jsonc
POST /v1/peer/connect
{ "listener_id": "pl_...", "protocol": "mjpeg", "candidates": [] }
// capability は任意。省略時は grant で認可する
```

サーバ仕様 §8.4 の検証順序に **grant の確認**を挿す。

1. `peer-connect:initiate` 権限
2. 候補アドレスの検証
3. Endpoint Token の `protocols` との照合
4. **capability があれば消費、無ければ grant を確認**（listener 一致 /
   `allowed_endpoint` 一致 / 未失効 / 未期限切れ / protocol 一致）
5. 接続作成 → リレーエッジ確保（**ここは一切変えない**）

応答は現行のまま。`target_endpoint` は grant から決まる。

### 5.4 通知チャネル — 本提案の中核

**現状これが存在しない**（§2.4）。リスナは `bind` のときに初めてリレーレグを
開くので、接続を待っている間プロキシからカメラへ何も送れない。ここを埋める。

#### 採用案: 制御プレーン上のイベントストリーム

```
GET /v1/peer-listeners/{id}/events
Accept: application/x-ndjson
```

長寿命のレスポンスボディに、1 行 1 イベントの JSON を流す。

- **認証は既存のまま**（Endpoint Token + PoP、`endpoint_auth` レイヤ）
- **トランスポートは既存のまま**。`ControlPlaneTransport`（H3 over msquic）が
  そのまま使える
- **NAT を通る**。クライアント発の接続なので穴あけ不要
- **リレーのデータ経路と分離される**。シグナリングが映像の輻輳に巻き込まれない

イベント:

```jsonc
{"type":"peer.connect.created","connection_id":"conn_...","endpoint_id":"ep_...","grant_id":"gr_...","expires_at":"..."}
{"type":"peer.connect.closed","connection_id":"conn_..."}
{"type":"grant.revoked","grant_id":"gr_..."}
{"type":"keepalive"}
```

#### 取りこぼしへの対処: 再接続時に照合する

イベントログとカーソルを作るのは大げさで、壊れ方も分かりにくい。代わりに
**再接続のたびに現在の接続一覧を取り直す**。

```
GET /v1/peer-listeners/{id}/connections?state=relay
```

接続は 300 秒の TTL で保持されている（§2.4）ので、これで収束する。
「ストリームは速い経路、照合が正しさの担保」という役割分担にする。

#### 代替案

| | 内容 | 不採用の理由 |
| --- | --- | --- |
| CONNECT-UDP bind セッションに相乗り | `channel-masque` の `MasqueClientEvent` は既に通知の仕組みを持つ | シグナリングがリレーのデータプレーンに結合する。bind レグは接続ごとに開くので常時接続化の改修が要る。`seera-signaling-session-id` はクライアント制御値で当事者検証が必須（§11.3）であり、シグナリングの土台にするには筋が悪い |
| ポーリング（`GET /v1/peer-listeners/{id}/connections`） | 実装が最小。**既存 API のみで可能** | 遅延と負荷。ただし **Phase 3 の実装手段**として採用し、以後もフォールバックとして残す |
| WebSocket / WebTransport | 双方向 | 片方向で足りるものに双方向を持ち込む理由が無い |

### 5.5 自動 bind とローカルポリシー

カメラは通知（またはポーリング結果）を受けたら、**ローカルポリシーに照らして**
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

`Auto` でも無条件にはしない。

- **同時接続数の上限**（既定 4 程度）。超過分は受けない
- **grant の失効確認**。プロキシ側でも見るが、カメラ側でも見る（多層防御）

---

## 6. API 変更案

### 6.1 プロキシ制御プレーン

| メソッド | パス | 必要 permission |
| --- | --- | --- |
| `POST` | `/v1/peer-listeners/{id}/pairing-codes` | `peer-grant:create`（新設） |
| `POST` | `/v1/peer/pair` | `peer-grant:accept`（新設） |
| `GET` | `/v1/peer-listeners/{id}/grants` | `peer-connect:accept`（既存で足りる） |
| `DELETE` | `/v1/peer-listeners/{id}/grants/{grant_id}` | `peer-grant:create` |
| `GET` | `/v1/peer-listeners/{id}/events` | `peer-connect:accept` |
| `GET` | `/v1/peer-listeners/{id}/connections` | `peer-connect:accept` |
| `GET` | `/v1/peer/listeners` | `peer-connect:initiate` |
| `POST` | `/v1/peer/connect` | 既存（`capability` を任意化） |

**`permissions` は完全一致でワイルドカード不可**（サーバ仕様 §5.4）なので、
新設分は **Identity API 側の Endpoint Token 発行にも手が入る**。
ここは `ISEKAI-identity` リポジトリとの調整が要る。既存の
`peer-connect:accept` / `peer-connect:initiate` で足りる範囲は流用し、
新設は最小限（2 つ）に抑えている。

方式 C を実装する場合は、これに加えて
`POST /v1/peer/connections/{id}/accept` / `.../reject` と、接続状態の追加が要る。

### 6.2 `isekai-p2p-core::proxy`

```rust
impl<T: ControlPlaneTransport> ProxyClient<T> {
    // --- リスナ側 ---
    pub async fn create_pairing_code(&self, listener_id: &str, ttl: Option<u64>)
        -> Result<PairingCode, ProxyError>;
    pub async fn list_grants(&self, listener_id: &str) -> Result<Vec<Grant>, ProxyError>;
    pub async fn revoke_grant(&self, listener_id: &str, grant_id: &str)
        -> Result<(), ProxyError>;
    pub async fn list_connections(&self, listener_id: &str, state: Option<&str>)
        -> Result<Vec<PeerConnection>, ProxyError>;
    /// 長寿命ストリーム。切断されたら呼び直す（再接続は呼び出し側の責務）。
    pub async fn subscribe_events(&self, listener_id: &str)
        -> Result<impl Stream<Item = Result<ListenerEvent, ProxyError>>, ProxyError>;

    // --- クライアント側 ---
    pub async fn pair(&self, code: &str) -> Result<Grant, ProxyError>;
    pub async fn list_reachable_listeners(&self) -> Result<Vec<ReachableListener>, ProxyError>;
}
```

### 6.3 `isekai-p2p::ListenerSession`

自動応答は**セッションが自分で回す**。呼び出し側が通知を捌く必要は無くする。

```rust
impl ListenerSession {
    /// 接続要求を拾ってポリシーに従い bind し続ける。ストリームが使えれば
    /// 使い、駄目ならポーリングへ落ちる。再接続と照合はこの中で行う。
    pub fn serve_signaling(
        &self,
        policy: AcceptPolicy,
        shutdown: CancellationToken,
    ) -> SignalingHandle;
}

pub struct SignalingHandle {
    /// UI 表示用。受理・拒否・失敗が流れる。
    pub events: mpsc::Receiver<SignalingEvent>,
    /// `AcceptPolicy::Prompt` のときの応答口。
    pub decisions: mpsc::Sender<Decision>,
}
```

### 6.4 `isekai-p2p::InitiatorSession`

```rust
impl InitiatorSession {
    /// grant による接続。capability を渡さない。
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

- 「Bind Relay」は `AcceptPolicy::Manual` のときだけ残す
- 追加: ペアリングコード表示（QR）、接続中の端末一覧、grant 一覧と失効
- 起動時に `serve_signaling` を開始

**camera-client / iOS**

- Listener ID / Capability の入力欄を**接続可能なカメラの一覧**に置き換える
- 追加: QR 撮影またはコード入力によるペアリング
- 現行の手入力は「詳細」に残す（§9）

---

## 7. 接続の状態とタイムアウト

**新しい状態は増やさない**（方式 C を除く）。既存の
`relay` / `hole_punching` / `direct` / `closed`（サーバ仕様 §8.5.2）のままで
成立する。自動化で変わるのは「誰が `bind` を起こすか」だけである。

```
POST /v1/peer/connect
   │  grant を確認 → 接続を作成（state=relay, TTL 300 秒）
   ▼
 relay ──── リスナが通知/ポーリングで気づき bind ────> リレー開通
   │                                                    │
   │                                                    └─> hole_punching → direct
   └──── 300 秒内に bind されなければ掃引で消滅
```

| 事象 | 現行 | 自動化後 |
| --- | --- | --- |
| 誰が `bind` する | 人間が `connection_id` を運んでから操作 | リスナが自動 |
| 待ち時間の上限 | 接続 TTL 300 秒（人間の作業を跨ぐ） | 同 300 秒（機械の応答のみ） |
| カメラがオフライン | 300 秒待って失敗 | **`connect` を即座に断る**（下記） |

オフラインのカメラには `409 listener-offline` を新設して即断する。
**「待たせてから失敗する」のが一番わかりにくい**ので、分かる時点で分かる形にする。

クライアント側の待ち時間（`VIDEO_CONNECT_DEADLINE`、現行 900 秒）は、自動化後は
人間の作業を跨がなくなるので**接続 TTL に合わせて短く戻せる**。ただし手動経路を
選んだときは長いままにする。

方式 C を入れる場合のみ `pending_approval` を追加する（§4.3）。

---

## 8. セキュリティ考察

### 8.1 認可 — 既存の境界を崩さない

- **接続時の認可入力は Endpoint ID のみ**。`sub` は grant 作成のきっかけと監査に
  しか使わない（§2.3, §4.1）
- リレーエッジの認可（サーバ仕様 §8.7）には**一切手を入れない**
- grant の検査は**プロキシで必ず行う**。カメラ側の検査は多層防御であって代替ではない
- 失効は即時反映する。`grant.revoked` を通知し、**確立済みの接続も切る**
- 所有者一致による自動作成は**リスナ単位で無効化できる**ようにする。アカウント
  乗っ取りの影響範囲を運用で絞れる余地を残す

### 8.2 ペアリングコードの扱い

コードは短期間だが本物のベアラ秘密になる。以下をすべて満たすこと。

- **有効期限 5 分以内**、**単回使用**、使用後は即座に無効化
- **エントロピー**: 表示用に短くする場合（6〜8 文字）は、**試行回数制限**で補う。
  リスナごとに 5 回失敗でそのコードを失効させる
- **列挙耐性**: 誤ったコードへの応答は一様にし、失敗理由を区別させない
- **スコープ**: コードは 1 リスナ・1 grant のみを生む。protocol も固定する
- **保存はハッシュのみ**。`capabilities` が既にそうしている（サーバ仕様 §11.1）
  ので、同じ扱いに揃える
- QR も同じ扱い。**スクリーンショットが流出したら失効させる**運用を明記する

### 8.3 濫用

- 認可済み Endpoint による**接続の大量生成**: grant ごとの同時接続上限と
  レート制限。カメラ側にも上限（§5.5）
- **grant の総数**: `--p2p-listener-quota`（既定 32）と同様に grant にも
  クォータを設ける
- **リスナの列挙**: `GET /v1/peer/listeners` は grant を持つものだけ返す。
  存在しない `listener_id` への `connect` は、認可が無い場合と同じ応答にする
  （サーバ仕様 §11.3 の「存在の秘匿」）

### 8.4 プライバシ

- grant の `label`（端末名）は**所有者にしか見せない**
- 接続一覧に相手の Endpoint ID を出すのは所有者に対してのみ

### 8.5 変わらないこと

映像の機密性・完全性は端点間の QUIC/TLS で保たれ、本提案は何も変えない。
プロキシは暗号文の中継のみを行う。

---

## 9. 互換性と移行

- **すべて加算的**。既存の `capability` + 手動 `bind` の経路はそのまま残す
- クライアントは `GET /v1/peer/listeners` が `404` を返すプロキシに対して
  自動的に手動モードへ落ちる（機能検出）
- リスナは `subscribe_events` が `404` の場合、**ポーリングへフォールバック**する。
  Phase 3 はそもそもポーリングで実装するので、この経路は最初から動いている
- アプリの UI は「かんたん接続（既定）」と「手動（詳細）」の 2 モードにする

---

## 10. 実装フェーズ

各フェーズは単独でマージ可能・単独で価値がある形にする。

| Phase | 内容 | リポジトリ | 依存 |
| --- | --- | --- | --- |
| 0 | §4.1 の (a)/(b)、§13 の 3 点を決める。permission 名を Identity と調整 | 設計 | — |
| 1 | `peer_grants` テーブル、grant CRUD、`connect` の capability 任意化、所有者一致の自動作成 | link-server | 0 |
| 2 | ペアリングコード API、`GET /v1/peer/listeners` | link-server | 1 |
| 3 | `isekai-p2p-core::proxy` にクライアント側メソッド。**`serve_signaling` をポーリングで実装** | ISEKAI-link | 2 |
| 4 | カメラアプリ: ペアリング UI（QR 表示/撮影）、カメラ一覧、grant 管理 | ISEKAI-link | 3 |
| 5 | イベントストリーム（サーバ側）＋購読への切り替え（クライアント側） | 両方 | 4 |
| 6 | 方式 C（承認プロンプト、状態追加） | 両方 | 5 |
| 7 | 実機 E2E、`VIDEO_CONNECT_DEADLINE` 見直し、ドキュメント更新 | ISEKAI-link | 6 |

**Phase 4 の完了時点で手作業は実質的に消える。** イベントストリーム（Phase 5）は
遅延と負荷の改善であって機能の前提ではない。この順序なら、サーバ側の大きい改修を
待たずに体験を先に良くできる。

---

## 11. リスクと未確定事項

| # | 項目 | 影響 | 対策 |
| --- | --- | --- | --- |
| 1 | ~~プロキシ本体仕様に grant 相当の概念が既にある可能性~~ | — | **解消**: 存在しないことを実装で確認（§2.1） |
| 2 | ~~Identity が Endpoint の所有者を制御プレーンに伝えているか~~ | — | **解消**: `owner_sub` として保持され、`listener_owner_sub()` もある（§2.2）。ただし #3 |
| 3 | **所有者一致を認可に使うことをサーバ仕様 §11.3 が禁じている** | 初版の方式 A が成立しない | **設計変更済み**: 所有者一致は grant 自動作成のきっかけに留め、認可入力は Endpoint 単位のまま（§4.1）。**この解釈自体をサーバ仕様の所有者に確認すること** |
| 4 | 新 permission の発行に Identity 側の変更が要る | Phase 1〜2 が別リポジトリに依存 | Phase 0 で名前を確定し、`ISEKAI-identity` と並行で進める。既存 permission で足りる分は流用済み（§6.1） |
| 5 | H3 の長寿命レスポンスボディが中間装置のタイムアウトに耐えるか | ストリームが頻繁に切れる | `keepalive` を 15 秒間隔。切断は異常でなく通常として扱い、再接続＋照合で収束（§5.4）。**Phase 3 のポーリング実装が常にフォールバックとして残る** |
| 6 | ペアリングコードの短さと総当たり耐性のトレードオフ | 不正な grant | §8.2。**表示を短くするなら試行制限は必須**であり、任意にはしない |
| 7 | 自動受理により意図しない接続が無言で成立する | プライバシ | 既定を `Auto` にしつつ、**接続中の端末を常に UI に出す**。`AutoNotify` を選べる |
| 8 | カメラがオフラインのときの体験 | 分かりにくい失敗 | `online` を一覧に出し、`connect` は `409 listener-offline` で即断（§7） |
| 9 | grant 失効が確立済み接続に伝わらない | 失効が効かない | `grant.revoked` 通知でカメラ側から切断。プロキシ側でもリレーエッジを落とす |
| 10 | 方式 C は接続状態の追加を伴い、リレーエッジ確保の順序に影響する | 想定より重い | Phase 6 に隔離。A・B だけで運用は成立する |
| 11 | 既存の手動フローとの UI 併存 | 複雑化 | 「かんたん」を既定、手動は詳細に畳む（§9） |
| 12 | iOS の QR 撮影にカメラ権限が要る | 権限拒否時に詰む | コード手入力を必ず併設する |

---

## 12. 検証計画

### 12.1 自動テスト（link-server）

- grant の認可判定（許可／不許可／失効後／期限切れ／protocol 不一致）
- 所有者一致による自動作成が、**`origin` を記録し、リスナ単位で無効化できる**こと
- ペアリングコード: 単回使用、期限切れ、試行制限、リスナ跨ぎの拒否、ハッシュ保存
- `GET /v1/peer/listeners` が grant の無いリスナを**返さない**こと
- 存在しない `listener_id` と認可の無い `listener_id` の応答が**区別できない**こと

### 12.2 自動テスト（ISEKAI-link）

- `serve_signaling`: ポーリング版・ストリーム版とも接続を拾って bind する
- 再接続時の照合で、切断中に発生した接続を取りこぼさない
- `AcceptPolicy` の各値の挙動、同時接続上限

### 12.3 手動 E2E（実プロキシ）

`docs/p2p_mode_migration_plan.md` §6.2 の環境をそのまま使う。

1. 方式 A: 同一アカウントの iOS 端末から、**何も入力せず**一覧 → 接続 → 再生
2. 方式 B: 別アカウントの端末に QR でペアリング → 接続 → 再生
3. grant 失効で接続が切れること
4. カメラをオフラインにして、一覧に `offline` が出て即座に断られること
5. 自動接続後も **Direct への切り替えが従来どおり動く**こと（migration との相互作用）

### 12.4 観測ポイント

- `connect` から映像が出るまでの所要時間（手作業込みの現行と比較）
- イベントストリームの切断頻度と再接続の収束時間
- ペアリング失敗の理由別カウント

---

## 13. 未解決の設計判断

Phase 0 で結論を出す。

1. **所有者一致による自動作成のタイミング** — §4.1 の (a) 遅延作成か
   (b) 事前作成か。(b) は Identity からの Endpoint 登録通知が要る。
2. **grant を誰に紐づけるか** — リスナ（カメラ）か、所有者アカウントか。
   後者ならカメラを買い替えても grant が残るが、リスナ単位の制御ができなくなる。
3. **`capability` の将来** — 期限付き委譲の用途だけ残すのか、grant の
   `expires_at` に一本化するのか。
4. **`sub` を認可のきっかけに使うことの是非** — §4.1 は §11.3 の境界を守ると
   判断しているが、**この解釈はサーバ仕様の所有者に確認する**（リスク #3）。
