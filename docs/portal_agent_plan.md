---
title: portal-client を Agent Runtime として動かす — agent_access 段階 3
status: draft
related: agent_access_spec_draft.md（ISEKAI-link-server 側）, portal_gateway_plan.md
---

# portal-client を Agent Runtime として動かす

`agent_access_spec_draft.md` の**段階 3**:

> **Runtime：タスク単位の Endpoint と、絞ったトークンの発行（§3.4.1）**

Agent Runtime に相当するのは `portal-client` である。本書はそこに
**agent モード**を足す計画。

> 以下、`§n` は本書の節。設計書を指すときは「**draft §n**」、Identity の仕様は
> 「**identity §n**」と書く。

---

## 0. 結論を先に

### 0.1 上流は揃っている。こちら側は思ったより揃っていない

| 要るもの | 状態 |
| --- | --- |
| `requested_protocols`（発行） | Identity 実装済み |
| `requested_protocols`（更新） | **送らない設計**（§3.3） |
| `requested_gateways` | Identity 実装済み／**クライアントに無い** |
| 発行がリース配布の引き金（draft §6.2.1） | Identity 実装済み |
| Gateway 側の受け取り（段階 2） | **`portal-server` 実装済み**（P0〜P5） |
| クライアントが絞りを送る経路 | **無い**（§0.4） |
| タスク単位の Endpoint | **無い** |
| Auth0 経路での自己失効 | **無い**（§2.3） |

> **初版はこの表を誤っていた。** 「`refresh_token` に `requested_protocols` がある」
> と書いたが、それは `issue_token` の引数を読み違えたものである。
> `refresh_token` は `(auth, key, challenge, ttl)` しか取らない — 意図的にそうで、
> 理由は §3.3 にある。

### 0.2 難しいのは絞りではなく、鍵の寿命

`portal-client` の鍵は `--key`（既定 `portal-client.pem`）で、**ファイルとして
残り続ける**。doc コメントが「新しい鍵は新しい Endpoint ID で、発行済みの
capability が意味を失う」と警告しているとおり、**鍵が残ることが前提の設計**である。

タスク単位の Endpoint はその逆を要求する。

```
タスク開始 → 鍵生成 → Identity に登録 → ep:A7-task1
タスク終了 → Endpoint を失効 → その名義の到達性はすべて消える
```

**鍵はタスクより長生きしてはならない。** 残れば、次のタスクが前のタスクの認可を
継ぐ経路になる — draft §3.4 が「トークンを絞るだけでは分離にならない」と書いている、
まさにその形である。

### 0.3 なぜ「トークンを絞る」だけでは足りないのか

draft §3.4 の中心。**Proxy が区別できるのは
`(owner_endpoint, allowed_endpoint, protocol)` までで、どのタスクかは見えない。**

```
タスク 1: ep:A7 / pg-sales-ro-v1 / R1 への Grant（TTL 1h）
タスク 1 終了
タスク 2: ep:A7 / pg-sales-ro-v1 / R2 を使う
   → タスク 1 の R1 Grant がまだ TTL 内なら、タスク 2 からも R1 に届く
```

**並行していなくても、Grant の TTL が重なれば起きる。** だから Endpoint を分ける。
本来の解（Grant のキーに `access_lease_id` を入れる）は Proxy の変更を要し、
段階 6 である。

### 0.4 絞りを送る経路が、そもそも繋がっていない

`IdentityClient::issue_token` は `requested_protocols` を取る。**しかし
`isekai-p2p` の Auth0 経路は、そこに必ず `None` を渡す。**

```rust
// config.rs の Auth0 分岐
client.issue_token(&auth0, &cfg.key, None, None, cfg.token_ttl)
//                                   ^^^^  ^^^^  permissions / protocols
```

`register_and_issue` も最後は同じ `issue_token(.., None, None, ..)` で終わる。
**そして agent モードは毎タスク新しい鍵なので、必ず `register` 経路を通る。**

つまり現状、**agent モードが得るトークンは初回から天井いっぱいになる。**
P0 は `P2pConfig` → `issue()` → `issue_token` と `register_and_issue` の
両方に絞りを通す仕事であり、「既存の呼び出し側は `None` を渡すだけ」では済まない。
---

## 1. agent モードとは何か

```
portal-client --agent --task <name> --protocol pg-sales-ro-v1 --gateway ep:R1 --map 5432:db
  ├─ タスク用の鍵を作る（ファイルに残さない）
  ├─ Identity に登録し、protocol と gateway を絞ってトークンを発行
  │    → その発行自体が Gateway へのリース配布の引き金になる（draft §6.2.1）
  ├─ Grant ができるのを待って接続し、転送する
  └─ 終了時に Endpoint を失効させる
```

**既存の動作を置き換えない。** `--agent` を渡さなければ今までどおりで、`--key` の
鍵も pairing も ticket もそのまま効く。

### 1.1 `--enroll` との違い

`portal-client --enroll`（CI 用）と形が似ているので、違いを明記する。

| | `--enroll`（CI） | `--agent`（本書） |
| --- | --- | --- |
| 誰が認証するか | Enrollment Key ＋ workload identity（人は居ない） | **Auth0 の人**（draft §6.2: 「A が Auth0 で認証した状態で」） |
| 鍵 | ファイル（`--key`）。枠を返して失効 | **メモリだけ**（§2.1） |
| 認可の出どころ | Provisioning Key の引き換え | **エンタイトルメント → リース → Grant** |
| 終了時 | 枠を返す（`release_enrollment`） | **Endpoint を失効させる** |

**失効の呼び出しは共有できない。** `--enroll` の
`portal_core::ci::release_the_slot` は `release_enrollment` を呼び、その先頭で

```rust
let Credential::Enrollment(enrollment) = &cfg.credential else {
    anyhow::bail!("only an Endpoint enrolled with a key can return its own slot");
};
```

と弾かれる。agent モードが持つのは `Credential::Auth0` なので、**そのまま流用すると
「枠を返せなかった、掃引に任せる」と警告して何も失効させない** — 後片付けが走った
ように見える無音の no-op である。

共有できるのは `main` の「`run` の後で呼ぶ」配管とシグナルの配線だけで、
**失効そのものは `RevokeAuth::Auth0` で作り直す**（§2.3）。

---

## 2. タスク単位の鍵

### 2.1 ファイルに残さない

**鍵はプロセスのメモリにだけ置く。** `--key` のようにファイルへ書くと、

- 次の起動が同じ Endpoint を名乗り、前タスクの Grant を継ぐ
- 失効させても**ファイルは残る**ので、「失効済み Endpoint の鍵」が転がる

`load_or_generate_key` は「無ければ作ってファイルに書く」なので、agent モードは
**それを呼ばない**。`EndpointKey` を生成して持つだけにする。

> **`--key` と併せて渡されたら拒否する。** 「タスク単位の鍵」と「保存された鍵」は
> 両立しない要求であり、黙ってどちらかを選ぶと、選ばれなかったほうを期待していた
> 運用者が**分離されているつもりで分離されていない**状態になる。

### 2.2 鍵をメモリだけに置くと、Auth0 のセッションの置き場が消える

`run` は**鍵のパスからトークン置き場を導いている**。

```rust
args.auth0_tokens.clone().unwrap_or_else(|| portal_core::login::tokens_beside(&args.key))
```

鍵ファイルが無く `--key` も拒否するなら、この既定は意味を持たない。
**`--agent` は `--auth0-tokens` を必須にする。**

なお `--key` は `#[argh(option, default = ...)]` なので、**「渡されなかった」と
「既定値が渡された」を区別できない。** §2.1 の拒否を実装するには
`Option<PathBuf>` に変える必要があり、`tokens_beside` と
「鍵が無ければ作ると言う」通知を含む既存の参照すべてに及ぶ。

### 2.3 Auth0 経路での自己失効は、まだ無い

`revoke_endpoint` の `RevokeAuth::Auth0` は `reason` を要求し、その語彙は
`device_lost` / `endpoint_deleted` / `admin_revoke` / `security_incident` の
4 つだけである。

**「タスクが終わった」に当たる語が無い。** 鍵経路の `enrollment_released` は
まさにそのために在る（「ジョブが片付けた」と「時間が片付けた」を区別するため）が、
Enrollment Key が無いと使えない。

取りうるのは 2 つで、**どちらも決めずに実装を始めてはいけない**。

| 案 | 評価 |
| --- | --- |
| 上流に語を足す（`task_finished` 相当） | 正しい。監査ログで区別がつく。**上流の作業** |
| `endpoint_deleted` を流用する | 動くが、**監査ログで運用者の削除と見分けがつかなくなる** |

> **決着した。** ISEKAI-identity [#44](https://github.com/seera-networks/ISEKAI-identity/issues/44)
> を立て、[#45](https://github.com/seera-networks/ISEKAI-identity/pull/45) で **`task_finished`
> が要求語彙に入った**。鍵経路の `enrollment_released` に当たる語だが、**こちらは要求から
> 名乗る** — 処理が終わったことを知っているのはクライアント側だけで、Identity には
> 分からない（Auth0 経路には掃引も無い）。

> **Auth0 アクセストークンが終了時にも有効でなければならない。** つまり agent
> モードは `--login` の更新される経路を使い、**更新されない `--auth0-token` は
> 使えない** — 長いタスクの失効が 401 で死ぬ。

### 2.4 失効に失敗したときの後ろ盾は、実は無い

初版は「§8.8.8 の掃引が後ろに居る」と書いた。**誤りである。**

`endpoint_idle_ttl` は `NewEnrollmentKey` の項であり、`enrollment_idle` は
**鍵経路の理由**である。Auth0 経路で登録された Endpoint に Enrollment Key は無く、
したがって**その掃引は掛からない**。

つまり失効に失敗すれば、Endpoint と Grant は**掃引までではなく、無期限に**残る。

- リース切れは効く（§2.5）ので **Grant は 1 リース TTL 以内に消える**
- **しかし Endpoint は残る。** 到達性そのものは Grant が消えれば無くなるが、
  Endpoint の登録は残り続ける
- したがって失効の失敗は**警告ではなく、はっきりした失敗として報告する**。
  タスクの結果を失敗にするかは呼び出し側の判断だが、黙って済ませてはならない

### 2.5 リースは放っておけば切れる

draft §6.2.1: **「タスクが終わった」を誰かが伝える必要は無い。** トークンの更新が
リースの時計なので、プロセスが消えれば 1 リース TTL 以内に Grant も消える。

**失効はそれを待たないための手段**であって、代わりではない。

### 2.6 2 度目のシグナルは失効を飛ばす

`hard_exit_on_second_signal` は `_exit(128+sig)` を呼ぶ生のハンドラを入れる。
**2 度目の Ctrl-C は失効を飛ばす。** そして `release_the_slot` が居る位置は
`run` が返った後 — つまり `connected.close().await` の後ろで、その close が
詰まることこそハッチが救おうとしている事態である。

したがって**失効は接続を畳む前に行う**。順序を逆にすると、いちばん失効したい場面
（畳むのに手間取っている）で、いちばん失効されなくなる。

---

## 3. 絞ったトークン

### 3.1 要求する 2 つ

```jsonc
POST /v1/tokens/endpoint
{ "endpoint_id": "ep:A7-task1",
  "requested_protocols": ["pg-sales-ro-v1"],
  "requested_gateways": ["ep:R1"],
  "ttl": 900 }
```

- **`requested_protocols`** はトークンの claim になる。天井
  （ユーザーごとの protocol 集合）を超えては広がらない
- **`requested_gateways`** は claim ではない。**どのエンタイトルメントのリースを
  起こすか**の selector である（draft §6.2）

> **`requested_gateways` を既定の運用にする。** 省略するとそのクラスの全 Gateway に
> リースが起き、Grant が不要に広がる。**指定を必須**にはしないが、省略したときは
> 何が起きるかをログに出す。

### 3.2 足すのは 4 箇所で、`refresh_token` も含む

- `IdentityClient::issue_token` に `requested_gateways` を足す
- `register_and_issue` に絞りを通す（いま `None, None` で終わっている）
- `P2pConfig` → `isekai_p2p::config::issue()` の Auth0 分岐に通す（§0.4）
- **`refresh_token` に `requested_gateways` を足す**。理由は §3.3

> **本書は 2 度、ここを取り違えた。** 初版は「更新で送らなければ天井に戻る」と書き、
> 第 2 版はそれを正して「`refresh_token` には足さない」とした。**どちらも 3 つの軸を
> 1 つの規則で括っていた点が同じ**で、P0 の実装中にサーバの記述を読んで判明した。

### 3.3 記憶される 2 軸と、記憶されない 1 軸

`refresh_token` の契約は `permissions` と `protocols` についてはこうである。

> **Renewal never widens.** The result is `current ceiling ∩ the token being
> refreshed`, monotonically, so `requested_*` is not sent: it exists only to
> narrow further, and asking for the ceiling back is what re-issuing is for.

つまりこの 2 つは**「いまの天井 ∩ いま持っているトークン」**で、送らないことが
絞りを保つ。送る必要があるのは**さらに狭めたいとき**だけである。

**`requested_gateways` はこの規則の外にある。** サーバの `RefreshRequest` が明記して
いる — 「更新のたびに指定すること。省略するとそのクラスの全 Gateway のリースが
延びる。絞りの記憶（0-b）はトークンの permissions / protocols についてのもので、
こちらは記憶しない」。実装も `gateways.is_none_or(|list| list.contains(..))` で、
**省略は「全部」を意味する**。

これは claim ではなく selector（§3.1）だからで、記憶の対象ではない。したがって
**issue で 1 つの Gateway に絞っても、最初の更新で全 Gateway に広がる** — 15 分の
トークンなら 12 分後である。agent モードは寿命がトークンより長いタスクを走らせる
のだから、これは例外ではなく通常の経路に当たる。

### 3.4 `register` が更新のたびに再登録する

`Credential::Auth0` の `register` は静的な引数から来て、`issue()` が**更新のたびに
読み直す**。agent モードは毎タスク新しい鍵なので `register` を立てる必要があり、
すると**2 回目以降の更新が、登録済みの鍵を登録し直す**。

**Auth0 経路には `409 endpoint-already-registered` の受け皿が無い**（あるのは
enrollment 経路だけ、`already_registered`）。このままだと初回以降の更新が毎回失敗し、
後退し、**タスクの途中で Endpoint Token が切れる**。

取るべきは「初回成功後に `register` を下ろす」— enrollment 経路に 409 の腕を足すのと
どちらでもよいが、**片方は要る**。

> **P2 では両方入れた。** enrollment 経路が既にその形（`Arc<OnceCell<_>>` を
> `Credential` に持たせ、`409` を「もう在る」として成功に倒す）で書かれていて、理由も
> そこに書かれている — 登録は 1 度きりだが、**応答が返らないまま届いていた**場合が
> あり、`get_or_try_init` は失敗を記憶しないので、腕が無いと更新のたびに登録し直して
> 毎回 `409` を見る。Auth0 経路に同じ危険があって守りだけが無かった、というのが実際の
> ところである。

---

## 4. Grant を待つ

### 4.1 発行してすぐ繋いでも、まだ Grant は無い

draft §6.2.1 の経路は **Identity → Gateway → Proxy** で、非同期である。

```
トークン発行 → Identity が policy.granted を流す
             → Gateway が受け取り、属性を検証し、表に書き、Grant を作る
             → ようやく connect が通る
```

**発行の直後に `connect` しても繋がらない。** これは失敗ではなく**早すぎる**だけ
なので、そう扱う。

> **P3 で分かった実際の症状は `grant-invalid` ではない。** そこまで行かない —
> 到達先の一覧（`GET /v1/peer/listeners`）が**空で返る**。一覧に載る条件が
> Grant の存在なので、Grant が無い間はそもそも `connect` する listener が見つからず、
> クライアントは「nothing reachable」で止まる。待つ対象は一覧のほうである。
>
> **そして空一覧は Gateway 側の話とは限らない。** 相手のサーバが動いていない、別の
> protocol で待っている、`--peer` の Endpoint ID が違う、も同じ空である。諦めるときの
> 文面は両方を挙げる。

- 短い間隔で再試行し、上限を設ける
- 上限に達したら**理由を言って終わる**。「Gateway が受け取っていない」「属性が
  値域外で拒否された」「そもそも entitle されていない」の区別は**こちらからは
  つかない** — Gateway 側のログにしかない。だから**何を見ればよいかを言う**

> **待つ時間の目安は、Gateway のストリーム遅延である。** 通常は秒の単位だが、
> Gateway が落ちていれば再接続時の照合（identity §8.10.2）までかかる。
> **数十秒で諦め、待ち続けない。**

### 4.2 `protocol-not-allowed` を無限に再試行しているのは、既存のループである

初版は「2 つを同じ再試行に入れない」と書いたが、**両者はそもそも同じループに
居ない**。`grant-invalid` は proxy の `connect` が返す `ProxyError`、
`protocol-not-allowed` は **Identity のトークン発行**が返す `IdentityError` である。

本当の危険はその上流にある。**`spawn_token_renewal` は
`issue_endpoint_token` のあらゆる失敗を、後退しながら永久に再試行し、
`tracing::warn!` しか出さない。**

つまり `protocol-not-allowed` — エンタイトルメントを足す以外に変わりようのない
拒否 — が、**そこで無限に再試行される**。§4.2 が禁じたい形そのものが、既に在る。

> **発行でも返る。** 仕様 §8.2.1 のエラー一覧に `protocol-not-allowed` は無いが、
> 実装の `resolve_protocols` は発行経路でも（`Bound::Ceiling` で）これを返す。
> agent モードは `--protocol` で絞るので、**エンタイトルメントが無ければここに当たる**。
> P3 は状態コードで線を引いた — `403` は規則が拒否した答えで、同じ規則に訊き直しても
> 変わらない。`429` / `503` / `401` / 転送エラーは再試行のままにしてある。
>
> **ただし「終わる」は「訊かなくなる」ではない。** 初版の実装はループを `return` させ
> たが、それだと**運用者がエラーを読んでエンタイトルメントを足しても、そのプロセスは
> 二度と回復しない** — 現行トークンが切れ、以後すべての proxy 呼び出しが失敗し、ログ
> には何も出ず、再起動以外に戻る道が無い。実装は「`error` で 1 度言い、以後は 5 分
> 間隔で静かに訊き続ける」に落ち着いた。

**P3 はこのループに触る必要がある。** 天井の拒否は後退の対象ではなく、
**その場で言って終わる**ものである。

---

## 5. 段取り

| # | やること | 出口 |
| --- | --- | --- |
| **P0** ✅ | 絞りを `P2pConfig` → `issue()` → `issue_token` / `register_and_issue` に通す。`requested_gateways` を足す（§0.4、§3.2）。**更新でも selector を送り直す**（§3.3） | **発行したトークンが実際に絞られ、更新で広がらない** |
| **P1** ✅ | `--key` を `Option<PathBuf>` にし、`--agent` との併用を拒否。`--auth0-tokens` を必須に（§2.1、§2.2） | 「渡されたか」が判定できる |
| **P2** ✅ | メモリだけの鍵と登録。**初回成功後に `register` を下ろす**（§3.4）。`--gateway` / `--task` と絞りの配線 | タスク単位の Endpoint が、更新をまたいで生き続ける |
| **P3** ✅ | Grant を待つ（§4.1）。**天井の拒否を更新ループの再試行から外す**（§4.2） | 早すぎる接続で失敗せず、直らない失敗を回し続けない |
| **P4** ✅ | Auth0 経路の自己失効。**接続を畳む前に**（§2.6）。`reason` は `task_finished`（§2.3、identity#45） | タスクの到達性が残らない |
| **P5** ✅ | 実配備で端から端まで | **段階 2 と 3 が噛み合う** |

**P0 は単独で入るが、無害ではない。** 既存の呼び出し側は `None` を渡せばよく挙動は
変わらないが、触るのは `register_and_issue` を含む発行経路そのものである。

**P4 は §2.3 が決まるまで着手できなかった。** `reason` の語彙に「タスクが終わった」が
無く、上流に足すか `endpoint_deleted` を流用するかは**監査ログの読み方を変える
判断**であって、実装中に決めてよいことではない。上流が `task_finished` を足して
決着したので、P4 はそれを名乗る。

**P5 が本当の検収である。** ここまでの段階はどれも片側だけの確認で、
「エンタイトルメントを 1 行足すと agent が繋がり、タスクが終わると消える」を
通して見るまでは、段階 2 と 3 が噛み合っているとは言えない。

> **通した（2026-09-18）。** 実配備の Identity・Proxy に対し、`--gateway-config` を
> 与えた portal-server と `--agent` の portal-client で確認した。
>
> | 段階 | 観測 |
> | --- | --- |
> | トークン発行がリースを起こす | Gateway に `lease="al_…"` が現れる |
> | Identity → Gateway のストリームが運ぶ | 同上 |
> | Gateway が封筒を検査する | 属性が値域外の回は ``policy: not applied: attribute `region` is out of range: …`` で**適用しない** |
> | Grant ができる | `policy: granted … ttl=1739 leases=1 ours=true` |
> | agent が繋ぐ | `the Grant arrived waited=796ms` → `ready` → 直接経路へ移行 |
> | 実際に転送される | 転送先が返したバイト列がクライアント側の local port に届く |
> | タスク終了で失効 | `revoked this task's Endpoint (task_finished)` |
> | 失効が Gateway に届く | 120 ms 後に `policy: withdrawn … reason="endpoint-revoked"` と `policy: grant removed` |
>
> **§6.3 の数字が出た。** Grant が届くまでは **796 ms**。設計からの推測は「秒の単位」で、
> 実測はその下限側だった。§4.1 の待ち（30 秒）は 37 倍の余裕がある。
>
> **§6.4 のクォータは当たらなかった。** タスク単位 Endpoint を数回作っても何も拒否
> されていない。**当たらなかったことは「当たらない」ことの証明ではない**ので、項は
> 残す。

---

## 6. 確かめていないこと

1. ~~**`reason` をどうするか**（§2.3）~~ — 決着（identity#45、`task_finished`）
2. **エンタイトルメントを誰がどう登録するか。** identity §8.9 に API はあり、
   ISEKAI-dashboard に画面ができた。運用の段取り（誰が `ep:R1` を Gateway として
   登録し、誰が A に `pg-sales-ro-v1` を与えるか）は本書の外のままである。
   **P5 で 2 つ踏んだ**ので書き留めておく。
   - **エンタイトルメントは天井を置き換える。** 1 行でも書くと、その主体の天井は
     エンタイトルメントが全部になり、0-c の天井表もサーバ既定も足されない
     （identity `resolve_ceiling`、§7.1 の剥奪が効くようにするため意図的）。
     `pg-sales-ro-v1` だけを足すと **camera 系がトークンを発行できなくなる**。
     使っている protocol の分だけ行を足すこと。なお**消して戻すことはできない** —
     最後の 1 行の削除は空の天井行を書いて剥奪を終端する
   - **`gateway` が指す Endpoint を間違えても、どこも失敗しない。** 誰も名乗れない
     Gateway 宛の行でも天井には載りリースも立つ（§8.9.2 が明記）。Gateway 側の
     `offered=0` が唯一の手がかりだった
3. ~~**Grant が配られるまでの実測。**~~ — 出た。**796 ms**（P5、上の表）
4. **タスク単位 Endpoint が何のクォータに当たるか。** 初版は `max_live_endpoints`
   を挙げたが、**それは Enrollment Key から生えた Endpoint を数えるもの**で、
   Auth0 経路には掛からない。当たるとすればユーザーごとの登録上限のほうで、
   **どれなのかを確かめていない。** 名前を取り違えたまま P5 に臨むと、
   間違った失敗を探すことになる
5. **同じ人の複数タスクが並行したとき。** 天井はユーザー単位なので共有される
   （draft §6.2 の注）。分離は Endpoint 分割で行う、というのが第一版の答えだが、
   **クォータと衝突しないかは 4 番目と同じ話である**

## 7. この計画で解かないもの

1. **PEP の強制**（Gateway 側の別計画）。agent が操作を実行する話はその先
2. **エージェント単位 Endpoint に戻すこと**（draft §3.4.2、段階 6）。Proxy に
   `access_lease_id` を通す変更が要る
3. **scope の提示**（draft §6.4.1）。Gateway が操作一覧を見せる口
4. **オーケストレータとの関係。** 本書が決めるのは 1 タスクを走らせる形だけで、
   タスクを並べる仕組みは別である
