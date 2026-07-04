use argh::FromArgs;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use webrtc::{
    api::APIBuilder,
    data_channel::{RTCDataChannel, data_channel_message::DataChannelMessage},
    ice_transport::ice_candidate::RTCIceCandidateInit,
    peer_connection::{
        RTCPeerConnection, configuration::RTCConfiguration,
        peer_connection_state::RTCPeerConnectionState,
        sdp::session_description::RTCSessionDescription,
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalMessage {
    pub r#type: SignalType,
    pub from: Option<String>,
    pub to: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SignalType {
    Join,
    Offer,
    Answer,
    Candidate,
    Peers,
}

#[derive(FromArgs, Clone)]
/// server args
pub struct CmdOptions {
    /// target address of the MASQUE server
    #[argh(option)]
    target: String,

    /// session ID for the WebRTC connection
    #[argh(option)]
    session_id: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let cmd_opts: CmdOptions = argh::from_env();

    let signaling_url = format!(
        "wss://{}/sessions/{}/ws",
        cmd_opts.target, cmd_opts.session_id
    );

    println!("🔌 connecting signaling: {}", signaling_url);

    let (ws, _) = connect_async(signaling_url).await?;
    let (write, mut read) = ws.split();
    let write = Arc::new(Mutex::new(write));

    let join_msg = SignalMessage {
        r#type: SignalType::Join,
        from: Some("app".to_string()),
        to: None,
        payload: serde_json::json!({
          "behind_agent": true,
        }),
    };
    let text = serde_json::to_string(&join_msg)?;
    write.lock().await.send(text.into()).await?;

    let api = APIBuilder::new().build();
    let peers: Arc<Mutex<HashMap<String, Arc<RTCPeerConnection>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let dc_map: Arc<Mutex<HashMap<String, Arc<RTCDataChannel>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut pending_candidates: HashMap<String, Vec<RTCIceCandidateInit>> = HashMap::new();

    println!("⏳ waiting offer...");

    while let Some(msg) = read.next().await {
        let msg = msg?;
        let text = msg.to_text()?;
        let msg = serde_json::from_str::<SignalMessage>(&text)?;

        println!("📩 received: {:?}", msg);

        match msg.r#type {
            SignalType::Offer => {
                let Some(from) = msg.from else {
                    println!("⚠️ offer missing from field");
                    continue;
                };

                // ✅ 新しい PeerConnection
                let pc = Arc::new(api.new_peer_connection(RTCConfiguration::default()).await?);

                peers.lock().await.insert(from.clone(), pc.clone());

                let dc_map_clone = dc_map.clone();
                let from_clone = from.clone();
                // ✅ DataChannel receive
                pc.on_data_channel(Box::new(move |dc| {
                    println!("✅ DataChannel: {}", dc.label());
                    let dc_map = dc_map_clone.clone();
                    let from = from_clone.clone();
                    let dc_map2 = dc_map_clone.clone();
                    let from2 = from_clone.clone();
                    Box::pin(async move {
                        dc_map.lock().await.insert(from.clone(), dc.clone());

                        let dc_for_message = dc.clone();
                        let dc_for_close = dc.clone();
                        dc_for_message.on_message(Box::new(move |msg: DataChannelMessage| {
                            let data = match String::from_utf8(msg.data.to_vec()) {
                                Ok(data) => data,
                                Err(_) => {
                                    println!("⚠️ non-UTF8 DataChannel message received");
                                    return Box::pin(async {});
                                }
                            };
                            let dc_map_clone = dc_map.clone();
                            let from_clone = from.clone();
                            let dc2 = dc.clone();

                            Box::pin(async move {
                                // ✅ JSONとして解析
                                if let Ok(json) = serde_json::from_str::<Value>(&data) {
                                    match json["type"].as_str() {
                                        Some("ping") => {
                                            // ===== ping受信 =====
                                            let (Some(id), Some(t)) =
                                                (json["id"].as_str(), json["t"].as_f64())
                                            else {
                                                println!("⚠️ malformed ping payload: missing id/t");
                                                return;
                                            };

                                            let pong = serde_json::json!({
                                                "type": "pong",
                                                "id": id,
                                                "t": t
                                            });

                                            if let Err(err) = dc2.send_text(pong.to_string()).await
                                            {
                                                println!("⚠️ failed to send pong: {}", err);
                                            }
                                        }
                                        Some("message") => {
                                            // ===== 通常メッセージ =====
                                            let Some(text) = json["text"].as_str() else {
                                                println!(
                                                    "⚠️ malformed message payload: missing text"
                                                );
                                                return;
                                            };
                                            let echo = serde_json::json!({
                                                "type": "echo",
                                                "text": format!("echo: {}", text)
                                            });
                                            if let Err(err) = dc2.send_text(echo.to_string()).await
                                            {
                                                println!("⚠️ failed to send echo: {}", err);
                                            }
                                        }
                                        Some("chat") => {
                                            // ===== チャットメッセージ =====
                                            let Some(text) = json["text"].as_str() else {
                                                println!("⚠️ malformed chat payload: missing text");
                                                return;
                                            };
                                            let dcs: Vec<(String, Arc<RTCDataChannel>)> = {
                                                let dc_map = dc_map_clone.lock().await;
                                                dc_map
                                                    .iter()
                                                    .map(|(k, v)| (k.clone(), v.clone()))
                                                    .collect()
                                            };

                                            for (peer_id, dc) in dcs.iter() {
                                                if peer_id != &from_clone {
                                                    let chat_msg = serde_json::json!({
                                                        "type": "chat",
                                                        "from": from_clone,
                                                        "text": text
                                                    });
                                                    if let Err(err) =
                                                        dc.send_text(chat_msg.to_string()).await
                                                    {
                                                        println!(
                                                            "⚠️ failed to send chat to {}: {}",
                                                            peer_id, err
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                } else {
                                    println!("📩 received (non-JSON): {}", data);
                                }
                            })
                        }));

                        dc_for_close.on_close(Box::new(move || {
                            let dc_map = dc_map2.clone();
                            let from = from2.clone();
                            Box::pin(async move {
                                if let Some(dc) = dc_map.lock().await.remove(&from) {
                                    println!("❌ DataChannel closed: {}", dc.label());
                                }
                            })
                        }))
                    })
                }));

                pc.on_ice_connection_state_change(Box::new(move |state| {
                    println!("ICE state: {:?}", state);
                    Box::pin(async {})
                }));

                let peers_clone = peers.clone();
                let from_clone = from.clone();
                pc.on_peer_connection_state_change(Box::new(move |state| {
                    println!("PC state: {:?}", state);
                    let from = from_clone.clone();
                    let peers = peers_clone.clone();
                    Box::pin(async move {
                        if state == RTCPeerConnectionState::Failed
                            || state == RTCPeerConnectionState::Disconnected
                            || state == RTCPeerConnectionState::Closed
                        {
                            remove_peer(&peers, &from).await;
                        }
                    })
                }));

                let Some(sdp) = msg.payload["sdp"].as_str() else {
                    println!("⚠️ offer missing sdp field");
                    continue;
                };
                let offer = RTCSessionDescription::offer(sdp.to_string())?;

                pc.set_remote_description(offer).await?;

                if let Some(candidates) = pending_candidates.remove(&from) {
                    for c in candidates {
                        println!("✅ add pending candidate: {:?}", c);
                        pc.add_ice_candidate(c).await?;
                    }
                }

                let answer = pc.create_answer(None).await?;
                pc.set_local_description(answer.clone()).await?;

                let answer_msg = SignalMessage {
                    r#type: SignalType::Answer,
                    from: Some("app".to_string()),
                    to: Some(from.clone()),
                    payload: serde_json::json!({
                        "type": "answer",
                        "sdp": answer.sdp
                    }),
                };
                let text = serde_json::to_string(&answer_msg)?;

                let mut ws_write = write.lock().await;
                ws_write.send(Message::Text(text.into())).await?;
                println!("✅ answer sent");
            }

            SignalType::Candidate => {
                let Some(from) = msg.from else {
                    println!("⚠️ candidate missing from field");
                    continue;
                };
                let Some(pc) = peers.lock().await.get(&from).cloned() else {
                    println!("⚠️ candidate from unknown peer: {}", from);
                    continue;
                };
                let c = msg.payload.clone();

                let candidate: RTCIceCandidateInit = match serde_json::from_value(c) {
                    Ok(candidate) => candidate,
                    Err(_) => {
                        println!("⚠️ malformed candidate payload");
                        continue;
                    }
                };

                if pc.remote_description().await.is_none() {
                    println!("⏳ queue candidate");
                    pending_candidates
                        .entry(from.clone())
                        .or_insert_with(Vec::new)
                        .push(candidate);
                } else {
                    println!("✅ add candidate");
                    pc.add_ice_candidate(candidate).await?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

async fn remove_peer(peers: &Arc<Mutex<HashMap<String, Arc<RTCPeerConnection>>>>, id: &str) {
    if let Some(pc) = peers.lock().await.remove(id) {
        println!("🧹 removing peer {}", id);
        let id = id.to_string();
        tokio::spawn(async move {
            if let Err(e) = pc.close().await {
                println!("Error closing peer connection: {:?}", e);
            } else {
                println!("Peer connection closed: {}", id);
            }
        });
    }
}
