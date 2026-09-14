# Tunneling LLM Chat Over MASQUE: the ISEKAI Portal Client

## Main Topic

Where `camera-client` streams live video from an ISEKAI-paired device, the ISEKAI Portal
client takes the opposite shape: a small Android chat app that forwards HTTP requests to a
locally-running Ollama instance on a remote box, over the same relay stack. It's built on
`portal-core` and `isekai-p2p` — the same forwarding protocol and session/relay machinery
the camera apps use — proving out the general-purpose half of ISEKAI link: instead of a
hardcoded video path, an operator declares a named service in a catalogue, and any paired
peer can reach it as if it were local.

## Reusing the Relay, Changing the Stream Shape

`portal-core`'s forwarding model is deliberately generic: one bidirectional QUIC stream
per TCP connection, and datagrams keyed by session id for UDP. That's a different shape
from `camera-client`'s one-unidirectional-stream-per-frame design — there's no "drop the
stale frame" logic here, because a chat request isn't live media, it's a regular
request/response HTTP exchange that just happens to be tunneled. The same relay and
certificate machinery underneath (`isekai-p2p`) serves both without change; only the
catalogue entry differs.

## The Catalogue Is the Whole Policy

The Jetson (an NVIDIA edge board — small enough to sit on a desk, with enough GPU to run a
local LLM) runs `portal-server`, started with a service catalogue that declares exactly one
entry:

```toml
[service.ollama]
protocol = "tcp"
target = "127.0.0.1:11434"
```

The client asks for a service **by name** ("ollama") — never an address — so a paired peer
can reach only what the catalogue explicitly offers, and the initiator can never name an
arbitrary target. This catalogue is deliberately kept out of `portal-server`'s default
config path/name specifically because Ollama has no auth of its own — a catalogue picked
up silently by an operator who forgot `--config` would hand a raw local LLM endpoint to any
paired peer.

## Streaming as a Liveness Signal

The first working version used Ollama's `stream: false` and waited for the whole reply. It
looked broken — long silent gaps over the tunnel read like a dead connection, not a
thinking model. Switching to `stream: true` (Ollama's newline-delimited-JSON streaming
format) fixed the *perception* of the problem without changing the underlying latency: real
bytes now cross the tunnel continuously while the model generates, the same principle
behind the camera product's decision to keep relay keepalives flowing rather than let a
path go quiet.

## Model Choice Is Just a Config String

The model running this time is `qwen3.5:4b` — chosen because it fits comfortably in this
Jetson Orin Nano's GPU memory alongside everything else sharing the box, not because anything
upstream of Ollama cares which model it is. Neither `portal-core`'s forwarding nor the
client's HTTP layer look at the model name beyond passing it through in the `/api/chat`
request body. Any open-weights model works as a drop-in replacement, as long as it fits the
on-premise xPU hardware it's meant to run on — the tradeoff is entirely local (VRAM budget,
cold-load time, tokens/sec), not architectural.

## Multi-Turn Memory Is Resent, Not Stored

Ollama keeps no state between requests on either `/api/generate` or `/api/chat` — a client
has to resend everything it wants remembered. The first version of this app didn't: every
request went to `/api/generate` with only the current turn's text, so each reply was
effectively the first message the model had ever seen.

The fix switched the client to `/api/chat`. The Send handler captures `chatLog` before
appending this turn's placeholder entries, and that history is translated into
`/api/chat`'s `messages` array (`"you"` → role `user`, `"ollama"` → role `assistant`;
`"error"` entries are skipped, since they aren't real conversation content), with the new
turn appended last. Response parsing changes to match — each streamed line's text now lives
under `message.content` rather than `/api/generate`'s flat `response` field.

Verified live, the simplest way that actually proves memory rather than just plausible
continuation: telling the model "My favorite color is teal." in one message, then asking
"What is my favorite color?" in a separate one, got back "Teal." — while confirming the
system prompt's instructions still held under the new request shape.

The tradeoff this leaves open: there's no context truncation, so the full conversation is
resent on every turn and token count grows unbounded with conversation length. Fine for a
demo's scope; a real deployment would need a truncation or summarization strategy before
this stopped being true.

## Auth, Inherited Wholesale

The endpoint-key/Auth0 device-flow pairing model is identical to `camera-client`'s: a fresh
ECDSA key generated and persisted on first launch, an Auth0 sign-in (with a manual-token
paste as fallback when Auth0 itself is unreachable), and a pairing Grant tied to the
Endpoint ID rather than the session — meaning it survives `portal-server` restarts on the
Jetson without needing to be re-paired.

## Design Philosophy

The interesting result isn't the chat UI — it's that swapping "stream video frames" for
"tunnel a stateless HTTP API" required no change to the relay, the pairing model, or the
transport. Only the catalogue entry and the client's own read-timeout/streaming choices
changed. That's the bet the generic service-catalogue design was making, and it held.
