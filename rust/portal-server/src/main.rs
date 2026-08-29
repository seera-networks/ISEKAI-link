//! The side with the services.
//!
//! Declares what exists, waits for a client the proxy says is authorised, and
//! forwards each requested service to its target. Phase 1c-iii-c-ii of
//! `docs/portal_plan.md`.
//!
//! ```text
//! portal-server --auth0-token … --key ep.pem \
//!               --config portal-server.toml --allow ep:abc…
//! ```
//!
//! # The target never crosses the wire
//!
//! Services are named here and asked for **by name** (plan §4.3). A client that
//! could name a host and port would turn this into an open proxy into whatever
//! network it sits on — every device on that LAN, every link-local metadata
//! endpoint, every `127.0.0.1` service the operator never meant to expose. A
//! Grant says *these two Endpoints may talk*; it says nothing about what may be
//! reached, and it was never meant to.
//!
//! The catalogue is that file, and reading it is `portal_core::config`, which
//! is where the format and the reasoning live.
//!
//! # UDP services carry a size limit the file cannot raise
//!
//! `protocol = "udp"` is forwarded as of phase 3b, up to 1163 bytes per
//! datagram; anything larger is dropped and counted rather than split.
//! `portal_core::datagram::MAX_PAYLOAD` has the arithmetic and the case to know
//! about, which is a large DNS response.

use std::path::PathBuf;

use anyhow::Context as _;
use argh::FromArgs;
use isekai_p2p::agent::{BindingView, ProvisioningBinding};
use isekai_p2p::{load_or_generate_key, AcceptPolicy, P2pConfig};
use tokio_util::sync::CancellationToken;

/// Forward local TCP and UDP services to authorised peers over ISEKAI link.
///
/// A peer asks for a service **by name**. What each name means is this file's
/// business and never crosses the wire, so a caller cannot reach anything the
/// catalogue does not offer.
#[derive(FromArgs)]
#[argh(
    example = "\
portal-server --login

portal-server --key ./portal-server.pem --register --pair

portal-server --key ./portal-server.pem --config ./portal-server.toml

portal-server --grants",
    note = "\
Sign in once with --login. It runs the Auth0 device flow -- a code and a URL to
open -- and saves tokens beside the Endpoint key that refresh from then on, so
nothing else here needs a token.

--auth0-token still works and cannot be refreshed: when it expires the Endpoint
Token renewal stops being authorised and the session ends a few minutes later.
For a server meant to be left running that is the thing --login exists to fix.
",
    note = "\
The catalogue (--config), which is the whole of what may be reached:

  [service.db]
  protocol = \"tcp\"
  target   = \"10.0.0.5:5432\"

  [service.dns]
  protocol = \"udp\"
  target   = \"10.0.0.1:53\"

`target` is an address, never a hostname: resolving one would put a DNS answer
in charge of where forwarded traffic goes. `--example-config` writes a starter
file to stdout.

UDP payloads over 1163 bytes are dropped rather than split, and counted.
The case to know is a large DNS response; docs/portal.md has the arithmetic.
",
    note = "\
The proxy will not let two Endpoints talk until this side has authorised them,
and there are three ways to do it. They are not alternatives of equal standing.

--pair shows a code. Whoever redeems it gets a GRANT, which is reusable, has no
expiry unless one is set, and -- because a Grant's key does not name a listener
(spec 8.8) -- keeps working when this server restarts onto a new listener id.
That is what an installation should run on. Use --grants to see who is in and
--revoke to take it away.

Everything to do with authorising somebody answers and exits without serving:
--pair, --ticket, --tickets, --revoke-ticket, --grants and --revoke all act on
the Endpoint rather than on a listener, so a code can be issued while a server
is already running rather than only by starting one. --allow is the exception;
a capability is issued against the listener it is for.

--ticket also ends in a grant, but one that EXPIRES ON ITS OWN, and you can
have several outstanding at once -- a pairing code is one per protocol because
a person is reading it off a screen. So this is the one for work that ends: a
CI job, an agent sandbox, anywhere there is no screen and nobody to read a code
aloud. It prints one string to send; --tickets shows who spent which, which is
the only record of where a ticket went. --revoke-ticket stops an unused one.

--allow issues a CAPABILITY for one Endpoint. It is one-shot and lasts 300
seconds at most, so it is for letting a guest in once. A peer that reconnects
on one needs another.",
    note = "\
A PROVISIONING KEY is the fourth way, and it is not a ticket you can use twice.
A ticket is a piece of paper you hand over; this is an arrangement you install,
so it lives in a secret store rather than in a chat window, and everything
about it is shaped by that being a standing power somebody holds.

  --provisioning-key       issue one, printing the secret once
  --provisioning-keys      list them, with how full each one is
  --provisioning-redemptions <id>   who came in on one, and how often
  --revoke-provisioning-key <id>    stop it

Use it where the same automation connects over and over and nobody is there to
hand out a ticket per run -- CI being the case it exists for. Bind it with
--binding-oidc and --binding-subject so the key alone is not enough to get in;
without a binding it is a bearer secret, which is fine on a build machine you
own and wrong for a public repository.

Two things differ from --ticket and both matter. Redeeming again EXTENDS the
grant rather than being refused, which is how a job longer than --grant-ttl
keeps working. And revoking DELETES the grants it made, so running jobs stop --
the opposite of --revoke-ticket, and deliberately: you cannot see who came in
on a key without asking, so stopping one has to close the door it opened.

The peer spends it with portal-client, which reads it from
ISEKAI_PROVISIONING_KEY -- see 'Letting a CI job in' in docs/portal.md, and note
that the job also needs an Enrollment Key from the Identity side."
)]
struct Args {
    /// identity API base URL (HTTPS). Defaults to the deployment the camera
    /// apps use
    #[argh(
        option,
        default = "String::from(\"https://identity.isekai.tools:9443\")"
    )]
    identity_url: String,
    /// reach the Identity API over HTTP/3 instead of HTTP/1.1 + HTTP/2
    #[argh(switch)]
    identity_http3: bool,
    /// proxy base URL. Defaults to the deployment the camera apps use
    #[argh(
        option,
        default = "String::from(\"https://tokyo.link.isekai.tools:8443\")"
    )]
    proxy_url: String,
    /// auth0 access token, used only to obtain the Endpoint Token. Cannot be
    /// refreshed -- `--login` is what keeps a long-running server working.
    /// Not needed with --example-config
    #[argh(option)]
    auth0_token: Option<String>,
    /// sign in to Auth0 once, saving tokens that refresh from then on, and
    /// exit. This is what lets a server be left running: an --auth0-token
    /// expires and takes the session with it
    #[argh(switch)]
    login: bool,
    /// where the saved sign-in lives. Defaults to the Endpoint key's name with
    /// `-auth0.json` in place of its extension
    #[argh(option)]
    auth0_tokens: Option<PathBuf>,
    /// P2P protocol string
    #[argh(option, default = "String::from(\"isekai-portal-v1\")")]
    protocol: String,
    /// register the Endpoint before issuing a token (needed on first use of a
    /// freshly generated key)
    #[argh(switch)]
    register: bool,
    /// device display name recorded at registration
    #[argh(option)]
    device_name: Option<String>,
    /// path to this Endpoint's signing key. Generated on first use; keep it,
    /// because a new one is a new Endpoint ID and every capability issued for
    /// the old one stops meaning anything. Not needed with --example-config
    #[argh(option, default = "PathBuf::from(\"portal-server.pem\")")]
    key: PathBuf,
    /// path to the certificate key this device keeps. Defaults to the Endpoint
    /// key's name with `-portal-cert` appended -- a separate key on purpose,
    /// since the Endpoint key is a signing identity and should never be handed
    /// to a QUIC stack
    #[argh(option)]
    cert_key: Option<PathBuf>,
    /// path to the service catalogue: what may be reached, and under what
    /// name. See the note below, or --example-config
    #[argh(option, default = "PathBuf::from(\"portal-server.toml\")")]
    config: PathBuf,
    /// print a starter catalogue on stdout and exit
    #[argh(switch)]
    example_config: bool,
    /// print a pairing code and exit, letting whoever redeems it in for good.
    /// This is the one to use: a redeemed code is a Grant, which is reusable
    /// and survives this server restarting. Needs no server running, so a
    /// code can be issued while one already is
    #[argh(switch)]
    pair: bool,
    /// how long the pairing code lasts, in seconds. Clamped to 60..=300
    #[argh(option)]
    pairing_ttl: Option<u64>,
    /// print who may reach this Endpoint, and exit
    #[argh(switch)]
    grants: bool,
    /// take a grant away, by the id --grants prints
    #[argh(option)]
    revoke: Option<String>,
    /// an Endpoint ID to issue a one-shot capability for at startup, printed
    /// on stdout. For letting a guest in once; --pair is what standing access
    /// wants. Repeatable
    #[argh(option)]
    allow: Vec<String>,
    /// how long an issued capability lasts, in seconds. The proxy clamps this
    /// to 30..=300 and defaults to 30, which is not long enough to send one to
    /// a person -- pass 300 unless the peer is already waiting
    #[argh(option)]
    capability_ttl: Option<u64>,
    /// issue a TICKET and print the one string to hand over, then exit.
    /// Unlike --pair, several can be outstanding at once -- run this again for
    /// each -- and what redeeming one makes expires on its own
    #[argh(switch)]
    ticket: bool,
    /// how long a --ticket stays redeemable, in seconds. Clamped to
    /// 60..=86400, default 900. This is the life of the paper, not of the
    /// access it grants
    #[argh(option)]
    ticket_ttl: Option<u64>,
    /// how long the grant made by redeeming a --ticket or a
    /// --provisioning-key lasts, in seconds. Never unlimited. THE TWO CLAMP
    /// DIFFERENTLY: a ticket to 60..=86400 (default 3600), a provisioning
    /// key to 60..=3600 (default 1800), because that one is meant to be
    /// extended by redeeming again rather than set long
    #[argh(option)]
    grant_ttl: Option<u64>,
    /// what a --ticket is for. Shown only to you, in --tickets, and carried
    /// onto the grant whoever redeems it gets. 128 bytes at most
    #[argh(option)]
    ticket_label: Option<String>,
    /// print the tickets this Endpoint has issued and who redeemed them, and
    /// exit
    #[argh(switch)]
    tickets: bool,
    /// stop a ticket being redeemable, by the id --tickets prints. One already
    /// redeemed is left as it is, record and all; the grant it made stays
    /// either way -- use --revoke for that
    #[argh(option)]
    revoke_ticket: Option<String>,
    /// issue a PROVISIONING KEY and print the secret once, then exit. For
    /// automation that connects again and again -- redeeming it repeatedly
    /// extends the grant rather than being refused. Bind it with
    /// --binding-oidc unless the machine holding it is yours
    #[argh(switch)]
    provisioning_key: bool,
    /// how long a --provisioning-key stays redeemable, in seconds. Clamped to
    /// 60..=2592000 (30 days), default 604800. There is no unlimited: rotate
    /// instead, which needs no downtime because four can be live at once
    #[argh(option)]
    provisioning_ttl: Option<u64>,
    /// how many grants a --provisioning-key may have alive at once. Clamped to
    /// 1..=32, default 4. Match it to how many jobs run in parallel, not to
    /// how many run in a day: re-redeeming does not take a second slot
    #[argh(option)]
    max_live_grants: Option<u64>,
    /// bind a --provisioning-key to a workload identity issuer, so the key
    /// alone will not let anyone in. Needs --binding-subject. The issuer must
    /// be one the proxy's operator allowed
    #[argh(option)]
    binding_oidc: Option<String>,
    /// the exact `sub` the bound workload must present. No wildcards and no
    /// prefixes -- issue another key to cover another branch or repository
    #[argh(option)]
    binding_subject: Option<String>,
    /// what a --provisioning-key is for. Shown only to you, and carried onto
    /// the grants it makes unless the peer names its own. 128 bytes at most
    #[argh(option)]
    provisioning_label: Option<String>,
    /// print the provisioning keys this Endpoint has issued, with how many
    /// grants each one is holding open, and exit
    #[argh(switch)]
    provisioning_keys: bool,
    /// print who came in on a provisioning key and how often, by the id
    /// --provisioning-keys prints, and exit. This is the only record of where
    /// a key went
    #[argh(option)]
    provisioning_redemptions: Option<String>,
    /// stop a provisioning key, by the id --provisioning-keys prints. THIS
    /// ALSO DELETES THE GRANTS IT MADE, so anything connected on one stops
    /// being authorised -- unlike --revoke-ticket, which leaves them
    #[argh(option)]
    revoke_provisioning_key: Option<String>,
    /// register this Endpoint with an ENROLLMENT KEY instead of signing in, so
    /// a server can run where nobody can sign one in -- a self-contained CI
    /// job being the case. The key comes from ISEKAI_SERVER_ENROLLMENT_KEY or
    /// --enrollment-key-file, never from an argument
    #[argh(switch)]
    enroll: bool,
    /// read the Enrollment Key from this file rather than
    /// ISEKAI_SERVER_ENROLLMENT_KEY
    #[argh(option)]
    enrollment_key_file: Option<PathBuf>,
    /// where to get the workload identity token a bound key needs: `github`
    /// (GitHub Actions), `files` (one per audience, see --oidc-token-file) or
    /// `none`. Default `none`
    #[argh(option, default = "String::from(\"none\")")]
    oidc: String,
    /// an `audience=path` pair for --oidc files. Repeatable
    #[argh(option)]
    oidc_token_file: Vec<String>,
}

/// Answer `--grants` and `--revoke`, which need no listener.
///
/// **Its own path, and it exits.** These are questions about who may reach this
/// Endpoint, and the answer lives on the proxy — a Peer Listener is what a peer
/// connects *through*, and standing one up to ask would put a second row under
/// this Endpoint for every client that then looks one up.
async fn administer_grants(args: &Args, tokens: &std::path::Path) -> anyhow::Result<()> {
    // **Settled on the arguments, before anything authenticates.** A half-given
    // binding is a typo, and finding it out after a sign-in and an Identity
    // round trip tells the operator nothing extra. `portal-client` checks a
    // ticket's authority the same way and for the same reason.
    let binding = provisioning_binding(args)?;
    let cfg = config(args, tokens).await?;
    grant_admin(args, &cfg, binding.as_ref()).await
}

/// The P2P configuration these arguments describe, authenticated however this
/// installation is.
async fn config(args: &Args, tokens: &std::path::Path) -> anyhow::Result<P2pConfig> {
    // **Authentication first, then the key.** The struct literal this replaced
    // evaluated the token before the key, so a run with neither a sign-in nor a
    // token bailed without writing anything; passing the key in as an argument
    // quietly reversed that and left a new Endpoint identity on disk before
    // failing.
    let credential = if args.enroll {
        // **A different variable from the client's**, because it is a different
        // key: a server has to create a listener and accept connections, so its
        // permissions differ, and one key carrying both roles' would be the
        // ceiling problem §8.8.2 exists to avoid.
        portal_core::ci::enrollment_credential(
            args.enrollment_key_file.as_deref(),
            portal_core::ci::SERVER_ENROLLMENT_KEY_VAR,
            &args.oidc,
            &args.oidc_token_file,
        )?
    } else {
        // **Authentication first, then the key.** The struct literal this
        // replaced evaluated the token before the key, so a run with neither a
        // sign-in nor a token bailed without writing anything.
        let auth = portal_core::login::authenticate(tokens, args.auth0_token.as_deref()).await?;
        // **The whole point of the source.** With it the Endpoint Token
        // renewal, which runs every few minutes for the life of the session,
        // asks for a current Auth0 token instead of reusing one that expired.
        isekai_p2p::Credential::auth0(auth.token, auth.source, args.register)
    };
    let key = load_or_generate_key(&args.key)?;
    Ok(P2pConfig {
        identity_url: args.identity_url.clone(),
        identity_http3: args.identity_http3,
        proxy_url: args.proxy_url.clone(),
        credential,
        protocol: args.protocol.clone(),
        device_name: args.device_name.clone(),
        token_ttl: None,
        key,
    })
}

/// The binding these arguments describe, refused before anything authenticates.
///
/// **Both halves or neither.** `--binding-oidc` alone would be a key bound to
/// an issuer and no subject, which the proxy refuses — and a run that got that
/// far has already signed in and asked Identity for a token to learn what the
/// arguments said on their own. A `sub` with no issuer is the same mistake from
/// the other side.
///
/// `None` means an unbound key, which the proxy accepts. It is the right shape
/// for a build machine whose secret store is yours, and the wrong one for a
/// public repository's CI: the key alone is then enough to reach this Endpoint.
fn provisioning_binding(args: &Args) -> anyhow::Result<Option<ProvisioningBinding>> {
    match (&args.binding_oidc, &args.binding_subject) {
        (Some(issuer), Some(subject)) => Ok(Some(ProvisioningBinding::Oidc {
            issuer: issuer.clone(),
            subject: subject.clone(),
        })),
        (None, None) => Ok(None),
        (Some(_), None) => anyhow::bail!(
            "--binding-oidc needs --binding-subject: an issuer without a subject would let \
             any workload that issuer knows about in"
        ),
        (None, Some(_)) => anyhow::bail!(
            "--binding-subject needs --binding-oidc, which says who vouches for that subject"
        ),
    }
}

/// Show a key's binding, including the audience the peer has to mint for.
///
/// **The audience is the half an operator cannot guess.** It is not settable
/// here — the proxy takes it from its own configuration, because a key naming
/// another service's audience would accept the tokens that service is holding —
/// so echoing it is the only way the person configuring CI learns the value.
fn print_binding(binding: Option<&BindingView>) {
    let Some(binding) = binding else {
        // **Not silence.** An operator who passed `--binding-oidc` reads the
        // absence of a line as "nothing to report", not as "I cannot tell you
        // whether it took" — and the difference is whether the string alone is
        // enough to reach this Endpoint.
        println!("bound to    : not reported -- check with --provisioning-keys");
        return;
    };
    match binding.kind.as_str() {
        "oidc" => {
            println!(
                "bound to    : {} / {}",
                binding.issuer.as_deref().unwrap_or("?"),
                binding.subject.as_deref().unwrap_or("?"),
            );
            match binding.audience.as_deref() {
                Some(audience) => {
                    println!("audience    : {audience}  (the peer mints its token for this)")
                }
                // Worth saying rather than printing nothing: without it the
                // peer cannot know what to ask its issuer for.
                None => println!("audience    : not reported -- ask the proxy's operator"),
            }
        }
        "none" => {
            println!("bound to    : nothing -- the key alone is enough to get in.");
            println!("              Use --binding-oidc for a public repository's CI.");
        }
        other => println!("bound to    : {other}"),
    }
}

async fn grant_admin(
    args: &Args,
    cfg: &P2pConfig,
    binding: Option<&ProvisioningBinding>,
) -> anyhow::Result<()> {
    let token = isekai_p2p::issue_endpoint_token(cfg).await?.endpoint_token;
    let proxy = isekai_p2p::proxy_client(cfg, &token)?;

    if let Some(grant_id) = &args.revoke {
        proxy
            .revoke_grant(grant_id)
            .await
            .with_context(|| format!("revoke {grant_id}"))?;
        println!("revoked     : {grant_id}");
    }
    if args.grants {
        let grants = proxy.list_grants().await.context("list grants")?;
        if grants.is_empty() {
            println!("Nobody is paired with this Endpoint.");
        }
        for grant in &grants {
            println!(
                "grant       : {}  {}  ({}{})",
                grant.grant_id,
                grant.allowed_endpoint.as_deref().unwrap_or("?"),
                grant.origin.as_deref().unwrap_or("origin unknown"),
                grant
                    .label
                    .as_deref()
                    .map(|l| format!(", {l}"))
                    .unwrap_or_default(),
            );
        }
    }

    if let Some(ticket_id) = &args.revoke_ticket {
        proxy
            .revoke_ticket(ticket_id)
            .await
            .with_context(|| format!("revoke ticket {ticket_id}"))?;
        // **`204` says almost nothing**, and deliberately: the id may never have
        // existed, or may name a ticket already spent -- which §8.12.6 leaves
        // alone, because revoking one would stop nothing and erase the only
        // record of who came in on it. So this reports the one thing true in
        // every case rather than announcing a deletion that may not have
        // happened.
        println!("not redeemable now: {ticket_id}");
        println!("If it had already been redeemed, the record of that stays in --tickets,");
        println!("and the grant it made is untouched -- --revoke is what takes those away.");
    }

    if args.pair {
        // **Nothing here needs the listener**, however much it looks like it
        // should: `POST /v1/peer/pairing-codes` names a protocol and a ttl and
        // no listener at all (§8.9.1), because what a redeemed code makes is a
        // Grant, whose key has no listener in it either (§8.8). That is the
        // same reason `--ticket` sits on this path.
        //
        // It used to be minted by the running server, which meant a code could
        // only be had by starting one -- so an installation with a server
        // already up could not issue a code without standing a second one
        // beside it, adding a row under this Endpoint for every client that
        // then looks one up.
        let code = proxy
            .create_pairing_code(&cfg.protocol, args.pairing_ttl)
            .await
            .context("mint a pairing code")?;
        println!("\npairing code: {}", code.code);
        println!(
            "  or the URI: {}",
            isekai_p2p::agent::pairing_uri(&code.code)
        );
        println!("  expires at: {}", code.expires_at);
        println!("\nThe peer runs: portal-client --pair {}", code.code);
        println!("Once redeemed they can reconnect without asking again, and this");
        println!("server can restart without breaking it.");
    }

    if args.ticket {
        let ticket = proxy
            .create_ticket(
                &cfg.protocol,
                args.ticket_ttl,
                args.grant_ttl,
                args.ticket_label.as_deref(),
            )
            .await
            .context("issue a ticket")?;
        // **The secret first.** Everything else here is optional, and the
        // reason is that it is shown once: a response missing `created_at`
        // must not cost the operator the one string they came for.
        println!("\nHand over this one string:\n");
        println!(
            "  {}",
            isekai_p2p::agent::ticket_transfer(
                isekai_p2p::agent::proxy_authority(&args.proxy_url),
                &ticket.ticket,
            )
        );
        println!();
        match &ticket.ticket_id {
            Some(id) => println!("ticket id   : {id}  (--revoke-ticket takes this)"),
            None => println!("ticket id   : not reported -- --tickets will list it"),
        }
        if let Some(at) = &ticket.expires_at {
            println!("expires at  : {at}");
        }
        if let Some(ttl) = ticket.grant_ttl {
            println!("grant ttl   : {ttl}s");
        }
        println!("\nThe peer runs: portal-client --redeem <that string>");
        println!("\nIt works once, it is not shown again, and it is a secret until");
        println!("it is spent -- send it the way you would send a password.");
    }

    // **Revocation before issuance**, as with tickets: a run that rotates a key
    // does both, and the old one should stop before the new one is printed.
    if let Some(key_id) = &args.revoke_provisioning_key {
        proxy
            .revoke_provisioning_key(key_id)
            .await
            .with_context(|| format!("revoke provisioning key {key_id}"))?;
        // **This says the opposite of `--revoke-ticket`, and has to.** Tearing
        // up a ticket leaves whoever already walked in; revoking one of these
        // deletes the grants it made. The asymmetry is deliberate on the
        // proxy's side (§8.13.7): an owner cannot see who came in on a key
        // without asking, so "stop this key" that left the door open would
        // leave them watching a door they cannot shut.
        println!("revoked     : {key_id}");
        println!("The grants it made are gone with it, so anything running on one has");
        println!("stopped being authorised. Established connections are not cut, but");
        println!("nothing new is let in. The record of who came in stays -- ask for it");
        println!("with --provisioning-redemptions {key_id}.");
    }

    if args.provisioning_key {
        let key = proxy
            .create_provisioning_key(
                &cfg.protocol,
                args.provisioning_ttl,
                args.grant_ttl,
                args.max_live_grants,
                binding,
                args.provisioning_label.as_deref(),
            )
            .await
            .context("issue a provisioning key")?;
        // **The secret first**, for the same reason `--ticket` prints it
        // first: everything else is optional in the response, and a missing
        // `created_at` must not cost the operator the one string they came for.
        println!("\nPut this in the automation's secret store:\n");
        println!("  {}", key.key);
        println!();
        match &key.key_id {
            Some(id) => println!("key id      : {id}  (--revoke-provisioning-key takes this)"),
            None => println!("key id      : not reported -- --provisioning-keys will list it"),
        }
        if let Some(at) = &key.expires_at {
            println!("expires at  : {at}");
        }
        if let Some(ttl) = key.grant_ttl {
            println!("grant ttl   : {ttl}s  (redeeming again extends it)");
        }
        if let Some(slots) = key.max_live_grants {
            println!("slots       : {slots} grants alive at once");
        }
        print_binding(key.binding.as_ref());
        println!("\nThe peer redeems it with its own Endpoint Token; it does not need");
        println!("--pair or a ticket as well.");
        println!("\nThe job reads it from ISEKAI_PROVISIONING_KEY. It also needs an");
        println!("Enrollment Key from the Identity side -- portal-client");
        println!("--issue-enrollment-key -- because a runner has no Endpoint of its own");
        println!("until something gives it one.");
        println!("\nIt is shown once and it is a standing power: whoever holds it can");
        println!("reach this Endpoint until the key expires or is revoked.");
    }

    if args.provisioning_keys {
        let keys = proxy
            .list_provisioning_keys()
            .await
            .context("list provisioning keys")?;
        if keys.is_empty() {
            println!("No provisioning keys issued.");
        }
        for key in &keys {
            let label = key
                .label
                .as_deref()
                .map(|l| format!(", {l}"))
                .unwrap_or_default();
            // **Both halves of the slot count.** The ceiling alone does not say
            // whether a key is turning jobs away, which is the question an
            // operator has when a run fails with `provisioning-slots-exhausted`.
            let slots = match (key.live_grants, key.max_live_grants) {
                (Some(live), Some(max)) => format!("{live}/{max} slots"),
                (Some(live), None) => format!("{live} grants"),
                _ => "slots unknown".to_owned(),
            };
            // **Which of these is a bare bearer secret** is the question this
            // listing has to answer — the whole framing of these keys is that
            // an unbound one is fine on a machine you own and wrong for a
            // public repository, and an operator cannot act on that without
            // being told which is which.
            let bound = match key.binding.as_ref().map(|b| b.kind.as_str()) {
                Some("none") | Some("") | None => "UNBOUND".to_owned(),
                Some("oidc") => key
                    .binding
                    .as_ref()
                    .and_then(|b| b.subject.as_deref())
                    .map(|subject| format!("oidc {subject}"))
                    .unwrap_or_else(|| "oidc".to_owned()),
                Some(other) => other.to_owned(),
            };
            println!(
                "key         : {}  {bound}, {slots}, {} redemptions, expires {}{label}",
                key.key_id,
                key.redemption_count.unwrap_or(0),
                key.expires_at.as_deref().unwrap_or("?"),
            );
        }
    }

    if let Some(key_id) = &args.provisioning_redemptions {
        let rows = proxy
            .provisioning_redemptions(key_id)
            .await
            .with_context(|| format!("list redemptions of {key_id}"))?;
        if rows.is_empty() {
            println!("Nobody has come in on {key_id}.");
        }
        for row in &rows {
            // **`redeem_count` is visits, and the row is an Endpoint.** One
            // long-lived runner re-redeeming all day is one row and many
            // visits, so printing only the row would answer a question nobody
            // asked.
            let subject = row
                .binding_subject
                .as_deref()
                .map(|s| format!("  as {s}"))
                .unwrap_or_default();
            println!(
                "redeemed by : {}  {} time(s), last {}{subject}",
                row.endpoint_id,
                row.redeem_count.unwrap_or(1),
                row.redeemed_at.as_deref().unwrap_or("?"),
            );
        }
    }

    if args.tickets {
        let tickets = proxy.list_tickets().await.context("list tickets")?;
        if tickets.is_empty() {
            println!("No tickets outstanding.");
        }
        for ticket in &tickets {
            let label = ticket
                .label
                .as_deref()
                .map(|l| format!(", {l}"))
                .unwrap_or_default();
            match &ticket.redemption {
                Some(r) => println!(
                    "ticket      : {}  redeemed by {} as {} at {}{}",
                    ticket.ticket_id, r.endpoint_id, r.grant_id, r.redeemed_at, label,
                ),
                None => println!(
                    "ticket      : {}  unredeemed, expires {}{}",
                    ticket.ticket_id, ticket.expires_at, label,
                ),
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // **stderr, and `info` unless `RUST_LOG` says otherwise.**
    //
    // Two fixes in one. `fmt()` writes to *stdout* by default, which puts log
    // lines in among the ids this program prints for the operator to copy —
    // every other binary in this workspace sets stderr and this one did not.
    //
    // And `from_default_env()` defaults to `ERROR`, so `warn!` and below were
    // dropped: a service refused, a target that would not answer, a datagram
    // too large to send. `from_env_lossy` rather than `try_from_default_env`
    // keeps the old leniency — one bad directive in `RUST_LOG` skips that
    // directive rather than throwing the whole variable away, which matters
    // because reaching for `RUST_LOG` is what somebody does when confused
    // already.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    let args: Args = argh::from_env();
    // **Every path out of `run` goes through the same wind-down**, which is the
    // only shape that works here: `PeerDirectory`, the sessions and the
    // one-shot commands all open control-plane transports on the shared msquic
    // registration, and a process that returns while those handles are live
    // drops the registration into `RegistrationClose` and aborts. Hardware
    // found it twice — once after a successful pairing, once on a connect that
    // was correctly refused — and both times the exit code contradicted what
    // had been printed a line earlier.
    // **Never returns**, and that is the fix for Ctrl+C not stopping these
    // programs once traffic had started: returning from `main` drops the
    // runtime and then the registrations, and `RegistrationClose` blocks
    // uninterruptibly on a configuration's rundown reference that no timeout
    // covers. `portal_core::shutdown` has the whole of it.
    // **Filled in by `run` once an Endpoint exists**, so returning the slot does
    // not depend on which way `run` left. The client does the same.
    let mut enrolled: Option<P2pConfig> = None;
    let code = match run(args, &mut enrolled).await {
        Ok(()) => 0,
        Err(e) => {
            // Printed here because `_exit` skips the reporting `main` would
            // have done by returning the error.
            eprintln!("Error: {e:#}");
            1
        }
    };
    // **Here, and not beside the listener.** `run` returns from several places
    // once the Endpoint exists, and the run that fails before serving starts is
    // exactly the one whose slot should come back.
    if let Some(cfg) = enrolled {
        portal_core::ci::release_the_slot(&cfg).await;
    }
    portal_core::shutdown::leave(code).await
}

/// SIGTERM on Unix, and a future that never completes elsewhere.
///
/// Windows has no SIGTERM; `ctrl_c` covers the interactive case there, and the
/// unattended one does not arise because CI runs this on Linux.
async fn terminate_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            // A process that cannot install the handler should still run; it
            // simply dies on SIGTERM the way it always did.
            Err(e) => {
                tracing::warn!("could not listen for SIGTERM: {e}");
                std::future::pending::<()>().await;
            }
        }
    }
    #[cfg(not(unix))]
    std::future::pending::<()>().await;
}

async fn run(args: Args, enrolled: &mut Option<P2pConfig>) -> anyhow::Result<()> {
    if args.example_config {
        // Before the key, the token and the catalogue: this is what somebody
        // runs when they have none of the three yet.
        print!("{}", portal_core::config::EXAMPLE);
        return Ok(());
    }

    // **Before the catalogue and before any listener**, because neither is
    // needed to answer them: grants belong to this Endpoint rather than to a
    // listener (spec §8.8), so listing and revoking are Endpoint-token calls on
    // the control plane and nothing more.
    //
    // Standing a listener up for them would be worse than wasteful. A second
    // listener on this Endpoint and protocol is exactly what a client on a
    // grant then has to choose between, so an operator asking "who is in?"
    // would be making the connections they are asking about ambiguous.
    let tokens = args
        .auth0_tokens
        .clone()
        .unwrap_or_else(|| portal_core::login::tokens_beside(&args.key));
    if args.login {
        // Before the key, the catalogue and the network: this is what somebody
        // runs when they have none of them.
        return portal_core::login::sign_in(&tokens).await;
    }

    portal_core::ci::check_unattended_args(
        args.enroll,
        args.auth0_token.is_some(),
        args.register,
        &args.oidc,
        &args.oidc_token_file,
    )?;
    // **Before the catalogue and before the network.** A missing key is a fact
    // about the arguments; reported later it hides behind whatever else fails
    // first, and the operator fixes the wrong thing.
    if args.enroll {
        portal_core::ci::require_key(
            args.enrollment_key_file.as_deref(),
            portal_core::ci::SERVER_ENROLLMENT_KEY_VAR,
        )?;
    }

    // Everything here is an Endpoint-token call that names no listener
    // (§8.8, §8.12), so none of it needs a server standing up first.
    let administering = args.grants
        || args.revoke.is_some()
        || args.pair
        || args.ticket
        || args.tickets
        || args.revoke_ticket.is_some()
        || args.provisioning_key
        || args.provisioning_keys
        || args.provisioning_redemptions.is_some()
        || args.revoke_provisioning_key.is_some();
    // **A binding with nothing to bind is refused, not ignored.** These only
    // mean anything to `--provisioning-key`, and a run that quietly dropped
    // them would start a server while the operator believed they had just
    // restricted a key. That is the same failure the `--allow` guard below
    // exists to avoid.
    if !args.provisioning_key && (args.binding_oidc.is_some() || args.binding_subject.is_some()) {
        anyhow::bail!(
            "--binding-oidc and --binding-subject describe a --provisioning-key, and this run \
             is not issuing one"
        );
    }
    // **`--allow` is the one that does need a listener**, and these paths exit
    // before there is one. Dropping it quietly is the worst of the three
    // options: the code or the listing would print, the run would look like it
    // worked, and the capability nobody was issued would be discovered by the
    // peer failing to connect.
    if administering && !args.allow.is_empty() {
        anyhow::bail!(
            "--allow issues a capability against a running listener, and this run exits \
             before there is one. Issue it from the run that serves, or use --pair \
             or --ticket, which need no server"
        );
    }
    if administering {
        return administer_grants(&args, &tokens).await;
    }

    // Read before anything else touches the network: a typo in the catalogue
    // should cost a message, not a registered Endpoint and a listener nobody
    // can use.
    let catalogue = portal_core::config::load(&args.config)?;

    let cert_key = args.cert_key.clone().unwrap_or_else(|| {
        let mut path = args.key.clone();
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "endpoint".to_owned());
        path.set_file_name(format!("{stem}-portal-cert.pem"));
        path
    });

    // **Said out loud, because a generated key looks exactly like a loaded one
    // until it fails.** `--key` has a default, so running from a different
    // directory than last time silently makes a *second* Endpoint — and the
    // failure is `capability-endpoint-mismatch` from the proxy, several steps
    // later, naming nothing that points back here.
    if !args.key.exists() {
        tracing::info!(path = %args.key.display(), "generating a new Endpoint key");
    }

    let cfg = config(&args, &tokens).await?;
    // From here on this Endpoint may exist, so every way out owes a slot back.
    if args.enroll {
        *enrolled = Some(cfg.clone());
    }

    let shutdown = CancellationToken::new();
    // `AutoNotify` rather than `Manual`: there is no operator watching a window
    // here, and the Grant the proxy checked is the authorization. It still says
    // who arrived, which is the difference from plain `Auto`.
    let server = portal_core::session::serve(
        cfg,
        &cert_key,
        catalogue,
        AcceptPolicy::AutoNotify,
        shutdown.clone(),
    )
    .await
    .context("stand the portal server up")?;

    println!("endpoint id : {}", server.info.endpoint_id);
    // **The listener id is printed for diagnostics, not for carrying.** A
    // client on a grant looks the current one up for itself; only the
    // capability path needs it by hand, and only until the connect it is for.
    println!("listener id : {}", server.info.listener_id);

    for endpoint in &args.allow {
        let capability = match server.issue_capability(endpoint, args.capability_ttl).await {
            Ok(capability) => capability,
            Err(e) => {
                server.close().await;
                return Err(e.context(format!("issue a capability for {endpoint}")));
            }
        };
        println!("\ncapability  : {capability}   (for {endpoint})");
        println!("One-shot, and it expires -- give the client this and the listener id now.");
    }

    let mut events = server.signaling.subscribe();
    // **Made once, outside the loop.** `ctrl_c()` builds a future over signals
    // that arrive *after* it is created, so calling it inside the select meant
    // a fresh one every time a signaling event woke this loop — and a Ctrl+C
    // landing in the gap between one iteration ending and the next future
    // being built was simply not seen. Pinned so the same future is polled
    // across iterations rather than restarted.
    let signalled = tokio::signal::ctrl_c();
    tokio::pin!(signalled);
    // **SIGTERM too, and the hatch armed with it.** A CI job stops this with a
    // plain `kill`, and on the enrolment path the way out is what returns the
    // slot. Registering takes SIGTERM's default disposition away for the rest
    // of the process, so the hatch has to cover it from that moment or a second
    // `kill` during a blocked close is swallowed.
    let terminate = terminate_signal();
    tokio::pin!(terminate);
    #[cfg(unix)]
    portal_core::shutdown::hard_exit_on_terminate();
    // Only an interrupt arms the hatch: the loop also ends when the signaling
    // stream breaks, and turning a user's *first* press into a hard exit there
    // would skip withdrawing the Peer Listener — the one thing the comment
    // below says must not be skipped.
    let mut interrupted = false;
    loop {
        tokio::select! {
            _ = &mut signalled => { interrupted = true; break }
            _ = &mut terminate => { interrupted = true; break }
            event = events.recv() => match event {
                Ok(event) => tracing::info!("signaling: {event:?}"),
                // Lagged only loses log lines; the session is unaffected.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("missed {n} signaling events");
                }
                Err(_) => break,
            },
        }
    }
    if interrupted {
        portal_core::shutdown::hard_exit_on_second_interrupt();
    }
    // Not just `shutdown.cancel()`: returning from `main` drops the runtime, and
    // the session withdraws the Peer Listener on its way out. Cancel-and-return
    // leaves it listed for its whole lease, pointing at a process that is gone.
    server.close().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with(oidc: Option<&str>, subject: Option<&str>) -> Args {
        let mut args: Args = argh::FromArgs::from_args(&["portal-server"], &[]).expect("defaults");
        args.binding_oidc = oidc.map(str::to_owned);
        args.binding_subject = subject.map(str::to_owned);
        args
    }

    /// An issuer with no subject would admit every workload that issuer knows
    /// about — which is most of GitHub. The proxy refuses it; this refuses it
    /// before a sign-in.
    #[test]
    fn half_a_binding_is_refused() {
        let err = provisioning_binding(&args_with(Some("https://issuer.test"), None)).unwrap_err();
        assert!(format!("{err:#}").contains("--binding-subject"));

        let err = provisioning_binding(&args_with(None, Some("repo:o/r"))).unwrap_err();
        assert!(format!("{err:#}").contains("--binding-oidc"));
    }

    /// Neither is a valid choice, not an oversight: it is the right shape for a
    /// build machine whose secret store is yours.
    #[test]
    fn no_binding_at_all_is_allowed() {
        assert!(provisioning_binding(&args_with(None, None))
            .expect("unbound is a choice")
            .is_none());
    }

    /// A binding that cannot apply is refused rather than dropped.
    ///
    /// The check lives in `run`, so this pins the condition it tests: the
    /// failure being avoided is a server that starts while the operator
    /// believes they have just restricted a key.
    #[test]
    fn a_binding_without_a_key_to_bind_is_a_mistake() {
        let stray = args_with(Some("https://issuer.test"), Some("repo:o/r"));
        assert!(!stray.provisioning_key);
        assert!(stray.binding_oidc.is_some() || stray.binding_subject.is_some());
    }

    #[test]
    fn both_halves_make_an_oidc_binding() {
        let binding =
            provisioning_binding(&args_with(Some("https://issuer.test"), Some("repo:o/r")))
                .expect("valid")
                .expect("some");
        assert_eq!(
            binding,
            ProvisioningBinding::Oidc {
                issuer: "https://issuer.test".to_owned(),
                subject: "repo:o/r".to_owned(),
            },
        );
    }
}
