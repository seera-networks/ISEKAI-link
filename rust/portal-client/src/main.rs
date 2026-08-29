//! The side with the local ports.
//!
//! Connects to a portal server and maps local ports onto the services it
//! offers. Phase 1c-iii-c-ii of `docs/portal_plan.md`, and UDP since 3b.
//!
//! ```text
//! portal-client --auth0-token … --key ep.pem \
//!               --listener pl_… --capability … \
//!               --map 5432:db --map udp:5353:dns
//! ```
//!
//! **The local ports are this side's own business** (plan §4.3): nothing about
//! `--map` reaches the server, which only ever sees the service name.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use argh::FromArgs;
use isekai_p2p::{load_or_generate_key, P2pConfig};
use portal_core::server::Protocol;
use tokio_util::sync::CancellationToken;

/// Map local TCP and UDP ports onto a portal server's services over ISEKAI
/// link.
///
/// A service is asked for **by name**. Which local port stands for which name
/// is this machine's business and nothing about it is sent, so the mapping can
/// be whatever suits you.
#[derive(FromArgs)]
#[argh(
    example = "\
portal-client --login

portal-client --pair ABCD-1234

portal-client --map 5432:db --map udp:5353:dns",
    note = "\
Sign in once with --login. It runs the Auth0 device flow -- a code and a URL to
open -- and saves tokens beside the Endpoint key that refresh from then on, so
nothing else here needs a token.

--auth0-token still works and cannot be refreshed: when it expires the session
ends a few minutes later, mid-forward.
",
    note = "\
--map takes `port:service`, or `udp:port:service` for a UDP one. TCP without
the prefix. Repeatable, and the port is yours to choose:

  --map 5432:db           reach `db` at 127.0.0.1:5432
  --map 15432:db          the same service on a port that is free
  --map udp:5353:dns      reach `dns` at 127.0.0.1:5353

The protocol has to be said and cannot be guessed: the server looks a name up
under a protocol, so asking for `dns` over TCP is refused with the same answer
as a name that does not exist.

Forwarded ports bind to loopback unless --bind says otherwise, because a
forward reachable from your network is a second door onto the server's
services.
",
    note = "\
The server's operator has to let you in first, and there are three ways in.

PAIRING, which is the one to use: they run `portal-server --pair` and read you
the code; you run `--pair <code>` once. That makes a standing grant, and after
it every connect needs only --map -- the current listener is looked up for you,
so the server can restart without breaking anything.

A TICKET, when nobody is reading a code aloud: they run `portal-server
--ticket` and send you the one string it prints; you run `--redeem <string>`
once. Same standing grant afterwards, except it expires on its own -- which is
the point, for work that ends.

Either of those can be given together with --map, and then the same run goes
on to forward -- there is no reason to start this twice, and the second run
would only have to be told the peer the first one was just told.

A CAPABILITY, for being let in once: run --whoami, send them the Endpoint ID,
and they issue one with --allow. Pass it with --capability and --listener. It
is one-shot and expires in 300 seconds at most, so have the command ready
before they issue it.

--whoami needs nothing but --key and makes no network call."
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
    /// refreshed -- `--login` is the way to stay signed in. Not needed with
    /// --whoami
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
    /// because a new one is a new Endpoint ID and the capability you were
    /// issued stops meaning anything
    #[argh(option, default = "PathBuf::from(\"portal-client.pem\")")]
    key: PathBuf,
    /// print this Endpoint's ID and exit -- what the server needs for --allow
    #[argh(switch)]
    whoami: bool,
    /// redeem a pairing code the server's operator showed. What it makes is a
    /// standing grant: after this, connecting needs neither --listener nor
    /// --capability, and survives the server restarting. Add --map to go
    /// straight on and forward; without one this stops after pairing
    #[argh(option)]
    pair: Option<String>,
    /// redeem a TICKET the server's operator sent you. Takes the one string
    /// --ticket printed, which says which proxy to redeem at. What it makes is
    /// a grant that expires on its own. Add --map to go straight on and
    /// forward; without one this stops after redeeming
    #[argh(option)]
    redeem: Option<String>,
    /// a name for this device, recorded with the grant so the operator can see
    /// what they let in
    #[argh(option)]
    label: Option<String>,
    /// which paired server to connect to, by its Endpoint ID. Only needed when
    /// paired with more than one
    #[argh(option)]
    peer: Option<String>,
    /// the server's listener id. Only for the one-shot --capability path; a
    /// grant finds the current listener itself
    #[argh(option)]
    listener: Option<String>,
    /// a one-shot capability the server issued for this Endpoint. --pair is
    /// what standing access wants
    #[argh(option)]
    capability: Option<String>,
    /// a local port to map onto a service, as `port:name` or
    /// `udp:port:name`. TCP without the prefix. Repeatable
    #[argh(option)]
    map: Vec<String>,
    /// the address to bind mapped ports on. Loopback by default, because a
    /// forward reachable from the network is a second open door onto the
    /// server's services
    #[argh(option, default = "std::net::IpAddr::from([127, 0, 0, 1])")]
    bind: std::net::IpAddr,
    /// register this Endpoint with an ENROLLMENT KEY instead of signing in.
    /// For a job with nobody at the keyboard. The key comes from
    /// ISEKAI_ENROLLMENT_KEY or --enrollment-key-file, never from an argument
    #[argh(switch)]
    enroll: bool,
    /// read the Enrollment Key from this file rather than
    /// ISEKAI_ENROLLMENT_KEY
    #[argh(option)]
    enrollment_key_file: Option<PathBuf>,
    /// read the Provisioning Key from this file rather than
    /// ISEKAI_PROVISIONING_KEY. Redeeming it is what authorises this Endpoint
    /// to reach the server, and this run redeems it again to extend the grant
    #[argh(option)]
    provisioning_key_file: Option<PathBuf>,
    /// where to get the workload identity token a bound key needs: `github`
    /// (GitHub Actions), `files` (one per audience, see --oidc-token-file) or
    /// `none`. Default `none`
    #[argh(option, default = "String::from(\"none\")")]
    oidc: String,
    /// an `audience=path` pair for --oidc files. Repeatable, and both
    /// audiences are needed: the Identity API and the proxy deliberately want
    /// different tokens
    #[argh(option)]
    oidc_token_file: Vec<String>,
    /// issue an ENROLLMENT KEY and print it once, then exit. This is what lets
    /// a job register an Endpoint of its own. Needs a sign-in: you are
    /// delegating what you can already do
    #[argh(switch)]
    issue_enrollment_key: bool,
    /// which protocols the derived Endpoints may use. Defaults to --protocol.
    /// Cannot exceed what you have yourself
    #[argh(option)]
    enrollment_protocols: Vec<String>,
    /// which permissions the derived Endpoints get. Defaults to
    /// `peer-connect:initiate` alone, which is all a job needs -- see the
    /// --issue-enrollment-key note
    #[argh(option)]
    permissions: Vec<String>,
    /// how long the key stays usable, in seconds. Clamped to 60..=2592000
    /// (30 days), default 604800. There is no unlimited
    #[argh(option)]
    enrollment_ttl: Option<i64>,
    /// how many derived Endpoints may be alive at once. Clamped to 1..=32,
    /// default 4. Match it to how many jobs run in parallel
    #[argh(option)]
    max_live_endpoints: Option<i64>,
    /// how long a derived Endpoint may go unused before it is retired, in
    /// seconds. Clamped to 900..=604800, default 3600. It is the insurance for
    /// a job that could not return its own slot, so shorter is safer
    #[argh(option)]
    endpoint_idle_ttl: Option<i64>,
    /// bind the key to a workload identity issuer, so the key alone will not
    /// register anything. Needs --binding-subject. REQUIRED unless you pass
    /// --binding-none
    #[argh(option)]
    binding_oidc: Option<String>,
    /// the exact `sub` the bound workload must present. No wildcards
    #[argh(option)]
    binding_subject: Option<String>,
    /// issue a key that anything holding it can use. Only for a machine whose
    /// secret store is yours -- never for a public repository
    #[argh(switch)]
    binding_none: bool,
    /// what the key is for. Shown only to you. 128 bytes at most
    #[argh(option)]
    enrollment_label: Option<String>,
    /// print the enrollment keys you have issued, and exit
    #[argh(switch)]
    enrollment_keys: bool,
    /// print which Endpoints came in on a key and how each ended, by the id
    /// --enrollment-keys prints, and exit
    #[argh(option)]
    enrollment_key_enrollments: Option<String>,
    /// stop an enrollment key, by the id --enrollment-keys prints. An
    /// `ephemeral` key takes its derived Endpoints with it
    #[argh(option)]
    revoke_enrollment_key: Option<String>,
    /// print the Endpoints this account owns, and exit. Revoked ones are
    /// hidden unless --endpoint-status says otherwise, and how many were
    /// hidden is printed so you know to ask
    #[argh(switch)]
    endpoints: bool,
    /// which Endpoints to list: `active` (default), `revoked` or `all`
    #[argh(option)]
    endpoint_status: Option<String>,
    /// retire an Endpoint, by the id --endpoints prints. NEEDS --reason. THIS
    /// CANNOT BE UNDONE, and the keypair cannot register again -- a device
    /// that comes back needs a new key
    #[argh(option)]
    revoke_endpoint: Option<String>,
    /// why an Endpoint is being retired: `device_lost`, `endpoint_deleted`,
    /// `admin_revoke` or `security_incident`. It lands in the audit log
    #[argh(option)]
    reason: Option<String>,
    /// free text kept with the revocation, for whoever reads the audit log
    #[argh(option)]
    note: Option<String>,
}

/// The audience the **proxy** checks a binding assertion against (§8.13.4).
const PROXY_AUDIENCE: &str = "isekai-proxy";

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
    // **Filled in by `run` once an Endpoint exists**, so that returning the
    // slot does not depend on which way `run` left.
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
    // **Here, and not beside the connection.** `run` returns from several
    // places once the Endpoint exists — no `--map` to forward, a refused
    // connect, a port already bound — and the run that fails before forwarding
    // starts is exactly the one whose slot should come back. Doing it on the
    // way out covers all of them, and a new early return cannot forget it.
    if let Some(cfg) = enrolled {
        portal_core::ci::release_the_slot(&cfg).await;
    }
    portal_core::shutdown::leave(code).await
}

async fn run(args: Args, enrolled: &mut Option<P2pConfig>) -> anyhow::Result<()> {
    let tokens = args
        .auth0_tokens
        .clone()
        .unwrap_or_else(|| portal_core::login::tokens_beside(&args.key));
    // **Before the key**, which signing in does not need — and a corrupt
    // `portal-client.pem` should not block the one command that has nothing to
    // do with it. `portal-server` orders these the same way.
    if args.login {
        return portal_core::login::sign_in(&tokens).await;
    }

    // **Before the key**, because none of these need an Endpoint of this
    // client's own: issuing a key is route A, and §8.8.2 asks for no PoP
    // precisely because the caller is a person.
    // **Before the dispatch below, not after it.** Put after, these never fire
    // for a run that takes the admin path — `--endpoints --reason device_lost`
    // dropped `--reason` exactly as a forwarding run did, which is the bug this
    // guard was written to close, entered from a different flag.
    if args.reason.is_some() || args.note.is_some() {
        anyhow::ensure!(
            args.revoke_endpoint.is_some(),
            "--reason and --note describe a --revoke-endpoint, and this run has none",
        );
    }
    if let Some(status) = &args.endpoint_status {
        anyhow::ensure!(
            args.endpoints,
            "--endpoint-status describes --endpoints, which this run is not asking for",
        );
        // **Checked here rather than left to the server.** An unknown value
        // answers `400`, but a *plausible* typo — `revoked_only`, `everything` —
        // is what somebody writes while hunting a row they cannot find, and
        // being told the accepted words beats being told the request was bad.
        anyhow::ensure!(
            matches!(status.as_str(), "active" | "revoked" | "all"),
            "--endpoint-status takes `active`, `revoked` or `all`, not `{status}`",
        );
    }

    if args.issue_enrollment_key
        || args.enrollment_keys
        || args.enrollment_key_enrollments.is_some()
        || args.revoke_enrollment_key.is_some()
        || args.endpoints
        || args.revoke_endpoint.is_some()
    {
        return enrollment_admin(&args, &tokens).await;
    }

    // **Said out loud, because a generated key looks exactly like a loaded one
    // until it fails.** `--key` has a default, so running from a different
    // directory than last time silently makes a *second* Endpoint — and the
    // failure is `capability-endpoint-mismatch` from the proxy, several steps
    // later, naming nothing that points back here.
    if !args.key.exists() {
        tracing::info!(path = %args.key.display(), "generating a new Endpoint key");
    }
    let key = load_or_generate_key(&args.key)?;
    if args.whoami {
        // Before any network call: this is what the operator needs in order to
        // ask the other side for a capability, and it costs nothing to answer.
        println!("{}", key.endpoint_id());
        return Ok(());
    }

    if let (Some(_), Some(_)) = (&args.pair, &args.redeem) {
        anyhow::bail!("--pair and --redeem are two ways in; use one");
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
            portal_core::ci::ENROLLMENT_KEY_VAR,
        )?;
    }
    let provisioning = portal_core::ci::secret_from(
        args.provisioning_key_file.as_deref(),
        portal_core::ci::PROVISIONING_KEY_VAR,
    )?;
    if provisioning.is_some() && (args.pair.is_some() || args.redeem.is_some()) {
        anyhow::bail!("a Provisioning Key and --pair/--redeem are different ways in; use one");
    }
    // **Refused on the arguments alone, before anything is spent.** Redeeming
    // is what says which peer, so naming one as well is either redundant or
    // wrong -- and finding out which would mean using up a single-use ticket
    // first, only to stop.
    if args.peer.is_some()
        && (args.pair.is_some() || args.redeem.is_some() || provisioning.is_some())
    {
        anyhow::bail!("--peer is not needed here: being let in is what names the peer");
    }
    if let Some(code) = &args.pair {
        // **A secret put in the wrong flag must not be sent as a code.** The
        // proxy would refuse it, but only after the secret had travelled in a
        // `code` field and landed in whatever that failure is logged to. They
        // are easy to mix up: all of them are "the thing they sent me".
        //
        // **All four prefixes, not just a ticket's.** A pairing code is eight
        // characters somebody reads aloud; everything with one of these
        // prefixes is a secret, and two of them are standing arrangements
        // rather than a single use, so putting one here is the more expensive
        // mistake of the two.
        if let Some(prefix) = isekai_p2p::agent::secret_prefix(code) {
            anyhow::bail!(
                "that is {}, not a pairing code{}\n\
                 Nothing was sent. ({})",
                what_it_is(prefix),
                match prefix {
                    isekai_p2p::agent::TICKET_PREFIX
                    | isekai_p2p::agent::TICKET_TRANSFER_PREFIX => " -- redeem it with --redeem.",
                    _ => ".",
                },
                isekai_p2p::agent::redact_secrets(code),
            );
        }
    }
    // Everything a ticket can be wrong about is settled before authenticating.
    let ticket = args
        .redeem
        .as_deref()
        .map(|t| check_ticket(&args, t))
        .transpose()?;

    let maps = maps(&args.map, args.bind)?;
    let letting_in = args.pair.is_some() || ticket.is_some() || provisioning.is_some();
    if maps.is_empty() && !letting_in {
        anyhow::bail!("nothing to forward; pass at least one --map port:service");
    }

    let cfg = config(&args, &tokens, key).await?;
    // From here on this Endpoint may exist, so every way out owes a slot back.
    if args.enroll {
        *enrolled = Some(cfg.clone());
    }

    // **Being let in and connecting are one command when both were asked for.**
    // Redeeming used to exit, so anyone starting out ran the same client twice
    // -- and the second run had to be told which peer, which the first one had
    // just been told. Without `--map` there is nothing to forward, so it still
    // stops after saying what it got.
    // **Made before anything that needs stopping**, so the grant keeper can
    // take it rather than a token nobody holds — with a throwaway, its
    // cooperative arm never fires and the only stop is `Drop`'s `abort`, which
    // can cut a redemption mid-request and leave msquic a handle for the drain
    // to wait on.
    let shutdown = CancellationToken::new();
    // **Held, not used** — underscored so that reads as intent rather than an
    // oversight. It is bound this far out because a provisioning grant is
    // capped at an hour precisely because redeeming again extends it: a client
    // that redeemed once would inherit the narrow ceiling without the thing
    // that makes it workable, and dropping the guard early is exactly that.
    let mut _keeper = None;
    let admitted_by = match (&args.pair, &ticket, &provisioning) {
        (Some(code), _, _) => {
            Some(redeem(&cfg, code, args.label.as_deref(), !maps.is_empty()).await?)
        }
        (None, Some(transfer), _) => {
            Some(redeem_ticket(&cfg, transfer, args.label.as_deref(), !maps.is_empty()).await?)
        }
        (None, None, Some(key)) => {
            let (owner, held) = redeem_provisioning(
                &cfg,
                key,
                portal_core::ci::assertions(&args.oidc, &args.oidc_token_file)?,
                args.label.as_deref(),
                !maps.is_empty(),
                shutdown.clone(),
            )
            .await?;
            _keeper = held;
            Some(owner)
        }
        (None, None, None) => None,
    };
    if maps.is_empty() {
        return Ok(());
    }
    // **The peer we were just let in by**, which is better than working it out:
    // a client paired with more than one server would otherwise have to be told
    // by hand what it has this second been told by the proxy. The two cannot
    // both be set -- that is refused above, on the arguments.
    let peer = admitted_by.as_deref().or(args.peer.as_deref());
    // **A grant unless a capability was handed over.** The two are not
    // alternatives of equal standing: a grant is what an installation should be
    // running on, and the capability path is for the guest who was let in once.
    let reach = match (&args.capability, &args.listener) {
        (Some(capability), Some(listener_id)) => portal_core::session::Reach::Capability {
            capability,
            listener_id,
        },
        (Some(_), None) => {
            anyhow::bail!("--capability needs --listener, which names the one it is for")
        }
        (None, Some(_)) => anyhow::bail!(
            "--listener is only for the --capability path. On a grant the current listener \
             is found for you -- drop it, or add --capability"
        ),
        (None, None) => portal_core::session::Reach::Grant { peer },
    };

    // **Installed before the connect, and the hatch armed with it.**
    // Registering it replaces SIGTERM's default disposition for the rest of the
    // process, so from here a `kill` does nothing unless something polls — and
    // the select below is a long way off, past a proxy connect that can hang.
    // Registering early means a SIGTERM arriving during the connect is queued
    // and delivered the moment the select starts, which is a clean stop with
    // the slot returned; arming the hatch means a second one leaves at once
    // even if the connect never returns.
    let terminate = terminate_signal();
    tokio::pin!(terminate);

    let connected = portal_core::session::connect(&cfg, reach, &shutdown)
        .await
        .context("connect to the portal server")?;
    println!("connection id: {}", connected.session.connection_id());

    // **Closed on the way out of a failure, not dropped.** A `?` here — and
    // `--map 5432:db` with 5432 already bound is enough — would leave the
    // forwards uncancelled, the connection never reported closed (so the relay
    // leg stays reserved until the proxy expires it), and the registration
    // dropped during the unwind, which is the `RegistrationClose` this whole
    // change is about.
    if let Err(e) = start_forwards(&connected, maps, &shutdown).await {
        connected.close().await;
        return Err(e);
    }
    // **One line, last, on stdout.** A CI step needs a point to wait for that
    // means "the ports are bound", and grepping the forward lines would mean
    // knowing how many to expect. `camera-core`'s `synthetic_server` prints the
    // same word and `ios-ffi.yml` waits on it with `grep -q '^ready$'`.
    println!("ready");

    // **Both ways this can end without us**, and watching only one of them is
    // the worse failure: the forwarded ports stay bound over a connection that
    // is gone, so anything connecting to them is accepted and then goes quiet
    // rather than being refused.
    //
    // `ended` is the proxy withdrawing the session -- a revoked Grant, a lease
    // that could not be renewed. The connection ending is the server exiting.
    //
    // `ended()` is bound rather than awaited inline because it hands back an
    // owned token, and a temporary inside the `select!` is dropped before it is
    // polled.
    let ended = connected.session.ended();
    let peer = connected.peer.connection().clone();
    // **Armed only when the stop was an interrupt**, because the hatch turns the
    // *next* Ctrl+C into an immediate exit. On the other two arms nobody has
    // pressed anything yet, and arming there would make a user's first press
    // skip reporting the connection closed — which leaves the relay leg
    // reserved until the proxy expires it.
    let mut interrupted = false;
    // SIGTERM as well as SIGINT, because a job that stops this with a plain
    // `kill` is the ordinary case in CI, and on the enrolment path the way out
    // is what returns the slot.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => { interrupted = true; }
        _ = &mut terminate => { interrupted = true; }
        _ = ended.cancelled() => {
            tracing::warn!("the session ended; the forwards are going with it");
        }
        // **Both jobs, one task.** This moves the forwards onto a direct path
        // when one turns up, and returns when the connection is no longer
        // usable — which is what this arm is here for. They cannot be two
        // tasks: a connection's events are a single queue, so a second poller
        // would take events belonging to the first.
        _ = portal_core::path::keep_on_the_best_path(peer, shutdown.clone()) => {
            tracing::warn!("the peer connection closed; the forwards are going with it");
        }
    }
    if interrupted {
        portal_core::shutdown::hard_exit_on_second_signal();
    }
    // **Told to stop before it is dropped.** Dropping the keeper aborts it,
    // which can cut a redemption mid-request and leave msquic a handle the
    // drain then waits on; cancelling first lets it finish what it is doing
    // and return.
    shutdown.cancel();
    connected.close().await;
    Ok(())
}

/// What a secret prefix means, in words a person can act on.
fn what_it_is(prefix: &str) -> &'static str {
    match prefix {
        isekai_p2p::agent::TICKET_PREFIX | isekai_p2p::agent::TICKET_TRANSFER_PREFIX => "a ticket",
        isekai_p2p::agent::PROVISIONING_KEY_PREFIX => "a Provisioning Key",
        isekai_p2p::agent::ENROLLMENT_KEY_PREFIX => "an Enrollment Key",
        _ => "a secret",
    }
}

/// Redeem a pairing code, and say what it paired with.
///
/// Returns the Endpoint that let us in, so a caller that also has `--map` can
/// go straight there rather than working out which peer this was.
async fn redeem(
    cfg: &P2pConfig,
    code: &str,
    label: Option<&str>,
    then_connect: bool,
) -> anyhow::Result<String> {
    // Whatever was scanned, pasted or typed: a URI from a QR, or the eight
    // characters with or without their dash.
    let code = isekai_p2p::agent::pairing_code_from_input(code);
    let directory = isekai_p2p::PeerDirectory::open(cfg)
        .await
        .context("open the proxy control plane")?;
    let grant = directory
        .pair(&code, label)
        .await
        .context("redeem the pairing code")?;
    println!("paired with : {}", grant.owner_endpoint);
    println!("grant       : {}", grant.grant_id);
    if !then_connect {
        println!("\nConnect with --map alone; the listener is found for you.");
    }
    Ok(grant.owner_endpoint)
}

/// Redeem a ticket, and say what it let us into.
///
/// The transfer has already been checked by [`check_ticket`], which runs before
/// anything authenticates — including the authority check, which is why this
/// takes a [`TicketTransfer`] rather than a string.
///
/// Returns the Endpoint that let us in, for the same reason [`redeem`] does.
async fn redeem_ticket(
    cfg: &P2pConfig,
    transfer: &isekai_p2p::agent::TicketTransfer,
    label: Option<&str>,
    then_connect: bool,
) -> anyhow::Result<String> {
    let directory = isekai_p2p::PeerDirectory::open(cfg)
        .await
        .context("open the proxy control plane")?;
    let redeemed = directory
        .redeem_ticket(&transfer.ticket, label)
        .await
        .context("redeem the ticket")?;
    let grant = &redeemed.grant;
    println!("let in by   : {}", grant.owner_endpoint);
    println!("grant       : {}", grant.grant_id);
    match &grant.expires_at {
        Some(at) => println!("expires at  : {at}"),
        // The proxy is required to put a finite life on a ticket's grant, so
        // this should not happen; say so rather than printing nothing, because
        // "access that never lapses" is the one thing tickets exist to avoid.
        None => println!("expires at  : never -- unexpected for a ticket"),
    }
    if redeemed.listeners.is_empty() && !then_connect {
        println!("\nNothing is listening on that Endpoint yet. That is not a failure:");
        println!("you are authorised, and --map will find it once the server is up.");
    } else if !then_connect {
        println!("\nConnect with --map alone; the listener is found for you.");
    }
    Ok(grant.owner_endpoint.clone())
}

/// Redeem a Provisioning Key, and keep the grant it made alive.
///
/// Returns the Endpoint that let us in and, when this run goes on to forward,
/// the guard that re-redeems. **Unlike a ticket this runs every time**: a
/// second redemption answers `200` and extends the grant rather than being
/// refused, which is the whole reason its ceiling can be an hour.
async fn redeem_provisioning(
    cfg: &P2pConfig,
    key: &str,
    assertions: Option<Arc<dyn isekai_p2p::AssertionSource>>,
    label: Option<&str>,
    then_connect: bool,
    shutdown: CancellationToken,
) -> anyhow::Result<(String, Option<portal_core::grant::GrantKeeper>)> {
    let directory = isekai_p2p::PeerDirectory::open(cfg)
        .await
        .context("open the proxy control plane")?;
    // Minted for this call. The proxy checks the binding on every redemption,
    // which is what stops a leaked key working once the job has ended.
    let assertion = match &assertions {
        Some(source) => Some(
            source
                .assertion(PROXY_AUDIENCE)
                .await
                .context("could not mint a workload identity token for the proxy")?,
        ),
        None => None,
    };
    let redeemed = directory
        .redeem_provisioning_key(key, assertion.as_deref(), label)
        .await
        .context("redeem the provisioning key")?;
    let grant = &redeemed.grant;
    println!("let in by   : {}", grant.owner_endpoint);
    println!("grant       : {}", grant.grant_id);
    match &grant.expires_at {
        Some(at) => println!("expires at  : {at}  (extended while this runs)"),
        // The proxy is required to put a finite life on one of these, so this
        // should not happen; say so rather than printing nothing.
        None => println!("expires at  : never -- unexpected for a provisioning key"),
    }
    let owner = grant.owner_endpoint.clone();
    if !then_connect {
        println!("\nNothing is being forwarded, so this grant is not being kept alive.");
        println!("Run again with --map when there is work to do.");
        return Ok((owner, None));
    }
    let keeper = portal_core::grant::keep_the_grant(
        directory,
        key.to_owned(),
        assertions,
        grant.expires_at.clone(),
        label.map(str::to_owned),
        shutdown,
    );
    Ok((owner, Some(keeper)))
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

/// Check a ticket's shape and where it wants to be redeemed, before anything
/// on the network happens.
///
/// **The string says which proxy, and that is not the same as choosing it.**
/// Redeeming presents this Endpoint's token, and PoP signs the method, path and
/// body but not the authority — so nothing binds those credentials to the proxy
/// they were meant for. Taking the address out of a pasted string would mean
/// whoever composed the string picks where the token goes.
///
/// So a mismatch stops here, before `--auth0-token` is even read, and names the
/// flag to pass. It also keeps what follows honest: every later `--map` builds
/// its config from `--proxy-url` again, and a grant made at some other proxy
/// would be looked up at this one and not found.
fn check_ticket(args: &Args, ticket: &str) -> anyhow::Result<isekai_p2p::agent::TicketTransfer> {
    let Some(transfer) = isekai_p2p::agent::ticket_from_transfer(ticket) else {
        // Deliberately does not echo the value back: it is a secret until it is
        // spent, and a failed paste is exactly the moment somebody copies the
        // whole line into a bug report.
        anyhow::bail!(
            "that is not a ticket -- expected the `iskt1_` string the operator sent, \
             or a bare `tkt1_` secret"
        );
    };
    let configured = isekai_p2p::agent::proxy_authority(&args.proxy_url);
    // Case-insensitively, because host names are: a ticket issued against
    // `Tokyo.link.…` would otherwise be refused by a client on the default
    // lowercase URL, with an error naming two addresses that read the same.
    // The security property is unchanged -- this still has to be the host the
    // operator passed.
    if !transfer.proxy.is_empty() && !transfer.proxy.eq_ignore_ascii_case(configured) {
        anyhow::bail!(
            "this ticket is for {}, but --proxy-url is {configured}.\n\
             Redeeming sends this Endpoint's token to whichever proxy is used, so \
             the address is not taken from the ticket on its own.\n\
             If you trust it: --proxy-url https://{} --redeem …\n\
             Pass it to every later command too -- that is where the grant lives.",
            transfer.proxy,
            transfer.proxy,
        );
    }
    Ok(transfer)
}

/// Bind each mapped port and start forwarding it.
///
/// Separate so the caller can close the session when one fails; see there.
async fn start_forwards(
    connected: &portal_core::session::Connected,
    maps: Vec<(Protocol, SocketAddr, String)>,
    shutdown: &CancellationToken,
) -> anyhow::Result<()> {
    for (protocol, local, service) in maps {
        let forwarding = match protocol {
            Protocol::Tcp => {
                portal_core::client::forward(
                    connected.peer.connection().clone(),
                    local,
                    service.clone(),
                    shutdown.clone(),
                )
                .await
            }
            // `Arc::clone` and not a binding kept here: `Connected::close`
            // drops the last one before it waits for msquic, and one held by
            // this loop would make that wait time out.
            Protocol::Udp => {
                portal_core::udp::forward(
                    std::sync::Arc::clone(&connected.sessions),
                    local,
                    service.clone(),
                    shutdown.clone(),
                )
                .await
            }
        }
        .with_context(|| format!("forward {protocol} {local} to `{service}`"))?;
        println!("{protocol} {forwarding} -> {service}");
    }
    Ok(())
}

/// The P2P configuration these arguments describe.
///
/// Built in one place because three paths need it — pairing, a grant connect
/// and a capability connect — and only the last of those used to exist.
async fn config(
    args: &Args,
    tokens: &std::path::Path,
    key: isekai_p2p::agent::EndpointKey,
) -> anyhow::Result<P2pConfig> {
    let credential = if args.enroll {
        // The client's own variable: this key carries `peer-connect:initiate`
        // and the server's carries what a listener needs, so they are two keys
        // and two variables.
        portal_core::ci::enrollment_credential(
            args.enrollment_key_file.as_deref(),
            portal_core::ci::ENROLLMENT_KEY_VAR,
            &args.oidc,
            &args.oidc_token_file,
        )?
    } else {
        let auth = portal_core::login::authenticate(tokens, args.auth0_token.as_deref()).await?;
        // **The whole point of the source.** The Endpoint Token renewal runs
        // every few minutes for the life of the session and needs a current
        // Auth0 token each time; without one it reuses one that expires.
        isekai_p2p::Credential::auth0(auth.token, auth.source, args.register)
    };
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

/// Answer the Enrollment Key commands, which need no key of this Endpoint's own.
///
/// **Route A, with no PoP.** The caller is a person rather than an Endpoint, so
/// there is no Endpoint private key to bind the request to (§8.8.2) — which is
/// also why `--login` is the whole of what these need.
async fn enrollment_admin(args: &Args, tokens: &Path) -> anyhow::Result<()> {
    // **Settled on the arguments, before anything authenticates.** A missing or
    // half-given binding is a typo, and a sign-in tells the operator nothing
    // they did not already know. `portal-server` does the same with its own
    // binding flags, and `portal-client` with a ticket's authority.
    let request = args
        .issue_enrollment_key
        .then(|| enrollment_request(args))
        .transpose()?;
    // Same reasoning: a missing or misspelled reason is a fact about the
    // arguments, and a sign-in adds nothing to saying so.
    let reason = args
        .revoke_endpoint
        .is_some()
        .then(|| revoke_reason(args))
        .transpose()?;
    let auth = portal_core::login::authenticate(tokens, args.auth0_token.as_deref()).await?;
    let identity = isekai_p2p::enrollment::Identity::new(&args.identity_url, args.identity_http3);
    let token = &auth.token;

    if let Some(key_id) = &args.revoke_enrollment_key {
        let revoked = isekai_p2p::enrollment::revoke(&identity, token, key_id)
            .await
            .with_context(|| format!("revoke enrollment key {key_id}"))?;
        println!("revoked     : {}", revoked.key_id);
        // **The two lists are the answer, not decoration.** An `ephemeral` key
        // takes its Endpoints down; one that is not leaves them running,
        // because an Endpoint revocation cannot be undone and one key
        // registers one Endpoint — retiring a long-lived runner's Endpoint
        // means it cannot come back until somebody makes it a new keypair.
        if let Some(effects) = &revoked.effects {
            for id in &effects.revoked_endpoints {
                println!("  retired   : {id}");
            }
            for id in &effects.remaining_endpoints {
                println!("  still up  : {id}  (revoke it yourself if you meant to)");
            }
        }
        println!("No new Endpoints can be registered with it, and no derived Endpoint");
        println!("can renew its token. The record of who came in stays.");
    }

    if let Some(request) = &request {
        let issued = isekai_p2p::enrollment::issue(&identity, token, request)
            .await
            .context("issue an enrollment key")?;
        // The secret first: everything else in the response is optional, and a
        // missing `created_at` must not cost the operator the one string they
        // came for.
        println!("\nPut this in the job's secret store as ISEKAI_ENROLLMENT_KEY:\n");
        println!("  {}", issued.key);
        println!();
        match &issued.key_id {
            Some(id) => println!("key id      : {id}  (--revoke-enrollment-key takes this)"),
            None => println!("key id      : not reported -- --enrollment-keys will list it"),
        }
        if let Some(at) = &issued.expires_at {
            println!("expires at  : {at}");
        }
        if !issued.permissions.is_empty() {
            println!("permissions : {}", issued.permissions.join(", "));
        }
        if !issued.protocols.is_empty() {
            println!("protocols   : {}", issued.protocols.join(", "));
        }
        if let Some(slots) = issued.max_live_endpoints {
            println!("slots       : {slots} Endpoints alive at once");
        }
        print_enrollment_binding(issued.binding.as_ref());
        // **Not authorization, and said so.** §8.8.2 is explicit that issuing
        // succeeds with these present; they name the §8.8.10 mismatches that
        // otherwise surface in CI days later.
        for warning in &issued.warnings {
            println!("warning     : {warning}");
        }
        println!("\nThe job also needs a Provisioning Key from the server side --");
        println!("portal-server --provisioning-key. They are different objects issued");
        println!("by different servers, and revoked at different ones.");
    }

    if let (Some(endpoint_id), Some(reason)) = (&args.revoke_endpoint, reason) {
        // **Looked up first, so the answer can say what stays.** A row whose
        // key another live row shares keeps working after this (#16), and an
        // emergency exit that looks taken while the door is open is the one
        // thing §8.7 must not be. A failed lookup does not stop the
        // revocation — that is what was asked for.
        // **A failed lookup is not "no siblings".** Treating the two as one
        // would print a clean revocation while the key may still work
        // elsewhere, which is the state this whole command exists to refuse.
        let before = isekai_p2p::endpoints::get(&identity, token, endpoint_id).await;
        let revoked = isekai_p2p::endpoints::revoke(
            &identity,
            token,
            endpoint_id,
            reason,
            args.note.as_deref(),
        )
        .await
        .with_context(|| format!("revoke {endpoint_id}"))?;
        println!("revoked     : {}", revoked.endpoint_id);
        if let Some(at) = &revoked.revoked_at {
            println!("at          : {at}");
        }
        print_effects(revoked.effects.as_ref());
        // **A `200` does not mean the Endpoint stopped**, and §8.7 says so.
        // Identity's own record is settled either way; whether the proxy heard
        // is a separate fact, and the one that decides if anything is still
        // reachable.
        match revoked.proxy_notification.as_deref() {
            Some("delivered") => println!("proxy       : told, and enforcing it"),
            Some("partial") => println!(
                "proxy       : TOLD BUT NOT ENFORCING -- its revocation set is full, and this \
                 Endpoint keeps getting through until it restarts",
            ),
            Some("failed") => println!(
                "proxy       : NOT TOLD -- its grants and listeners for this Endpoint stand. \
                 Repeat this once the proxy is reachable; it is idempotent",
            ),
            Some("disabled") => println!(
                "proxy       : not told -- this deployment has no PROXY_INTERNAL_URL, so \
                 nothing there has changed",
            ),
            other => println!("proxy       : {}", other.unwrap_or("not reported")),
        }
        // **The server's word for why**, which is what decides whether repeating
        // helps: `unreachable` and `gave up after …` are worth another try once
        // the path is open, and the rest usually are not.
        if let Some(detail) = &revoked.proxy_notification_detail {
            println!("              ({detail})");
        }
        match &before {
            // **`duplicate_key` decides, and the list only names names.** A row
            // can be flagged with an empty list — the siblings are same-tenant
            // only — and gating on the list alone would print nothing in
            // exactly the case the flag was raised for.
            Ok(detail)
                if detail.summary.duplicate_key || !detail.duplicate_key_siblings.is_empty() =>
            {
                println!("\nTHE KEY STILL WORKS. Another Endpoint shares it, so revoking this row");
                println!("stopped a name and not a credential.");
                for id in &detail.duplicate_key_siblings {
                    println!("  still live : {id}");
                }
                if detail.duplicate_key_siblings.is_empty() {
                    println!("  (the other rows are not in this tenant, so they are not named)");
                }
            }
            Ok(_) => {}
            Err(e) => println!(
                "\ncould not check whether another Endpoint shares this key: {e:#}\n\
                 Look it up with --endpoints before trusting that the key is stopped.",
            ),
        }
    }

    if args.endpoints {
        let status = args.endpoint_status.as_deref();
        // **Paged through, because the point is finding a row to act on.**
        // Printing one page and saying more exist leaves the id somebody came
        // for out of reach, with no flag to go further. The enrolment records
        // follow their cursor for the same reason.
        let mut cursor: Option<String> = None;
        let mut shown = 0usize;
        let mut hidden = None;
        let mut truncated = false;
        for _ in 0..100 {
            let page = isekai_p2p::endpoints::list(&identity, token, status, cursor.as_deref())
                .await
                .context("list endpoints")?;
            for endpoint in &page.items {
                print_endpoint(endpoint);
                shown += 1;
            }
            // The count is over the whole filter rather than the page, so the
            // first answer is the one to keep.
            hidden = hidden.or(page.revoked_count);
            match page.next_cursor {
                Some(next) => {
                    cursor = Some(next);
                    truncated = true;
                }
                None => {
                    truncated = false;
                    break;
                }
            }
        }
        if shown == 0 {
            println!("No endpoints.");
        }
        // **Said even when it is zero.** The default filter hides revoked rows,
        // and the server counts them separately so that the hiding is visible
        // rather than silent.
        if let Some(hidden) = hidden {
            println!("\n{hidden} revoked endpoint(s) not shown -- --endpoint-status all");
        }
        // **"No more here" is not "that was everything".** Rows can be
        // registered or revoked while the pages are walked, so a listing that
        // ended is a snapshot rather than a census.
        if truncated {
            println!("Stopped after 100 pages; there are more rows than this shows.");
        }
    }

    if args.enrollment_keys {
        let keys = isekai_p2p::enrollment::list(&identity, token)
            .await
            .context("list enrollment keys")?;
        if keys.is_empty() {
            println!("No enrollment keys issued.");
        }
        for key in &keys {
            let label = key
                .label
                .as_deref()
                .map(|l| format!(", {l}"))
                .unwrap_or_default();
            let slots = match (key.live_endpoints, key.max_live_endpoints) {
                (Some(live), Some(max)) => format!("{live}/{max} slots"),
                (Some(live), None) => format!("{live} live"),
                _ => "slots unknown".to_owned(),
            };
            // Which of these is a bare bearer credential is the question worth
            // answering here, the same as on the server's side.
            let bound = match key.binding.as_ref().map(|b| b.kind.as_str()) {
                Some("oidc") => "oidc".to_owned(),
                Some("none") | Some("") | None => "UNBOUND".to_owned(),
                Some(other) => other.to_owned(),
            };
            println!(
                "key         : {}  {bound}, {slots}, {}{label}",
                key.key_id,
                key.status.as_deref().unwrap_or("?"),
            );
        }
    }

    if let Some(key_id) = &args.enrollment_key_enrollments {
        let rows = isekai_p2p::enrollment::enrollments(&identity, token, key_id)
            .await
            .with_context(|| format!("list enrollments of {key_id}"))?;
        if rows.is_empty() {
            println!("Nothing has registered with {key_id}.");
        }
        for row in &rows {
            let subject = row
                .binding_subject
                .as_deref()
                .map(|s| format!("  as {s}"))
                .unwrap_or_default();
            // **`enrollment_released` against `enrollment_idle` is the axis
            // worth watching.** The first means the job tidied up after itself;
            // the second means nothing did and the sweep got there, which is a
            // CI problem rather than a capacity one.
            let ended = match (row.status.as_deref(), row.revoke_reason.as_deref()) {
                (_, Some(reason)) => format!("  ended {reason}"),
                (Some(status), None) => format!("  {status}"),
                _ => String::new(),
            };
            println!("registered  : {}{subject}{ended}", row.endpoint_id);
        }
    }
    Ok(())
}

/// The reason these arguments name, refused before anything authenticates.
///
/// **Required, and not defaulted.** §8.7 makes it mandatory, and a default
/// would write somebody else's word into an audit log that gets read during an
/// incident. The vocabulary is closed and half of it is Identity's own —
/// `enrollment_idle` and `enrollment_released` are what the sweep and a job
/// write, and naming one here is refused by the server.
fn revoke_reason(args: &Args) -> anyhow::Result<isekai_p2p::agent::RevokeReason> {
    use isekai_p2p::agent::RevokeReason;
    let Some(reason) = args.reason.as_deref() else {
        anyhow::bail!(
            "--revoke-endpoint needs --reason: device_lost, endpoint_deleted, admin_revoke \
             or security_incident. It goes in the audit log, so it is not guessed for you"
        );
    };
    match reason {
        "device_lost" => Ok(RevokeReason::DeviceLost),
        "endpoint_deleted" => Ok(RevokeReason::EndpointDeleted),
        "admin_revoke" => Ok(RevokeReason::AdminRevoke),
        "security_incident" => Ok(RevokeReason::SecurityIncident),
        // Named rather than lumped in with a typo: somebody reaching for these
        // has read them in a listing, and the answer is that Identity writes
        // them and a request may not.
        "enrollment_idle" | "enrollment_released" | "enrollment_key_revoked" => anyhow::bail!(
            "`{reason}` is a reason Identity writes for itself -- the idle sweep, a job \
             returning its slot, a key being revoked. A request cannot claim one"
        ),
        other => anyhow::bail!(
            "unknown --reason `{other}`: device_lost, endpoint_deleted, admin_revoke \
             or security_incident"
        ),
    }
}

/// Say what the revocation destroyed, when there was anything.
///
/// **Zero is not silence.** "Nothing was torn down" and "the proxy was never
/// told" produce the same zeros, which is why the notification line is printed
/// beside this rather than instead of it.
fn print_effects(effects: Option<&isekai_p2p::agent::RevokeEffects>) {
    let Some(effects) = effects else {
        return;
    };
    // **Every counter, because a missing one reads as nothing happened.** An
    // Endpoint with only a public listener and live tokens would otherwise be
    // reported as "nothing was there to remove" while both were torn down.
    let counted: Vec<String> = [
        ("tokens", effects.revoked_tokens),
        ("peer listeners", effects.deleted_peer_listeners),
        ("public listeners", effects.deleted_public_listeners),
        ("grants", effects.deleted_grants),
        ("capabilities", effects.deleted_capabilities),
        ("connections", effects.closed_connections),
        ("pairing codes", effects.deleted_pairing_codes),
        ("policy leases", effects.revoked_policy_leases),
    ]
    .iter()
    .filter_map(|(label, n)| match n {
        Some(n) if *n > 0 => Some(format!("{n} {label}")),
        _ => None,
    })
    .collect();
    if counted.is_empty() {
        println!("torn down   : nothing was there to remove");
    } else {
        println!("torn down   : {}", counted.join(", "));
    }
    // **Worth saying when it is false.** Repeating a revocation whose
    // notification failed is the documented recovery, and this is what tells
    // the operator whether the repeat did anything or the first one had.
    if effects.newly_revoked == Some(false) {
        println!("note        : it was already revoked; this call changed nothing at Identity");
    }
}

/// Print one Endpoint the way somebody looking for what to stop needs it.
fn print_endpoint(e: &isekai_p2p::agent::EndpointSummary) {
    let name = e.device_name.as_deref().unwrap_or("(no name)");
    let status = e.status.as_deref().unwrap_or("?");
    let mut notes = Vec::new();
    if e.ephemeral {
        notes.push("ephemeral".to_owned());
    }
    if let Some(key) = &e.enrollment_key_id {
        notes.push(format!("from {key}"));
    }
    if let Some(reason) = &e.revoke_reason {
        notes.push(reason.clone());
    }
    // **First, and in capitals.** Revoking a row whose key another live row
    // shares does not stop the key (ISEKAI-identity#16), and somebody reading
    // this list is choosing what to stop.
    if e.duplicate_key {
        notes.insert(0, "SHARES ITS KEY".to_owned());
    }
    let notes = if notes.is_empty() {
        String::new()
    } else {
        format!("  ({})", notes.join(", "))
    };
    println!("endpoint    : {}  {status}  {name}{notes}", e.endpoint_id);
}

/// What to ask for when issuing, refused before anything authenticates.
///
/// **`binding` cannot be omitted**, and this insists on the same thing §8.8.2
/// does: every other knob fails closed, so letting the shortest request be the
/// most dangerous one would be backwards. `--binding-none` is how somebody says
/// they meant it.
fn enrollment_request(args: &Args) -> anyhow::Result<isekai_p2p::agent::NewEnrollmentKey> {
    // **The contradiction is matched first.** Reaching the half-given arms with
    // `--binding-none` also set answers a narrower question than the one the
    // operator got wrong.
    if args.binding_none && (args.binding_oidc.is_some() || args.binding_subject.is_some()) {
        anyhow::bail!("--binding-none and --binding-oidc are two answers; give one");
    }
    let binding = match (&args.binding_oidc, &args.binding_subject, args.binding_none) {
        (Some(issuer), Some(subject), false) => isekai_p2p::agent::Binding::Oidc {
            issuer: issuer.clone(),
            subject: subject.clone(),
        },
        (None, None, true) => isekai_p2p::agent::Binding::None,
        (None, None, false) => anyhow::bail!(
            "--issue-enrollment-key needs a binding: --binding-oidc with --binding-subject, \
             or --binding-none to say the key alone is enough. Omitting it would make the \
             shortest command the most dangerous one"
        ),
        (Some(_), None, _) => anyhow::bail!(
            "--binding-oidc needs --binding-subject: an issuer without a subject would let any \
             workload that issuer knows about register"
        ),
        (None, Some(_), _) => anyhow::bail!(
            "--binding-subject needs --binding-oidc, which says who vouches for that subject"
        ),
        // Unreachable: the contradiction is refused above.
        (_, _, true) => unreachable!("--binding-none with a binding is refused above"),
    };
    let mut request = isekai_p2p::agent::NewEnrollmentKey::new(binding);
    // **Narrow by default, and this is the one place it matters.** The server
    // burns the *ceiling* into the key when `permissions` is omitted, and the
    // ceiling is the deployment's `DEFAULT_PERMISSIONS` — so in a deployment
    // that enabled `peer-provisioning:create` for its portal server, an omitted
    // list would hand every CI Endpoint the power to mint Provisioning Keys of
    // its own. A job needs `peer-connect:initiate` and nothing else.
    request.permissions = Some(if args.permissions.is_empty() {
        vec!["peer-connect:initiate".to_owned()]
    } else {
        args.permissions.clone()
    });
    request.protocols = Some(if args.enrollment_protocols.is_empty() {
        vec![args.protocol.clone()]
    } else {
        args.enrollment_protocols.clone()
    });
    request.ttl = args.enrollment_ttl;
    request.max_live_endpoints = args.max_live_endpoints;
    request.endpoint_idle_ttl = args.endpoint_idle_ttl;
    request.label = args.enrollment_label.clone();
    Ok(request)
}

/// Show a key's binding, including the audience the job has to mint for.
fn print_enrollment_binding(binding: Option<&isekai_p2p::agent::BindingView>) {
    let Some(binding) = binding else {
        println!("bound to    : not reported -- check with --enrollment-keys");
        return;
    };
    match binding.kind.as_str() {
        "oidc" => {
            println!(
                "bound to    : {} / {}",
                binding.issuer.as_deref().unwrap_or("?"),
                binding.subject.as_deref().unwrap_or("?"),
            );
            // **The value the job cannot guess and nobody can set.** Identity
            // takes it from its own configuration, and it is deliberately not
            // the proxy's — a token minted for one is refused by the other.
            match binding.audience.as_deref() {
                Some(audience) => println!("audience    : {audience}  (the job mints for this)"),
                None => println!("audience    : not reported -- ask the Identity operator"),
            }
        }
        "none" | "" => {
            println!("bound to    : nothing -- the key alone can register Endpoints.");
            println!("              Never do this for a public repository's CI.");
        }
        other => println!("bound to    : {other}"),
    }
}

/// Parse `port:name` or `udp:port:name` into what to bind and what to ask for.
///
/// The address is assembled rather than formatted and re-parsed, which is what
/// lets `--bind ::1` work: an IPv6 address needs brackets in a `host:port`
/// string and does not have them here.
///
/// **The protocol has to be said and cannot be inferred.** The server looks a
/// name up under a protocol, so a `--map` that guessed wrong would be refused
/// with the same byte as a name that does not exist — a correct catalogue entry
/// reported as "the peer does not offer it". The prefix is optional only because
/// TCP is the common case; it is never ambiguous, since `udp` and `tcp` are not
/// port numbers.
fn maps(
    maps: &[String],
    bind: std::net::IpAddr,
) -> anyhow::Result<Vec<(Protocol, SocketAddr, String)>> {
    maps.iter()
        .map(|m| {
            let (protocol, rest) = match m.split_once(':') {
                Some(("tcp", rest)) => (Protocol::Tcp, rest),
                Some(("udp", rest)) => (Protocol::Udp, rest),
                _ => (Protocol::Tcp, m.as_str()),
            };
            let (port, service) = rest.split_once(':').with_context(|| {
                format!("--map wants `port:service` or `udp:port:service`, got `{m}`")
            })?;
            let port: u16 = port
                .parse()
                .with_context(|| format!("`{port}` is not a port, in --map `{m}`"))?;
            Ok((protocol, SocketAddr::new(bind, port), service.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use isekai_p2p::agent::RevokeReason;

    fn args_with(reason: Option<&str>) -> Args {
        let mut args: Args = argh::FromArgs::from_args(&["portal-client"], &[]).expect("defaults");
        args.revoke_endpoint = Some("ep:abc".to_owned());
        args.reason = reason.map(str::to_owned);
        args
    }

    #[test]
    fn a_reason_is_required() {
        let err = revoke_reason(&args_with(None)).unwrap_err();
        assert!(format!("{err:#}").contains("--reason"));
    }

    /// **Identity's own vocabulary is refused with its own message.** Somebody
    /// reaching for one of these has read it in a listing, and "unknown reason"
    /// would not answer why it cannot be used.
    #[test]
    fn identitys_own_reasons_are_refused_by_name() {
        for reason in [
            "enrollment_idle",
            "enrollment_released",
            "enrollment_key_revoked",
        ] {
            let err = revoke_reason(&args_with(Some(reason))).unwrap_err();
            let message = format!("{err:#}");
            assert!(message.contains("Identity writes for itself"), "{message}");
        }
    }

    #[test]
    fn a_typo_names_what_is_accepted() {
        let err = revoke_reason(&args_with(Some("lost"))).unwrap_err();
        assert!(format!("{err:#}").contains("device_lost"));
    }

    #[test]
    fn the_four_the_caller_may_use_parse() {
        for (text, expected) in [
            ("device_lost", RevokeReason::DeviceLost),
            ("endpoint_deleted", RevokeReason::EndpointDeleted),
            ("admin_revoke", RevokeReason::AdminRevoke),
            ("security_incident", RevokeReason::SecurityIncident),
        ] {
            assert_eq!(revoke_reason(&args_with(Some(text))).unwrap(), expected);
        }
    }
}
