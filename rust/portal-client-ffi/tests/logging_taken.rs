//! A log bridge that could not be installed is reported, not passed off as
//! working (PR #298 review). Its own test binary: it takes the process-wide
//! subscriber before `init_logging` runs, which the unit tests must not do.

#[test]
fn a_bridge_that_could_not_be_installed_is_reported_on_every_call() {
    tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::default())
        .expect("nothing else has a subscriber yet");
    for _ in 0..2 {
        let err = portal_client_ffi::init_logging(String::new()).expect_err("no bridge");
        assert!(err.to_string().contains("not reaching logcat"), "{err}");
    }
}
