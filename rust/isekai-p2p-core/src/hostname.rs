//! Does this certificate belong to the host we dialled?
//!
//! # Why this is here rather than in the TLS stack
//!
//! A certificate being valid and a certificate being *yours* are two different
//! checks. The first says a CA signed it; the second says the name in it is the
//! name we asked for. Without the second, any certificate from any CA in the
//! trust store is accepted for any host — and obtaining a certificate for a
//! domain you control is free and automated.
//!
//! Our credentials ask for the peer certificate to be handed to us
//! (`INDICATE_CERTIFICATE_RECEIVED`), so the check can be made here, on the
//! connection, where the name we dialled is still known. See
//! [`ISEKAI-link#134`](https://github.com/seera-networks/ISEKAI-link/issues/134).
//!
//! # What is matched
//!
//! `subjectAltName` only. **`CN` is not consulted**: it has not been a valid
//! source of identity since RFC 2818 was replaced, browsers stopped honouring
//! it years ago, and accepting it here would take a certificate that names
//! nothing and treat it as naming us.
//!
//! - `dNSName`, ASCII case-insensitively, with a leading `*` matching exactly
//!   one label and never the whole name
//! - `iPAddress`, when the host dialled is a literal address

use std::net::IpAddr;

/// Whether `der` names `host`.
///
/// `Err` carries what was presented, because the useful thing to see in a log
/// is which name arrived when the expected one did not.
pub fn certificate_matches(der: &[u8], host: &str) -> Result<(), String> {
    use x509_parser::prelude::*;

    let (_, certificate) = X509Certificate::from_der(der)
        .map_err(|e| format!("the certificate does not parse: {e}"))?;
    let Ok(Some(san)) = certificate.subject_alternative_name() else {
        return Err("the certificate has no subjectAltName".to_owned());
    };

    // `Uri::host()` keeps the brackets on an IPv6 literal (`[::1]`), and
    // `IpAddr` will not parse those — so without this the address arm can never
    // match and the SAN's names get compared to a string with brackets in it.
    let wanted_ip: Option<IpAddr> = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .parse()
        .ok();
    let mut presented = Vec::new();
    for name in &san.value.general_names {
        match name {
            GeneralName::DNSName(dns) => {
                presented.push((*dns).to_owned());
                if wanted_ip.is_none() && dns_matches(dns, host) {
                    return Ok(());
                }
            }
            GeneralName::IPAddress(bytes) => {
                let addr = match bytes.len() {
                    4 => {
                        let mut octets = [0_u8; 4];
                        octets.copy_from_slice(bytes);
                        Some(IpAddr::from(octets))
                    }
                    16 => {
                        let mut octets = [0_u8; 16];
                        octets.copy_from_slice(bytes);
                        Some(IpAddr::from(octets))
                    }
                    _ => None,
                };
                if let Some(addr) = addr {
                    presented.push(addr.to_string());
                    if wanted_ip == Some(addr) {
                        return Ok(());
                    }
                }
            }
            _ => {}
        }
    }
    Err(format!(
        "the certificate is for {}, not {host}",
        if presented.is_empty() {
            "no name this understands".to_owned()
        } else {
            presented.join(", ")
        },
    ))
}

/// One `dNSName` against the host, per RFC 6125 in the shape TLS stacks use.
///
/// A wildcard stands for **exactly one** whole label and only the leftmost one,
/// so `*.example.com` matches `a.example.com` and neither `example.com` nor
/// `a.b.example.com`. Partial wildcards (`w*.example.com`) are not honoured:
/// they are legal to write and no modern client accepts them.
fn dns_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let host = host.trim_end_matches('.');
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    let Some(rest) = pattern.strip_prefix("*.") else {
        return pattern.eq_ignore_ascii_case(host);
    };
    // The wildcard consumes one label, so what follows the first dot in the
    // host has to be the rest of the pattern — and there has to be a label in
    // front of it.
    match host.split_once('.') {
        Some((label, tail)) if !label.is_empty() => tail.eq_ignore_ascii_case(rest),
        _ => false,
    }
}

/// A connector callback that refuses any certificate not naming `host`.
///
/// The credential has to carry `INDICATE_CERTIFICATE_RECEIVED` and
/// `USE_PORTABLE_CERTIFICATES` for this to run and for the certificate to
/// arrive in a parseable form; [`crate::transport::make_client_config`] sets
/// both unless validation is off altogether.
#[cfg(feature = "msquic")]
pub fn refuse_other_hosts(host: String) -> h3_util::msquic_async::PeerCertificateCallback {
    use h3_util::msquic_async::h3_msquic_async::msquic;

    std::sync::Arc::new(move |certificate, _flags, _status, _chain| {
        // `USE_PORTABLE_CERTIFICATES` makes this a `QUIC_BUFFER` of DER. It is
        // msquic's memory and lives only for this call, so nothing is kept.
        let der = unsafe {
            (certificate as *const msquic::ffi::QUIC_BUFFER)
                .as_ref()
                .map(|buffer| msquic::BufferRef::from_ffi_ref(buffer).as_bytes())
        };
        let verdict = match der {
            Some(der) => certificate_matches(der, &host),
            None => Err("the peer presented no certificate".to_owned()),
        };
        match verdict {
            Ok(()) => {
                tracing::debug!(host = %host, "the certificate is for the host dialled");
                Ok(())
            }
            Err(reason) => {
                // At `warn`, and not swallowed: this is either a
                // misconfiguration or the thing the check exists to catch, and
                // both want saying.
                tracing::warn!(host = %host, "refusing the connection: {reason}");
                Err(msquic::Status::from(
                    msquic::ffi::QUIC_STATUS_BAD_CERTIFICATE,
                ))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn cert_for(names: Vec<String>) -> Vec<u8> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        let params = CertificateParams::new(names).expect("params");
        params
            .self_signed(&key)
            .expect("self-signed")
            .der()
            .to_vec()
    }

    /// The case the check exists for: a certificate that is perfectly valid and
    /// is for somebody else.
    #[test]
    fn a_certificate_for_another_host_is_refused() {
        let der = cert_for(vec!["attacker.example".to_owned()]);
        let err = certificate_matches(&der, "tokyo.link.isekai.tools").unwrap_err();
        assert!(err.contains("attacker.example"), "{err}");
    }

    /// The ordinary case, which must not become noisy.
    #[test]
    fn the_right_host_is_accepted() {
        let der = cert_for(vec!["tokyo.link.isekai.tools".to_owned()]);
        assert!(certificate_matches(&der, "tokyo.link.isekai.tools").is_ok());
    }

    /// DNS is case-insensitive and certificates are not always lowercased.
    #[test]
    fn the_comparison_ignores_case() {
        let der = cert_for(vec!["Tokyo.Link.Isekai.Tools".to_owned()]);
        assert!(certificate_matches(&der, "tokyo.link.isekai.tools").is_ok());
    }

    /// A certificate that names nothing must not be read as naming us — which
    /// is what consulting `CN` would do.
    #[test]
    fn a_certificate_with_no_san_is_refused() {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "tokyo.link.isekai.tools");
        params.distinguished_name = dn;
        let der = params
            .self_signed(&key)
            .expect("self-signed")
            .der()
            .to_vec();
        assert!(certificate_matches(&der, "tokyo.link.isekai.tools").is_err());
    }

    /// Anything unparseable is a refusal rather than a panic mid-handshake.
    #[test]
    fn rubbish_is_refused_rather_than_fatal() {
        assert!(certificate_matches(b"not a certificate", "example.com").is_err());
    }

    /// A wildcard covers one label, and the bugs are all at the edges: it must
    /// not match the bare domain, and it must not swallow two labels.
    #[test]
    fn a_wildcard_covers_exactly_one_label() {
        assert!(dns_matches("*.example.com", "a.example.com"));
        assert!(!dns_matches("*.example.com", "example.com"));
        assert!(!dns_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_matches("*.example.com", ".example.com"));
    }

    /// A partial wildcard is legal to write and matches nothing here, rather
    /// than being treated as a prefix.
    #[test]
    fn a_partial_wildcard_matches_nothing() {
        assert!(!dns_matches("w*.example.com", "www.example.com"));
    }

    /// `Uri::host()` hands back an IPv6 literal with its brackets on, and
    /// `IpAddr` does not parse those — so a bracketed host would never reach
    /// the address arm at all.
    #[test]
    fn a_bracketed_ipv6_literal_still_matches() {
        let der = cert_for(vec!["::1".to_owned()]);
        assert!(certificate_matches(&der, "[::1]").is_ok());
        assert!(certificate_matches(&der, "::1").is_ok());
    }

    /// The video path dials a loopback FQDN in production but a literal address
    /// in development, and a certificate can name one.
    #[test]
    fn a_literal_address_matches_an_ip_san() {
        let der = cert_for(vec!["127.0.0.1".to_owned()]);
        assert!(certificate_matches(&der, "127.0.0.1").is_ok());
        assert!(certificate_matches(&der, "example.com").is_err());
    }

    /// A name that happens to read like an address must not be matched against
    /// the DNS entries of a certificate that only names an address.
    #[test]
    fn an_ip_san_does_not_satisfy_a_hostname() {
        let der = cert_for(vec!["127.0.0.1".to_owned()]);
        assert!(certificate_matches(&der, "localhost").is_err());
    }
}
