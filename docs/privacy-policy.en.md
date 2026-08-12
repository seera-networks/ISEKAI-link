# ISEKAI link Privacy Policy

Version: 2026-08-05

## 1. Who we are

| | |
| --- | --- |
| Operator | SEERA Networks Corporation |
| Representative | Makiko Kozuka |
| Address | 6-23-4 2F Jingumae, Shibuya-ku, Tokyo, Japan |
| Data protection officer | Makiko Kozuka |
| Contact | info@seera-networks.com |

Referred to below as "we".

## 2. What this covers

The ISEKAI link camera application (camera-server), the desktop viewer
(camera-client), the iOS viewer, and the Identity API and relay (proxy) servers
they connect to.

## 3. What we collect

### 3.1 Account

Using the service requires an account. Authentication is provided by Auth0
(Okta, Inc.), through which we receive:

- your email address
- profile information held by Auth0, such as your name and picture
- the user identifier Auth0 issues

### 3.2 Device (Endpoint)

Registering a device sends the following to our Identity API:

- the device's public key, and the device identifier derived from it
  (Endpoint ID)
- a device name (`camera-server`, `camera-client` or `ios-camera-client` by
  default, or whatever you set)
- the times of registration and of each token issued

### 3.3 Connections

When traffic passes through the relay, our servers handle:

- **IP addresses and port numbers.** To establish a direct path, the service
  observes the public address your device appears from and tells the other side
  what it is. This is inherent to how the connection is made.
- connection identifiers, listener identifiers, grants and pairing codes
- operational records such as connection start and end times and traffic volume

### 3.4 Video

Video sent by the camera application passes through our relay on its way to a
viewer. It may show people, the inside of a home, or anything else in view. How
we handle it is set out in section 5.

### 3.5 Logs

We keep operational logs, including the connection information above, to
investigate faults. Diagnostic logging that you switch on in an application is
shown and kept on that device only, and is not sent to us.

### 3.6 What we do not collect

The service uses no third-party push notification, advertising, analytics, or
crash and error reporting service. We do not send your information to third
parties for any of those purposes.

## 4. Why we use it

1. To provide the service: authentication, device registration, connection
   brokering and relaying video.
2. To prevent abuse and keep the service secure.
3. To investigate faults and improve quality.
4. To meet legal obligations.

## 5. Video — please read

**While video passes through the relay, our systems are technically capable of
accessing its content.** The TLS certificate for the video connection, and the
matching private key, are issued by our servers and given to the camera
application.

- We do not view or retain video beyond the purposes in this policy.
- We do not record or accumulate video. The relay forwards it and nothing more.
- We do not provide video to anyone other than the viewer you have authorised.
- **Once a direct path is established between camera and viewer, the video no
  longer passes through our relay.** Whether that path can be established
  depends on both networks.

This is not an arrangement in which we are technically unable to see your video,
and we would rather say so than imply otherwise.

## 6. Sharing, processors and transfers abroad

### 6.1 Processors

- **Auth0 (Okta, Inc.)** provides authentication and handles the information in
  section 3.1.

Otherwise we do not disclose personal information to third parties without your
consent, except where the law requires it.

### 6.2 Transfers of personal data to third parties in foreign countries

We transfer personal data to third parties in foreign countries as follows.

| Recipient | Country | Information transferred | Basis |
| --- | --- | --- | --- |
| Okta, Inc. (Auth0) | United States | the information in section 3.1 | provision to a party that has established a system conforming to the standard in Article 16 of the APPI Enforcement Rules (we have entered into a data processing addendum with them) |

Okta, Inc. uses sub-processors in providing the service. We have confirmed that
it imposes obligations on them equivalent to or stronger than its own, and we
review how that is carried out at regular intervals.

On request to the contact in section 1, we will provide information about the
data-protection regime of the country the data is transferred to, an outline of
the measures the recipient takes, and how often and by what means we review
them.

**The information in sections 3.2 to 3.5 — device information, connection
information, video and operational logs — is not transferred to any third party
in a foreign country.**

## 7. How long we keep it

| | |
| --- | --- |
| Account information | until you close your account |
| Device registrations | until you remove the device |
| Connection logs | 3 years from collection |
| Video | not retained — relayed only |

## 8. What stays on your device

The following is stored on your device and not sent to us:

- the device's private key, a long-lived secret that must not be shared
- your Auth0 access and refresh tokens
- settings such as which servers to connect to

Signing out of an application deletes the Auth0 tokens from that device.

## 9. Your rights, and how to exercise them

You may ask us to notify you of the purpose of use, and to disclose, correct,
add to, delete, suspend the use of, erase or stop sharing the personal
information we hold about you, and to disclose our records of provision to
third parties.

- **Where to send it**: info@seera-networks.com
- **How**: write to us from your registered email address, setting out what you
  are asking for.
- **How we verify it is you**: as well as the message coming from your
  registered address, we send a confirmation code to that address and treat
  your reply as confirming your identity.
- **Requests through a representative**: a statutory representative (a parent
  or guardian of a minor, an adult guardian, and so on) or an appointed
  representative should also send a document evidencing their authority (a
  family register extract, a certificate of registered matters, a power of
  attorney) together with a copy of their own identification.
- **How disclosure is made**: you may ask for disclosure by electromagnetic
  record, in writing, or by another means. Without a preference we answer by
  electromagnetic record. Where the method you ask for would be difficult — if
  it would cost a great deal, for instance — we disclose in writing.
- **Fee**: none.

Some requests cannot be met, where the law says so. We will tell you, with our
reasons.

## 10. Measures taken to manage security

- **Technical**: traffic between your device and our servers is encrypted with
  TLS. Device private keys and authentication tokens are stored readable only by
  their owner. Access to personal data is limited to the people whose work
  requires it.
- **Organisational**: we limit who handles personal data and operate to an
  internal procedure setting out how. We have a procedure for reporting and
  responding to a leak or similar incident. We review how personal data is
  handled, and the measures in this section, at regular intervals and revise
  them where needed.
- **Personnel**: those who handle personal data are informed of what handling
  it requires of them.
- **Where the servers are**: our Identity API runs in Japan (Ishikari) and our
  relay servers in Japan (Tokyo), on equipment operated by cloud providers.
  Those providers do not handle our personal data.
- **Countries in which personal data is handled**: the information in sections
  3.2 to 3.5 is handled in Japan. The account information in section 3.1 is
  held primarily in the Japan region by our authentication provider, and may
  also be handled in **the United States, Germany and Romania** through its
  sub-processors. Some processing, by the nature of content delivery networks,
  is in a country that cannot be identified in advance. We have informed
  ourselves of the data-protection regimes of these countries and take the
  measures necessary and appropriate to manage security.

## 11. Minors

If you are under 16, please use the service with the consent of a parent or
guardian. Minors of 16 and over may use it only with the appropriate
involvement of a parent or guardian.

## 12. Changes

If we change this policy we will update its version, and applications will ask
for your agreement again the next time they start. We will give notice of
significant changes by other means as well.

## 13. Contact

SEERA Networks Corporation
info@seera-networks.com
