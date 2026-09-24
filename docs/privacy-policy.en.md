# ISEKAI link Privacy Policy

Version: 2026-09-24

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

Two families of application, and the Identity API and relay (proxy) servers
they both connect to.

- **ISEKAI camera** — the camera application (camera-server), the desktop
  viewer (camera-client) and the iOS viewer.
- **ISEKAI portal** — the server that offers a service (portal-server) and the
  client that maps a local port onto it (portal-client), including the
  unattended uses of them: a CI job that enrols with a key, and an agent run
  authorised by an entitlement.

Where something below applies to only one of the two, it says so.

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
- a device name (`camera-server`, `camera-client`, `ios-camera-client`,
  `portal-server` or `portal-client` by default, or whatever you set)
- the times of registration and of each token issued

For portal, a device may instead be registered by an unattended job rather than
by a person at a keyboard. Where it is, we also receive:

- the record of which key admitted it, and the identity the job presented
  (for a job on a hosting service, the repository and branch it ran for)
- the label the job gave the registration, so that a run can be recognised
  later

### 3.3 Connections

When traffic passes through the relay, our servers handle:

- **IP addresses and port numbers.** To establish a direct path, the service
  observes the public address your device appears from and tells the other side
  what it is. This is inherent to how the connection is made.
- connection identifiers, listener identifiers, grants, pairing codes and
  tickets
- operational records such as connection start and end times and traffic volume

For portal we additionally hold, for an organization that uses one:

- which people may reach which class of service, and — where somebody has been
  admitted for a fixed term as a guest — the date that term ends
- where a public address has been allocated for a service, that address and the
  port

### 3.4 What you send through it

**Camera.** Video sent by the camera application passes through our relay on
its way to a viewer. It may show people, the inside of a home, or anything else
in view.

**Portal.** Whatever the service you forward speaks passes through our relay on
its way to the other side — a database session, a web request, a name lookup,
anything the operator of the server chose to offer. We do not know what any of
it is, and the list of services a portal-server offers stays on that machine
(section 8).

How we handle both is set out in section 5.

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

## 5. Video, and what you forward

**The key that encrypts your video is created on the device running the camera
application, and does not leave it.** What reaches us is a certificate signing
request — a public key and a name — and our servers return a certificate signed
against it. We do not hold the matching private key. Video passing through the
relay is therefore ciphertext whose content we cannot read.

We do, however, issue that certificate, and we control the name it is issued
for. In principle, then, we could obtain a second certificate for the same name
and place ourselves in the middle. To prevent that, the camera application signs
a statement, with the device's own key, saying which key it uses; the viewer
application refuses any connection that does not present that key. A certificate
we obtained separately does not allow the connection to be established at all.
The viewer also checks that the device answering is the one recorded when you
paired with it.

- We do not view or retain video beyond the purposes in this policy.
- We do not record or accumulate video. The relay forwards it and nothing more.
- We do not provide video to anyone other than the viewer you have authorised.
- **Once a direct path is established between camera and viewer, the video no
  longer passes through our relay.** Whether that path can be established
  depends on both networks.

Two things this does not change:

- **This section does not describe version 0.1.0 of the camera application.**
  In that version the private key for the video connection is issued by our
  servers and given to the application, and the application signs no statement
  about which key it uses, so the viewer validates only the name on the
  certificate. **In that case we remain technically capable of accessing the
  content of the video.**
- Separately from content, **when two devices communicated, which ones, and how
  much** is handled by our servers (sections 3.3 and 7).

### Portal

The connection a portal forward runs inside is the same one, made the same way
and with the same key arrangement, so **what passes through our relay is
ciphertext we cannot read**, and it stops passing through us once a direct path
is established. The four statements above — that we do not view, retain,
accumulate or hand on what is relayed — apply to it unchanged.

One thing is different, and it is the operator's to know rather than ours:
**the forward carries whatever the service speaks, and makes no promise about
it.** A service with no password of its own is reached by whoever you let in,
exactly as if it were exposed; the tunnel protects the transport and says
nothing about what is at the end of it.

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
| Video, and what a portal forwards | not retained — relayed only |
| Records of which unattended job registered which device | 3 years from collection |

## 8. What stays on your device

The following is stored on your device and not sent to us:

- the device's private key, a long-lived secret that must not be shared
- the private key used to encrypt the video connection, likewise
- the device identifier (Endpoint ID) of each camera or portal server you have
  paired with
- your Auth0 access and refresh tokens
- settings such as which servers to connect to
- your agreement to this policy, and which version of it you agreed to
- for portal: the list of services a portal-server offers and the addresses
  behind them, the policy a gateway is willing to apply, and any key or ticket
  you were given to let a job in

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
for your agreement again the next time they start. For the portal programs,
which have no window, that means printing the policy and refusing to run until
`--accept-privacy-policy` is passed again. We will give notice of significant
changes by other means as well.

## 13. Contact

SEERA Networks Corporation
info@seera-networks.com
