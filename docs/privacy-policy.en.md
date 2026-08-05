# ISEKAI link Privacy Policy

Version: 2026-08-05

> **Note — remove before publishing.**
> This was drafted from what the ISEKAI link client code actually sends and
> stores, and has **not been reviewed by a lawyer**. The `{{...}}` fields can
> only be filled in by the operator. Have it reviewed against the applicable
> data-protection law before publishing.

## 1. Who we are

| | |
| --- | --- |
| Operator | {{legal entity}} |
| Address | {{address}} |
| Data protection contact | {{role or team}} |
| Contact | {{email}} |

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

## 6. Sharing and processors

- **Auth0 (Okta, Inc.)** provides authentication and handles the information in
  section 3.1.
- Otherwise we do not disclose personal information to third parties without
  your consent, except where the law requires it.
- {{state any international transfer, the destination and its legal basis}}

## 7. How long we keep it

| | |
| --- | --- |
| Account information | until you close your account |
| Device registrations | until you remove the device |
| Connection logs | {{retention period}} |
| Video | not retained — relayed only |

## 8. What stays on your device

The following is stored on your device and not sent to us:

- the device's private key, a long-lived secret that must not be shared
- your Auth0 access and refresh tokens
- settings such as which servers to connect to

Signing out of an application deletes the Auth0 tokens from that device.

## 9. Your rights

You may ask us to disclose, correct, add to, delete, or stop using or sharing
the personal information we hold about you. Contact us at the address in
section 1.

## 10. Security

- Traffic between your device and our servers is encrypted with TLS.
- Device private keys and authentication tokens are stored readable only by
  their owner.
- {{describe organisational and personnel safeguards}}

## 11. Children

{{state the age limit and any parental-consent requirement}}

## 12. Changes

If we change this policy we will update its version, and applications will ask
for your agreement again the next time they start. We will give notice of
significant changes by other means as well.

## 13. Contact

{{email}}
