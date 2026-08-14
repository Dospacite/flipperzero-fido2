# FIDO2 Security Key for Flipper Zero

A standalone Flipper Zero application that exposes the device as a USB FIDO2/U2F security key.
It supports ordinary WebAuthn registrations and assertions with an explicit Flipper OK-button
confirmation, as well as the CTAP2 `hmac-secret` extension required by `systemd-cryptenroll`.
The latter can unlock a LUKS2 volume while the application is running.

This repository contains only the application. It does not require or carry a firmware fork.
It builds against official Flipper Zero firmware 1.4.3 (Flipper API 87.1); its FIDO transport,
PIN storage, and cryptography use public Flipper SDK APIs.

## Features

- CTAPHID CBOR, MSG, cancellation, ping, lock, init, and wink handling
- `authenticatorGetInfo`
- ES256 `authenticatorMakeCredential` with self-contained credential IDs
- `authenticatorGetAssertion`, including pre-flight assertions
- WebAuthn user presence: press the Flipper's OK button to register or authenticate
- CTAP2 client-PIN protocol 1 for browser-mediated user verification, with the PIN hash and
  retry count encrypted using the Flipper's device-unique key
- PIN/UV protocol 1 key agreement for `hmac-secret`
- Compatibility with the stock U2F application's `/ext/u2f` device key and certificate data

The application supports up to eight persistent resident credentials and browser-mediated
user verification through a client PIN. It emits `none` attestation and is not a certified or
tamper-resistant hardware authenticator.

## Interface assets

The app bundles the U2F screen artwork from the official Flipper Zero 1.4.3 source release in its
own `images/` asset bundle. This preserves the familiar U2F interface while keeping the FAP
independent of firmware-global icon symbols, so it continues to build and run on official firmware.

## Firmware support and migration

Momentum is not required. The app was built, installed, and exercised as a FIDO2 security key on
official firmware 1.4.3. Future firmware releases may change the external-app API, so always build
with an SDK matching the firmware release installed on the Flipper.

The FIDO device key, counter, resident credentials, and PIN state are kept in `/ext/u2f` on the SD
card. A normal firmware update and `ufbt launch` do not erase that directory. Do not delete it: if
it is retained while moving from a firmware-integrated U2F app or Momentum, existing credentials
remain usable and do not need to be re-enrolled.

## Build

Install [uFBT](https://github.com/flipperdevices/flipperzero-ufbt), then download the official
release SDK and build:

```sh
python3 -m pip install --upgrade ufbt
ufbt update --channel release
ufbt
```

The resulting application is `dist/fido2_security_key.fap`.

To upload and start it on an attached Flipper:

```sh
ufbt launch
```

The application must remain open for the host to discover and use the security key.

## LUKS enrollment

Back up the LUKS2 header before enrolling any new unlock method. With the application running and
the Flipper connected over USB:

```sh
sudo systemd-cryptenroll --fido2-device=auto /dev/your-luks-device
```

For an unattended key, select no PIN, user presence, or user verification when prompted. Those
choices make possession of the running Flipper sufficient to unlock the volume, so retain a strong
recovery passphrase and protect the device accordingly.

## Design

Credentials are derived from the existing device-unique U2F master key and relying-party ID. Each
64-byte credential ID contains a random nonce and an authenticated tag, so no per-credential
database is required. The `hmac-secret` exchange uses P-256 ECDH, SHA-256, HMAC-SHA256, and
AES-256-CBC as specified by CTAP2 PIN/UV protocol 1.

The app deliberately keeps using `/ext/u2f` so credentials created by an earlier firmware-integrated
build remain valid. Firmware updates and app reinstalls must not delete that directory.

## License

GPL-3.0. The application is derived from the Flipper Zero firmware's U2F application, including
the bundled U2F interface assets, and retains the same license.
