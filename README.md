# FIDO2 Security Key for Flipper Zero

A standalone Flipper Zero application that exposes the device as a USB FIDO2/U2F security key.
It implements the CTAP2 `hmac-secret` extension required by `systemd-cryptenroll`, allowing a
Flipper to unlock a LUKS2 volume while the application is running.

This repository contains only the application. It does not require or carry a firmware fork.
The current build target is [Momentum Firmware](https://github.com/Next-Flip/Momentum-Firmware)
mntm-012 (Flipper API 87.1).

## Features

- CTAPHID CBOR, MSG, cancellation, ping, lock, init, and wink handling
- `authenticatorGetInfo`
- ES256 `authenticatorMakeCredential` with self-contained credential IDs
- `authenticatorGetAssertion`, including pre-flight assertions
- PIN/UV protocol 1 key agreement for `hmac-secret`
- Compatibility with the stock U2F application's `/ext/u2f` device key and certificate data

The application intentionally advertises no resident-key, client-PIN, user-presence, or
user-verification support. It is designed for unattended, possession-based disk unlock. It emits
`none` attestation and is not a certified or tamper-resistant hardware authenticator.

## Build

Install [uFBT](https://github.com/flipperdevices/flipperzero-ufbt), download the SDK archive from
the [Momentum mntm-012 release](https://github.com/Next-Flip/Momentum-Firmware/releases/tag/mntm-012),
and point uFBT at that archive:

```sh
python3 -m pip install --upgrade ufbt
ufbt update --hw-target 7 --local=/path/to/flipper-z-f7-sdk-mntm-012.zip
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

GPL-3.0. The application is derived from the Flipper Zero firmware's U2F application and retains
the same license.
