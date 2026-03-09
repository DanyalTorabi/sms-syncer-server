# Android Certificate Pinning Runbook

This runbook defines how server maintainers provide certificate pin data to Android for `CertificatePinner`.

## Scope

- Source issue: [#130](https://github.com/DanyalTorabi/sms-syncer-server/issues/130)
- Android dependency: [DanyalTorabi/SmsLogger#56](https://github.com/DanyalTorabi/SmsLogger/issues/56)
- Pin bundle source of truth: [android-pin-bundle.json](./android-pin-bundle.json)

## Required Outputs

1. Environment-specific API hostname list (staging/production and any additional public hosts)
2. SPKI pin values in OkHttp format: `sha256/<base64-hash>`
3. Two pins per host:
   - `current`: currently deployed serving key
   - `backup`: next key available for rotation
4. Rotation and rollback steps with owner responsibilities

## Interactive Update Script

Step 1: Generate local SPKI/date artifacts from live endpoints:

```bash
make generate-android-pin-artifacts
```

This creates local files under `.artifacts/android-pin-inputs/` (gitignored), including:

- `.artifacts/android-pin-inputs/staging.json`
- `.artifacts/android-pin-inputs/production.json`

Step 2: Fill/update the pin bundle interactively:

```bash
make update-android-pin-bundle
```

The update command auto-loads generated defaults (hostname, current pin, validity dates) from those artifact files.

or run it directly:

```bash
./scripts/update-android-pin-bundle.sh
```

The script prompts for:

- owner and rotation notice lead time
- staging and production hostnames
- edge TLS termination mode
- current and backup SPKI pins
- validity window (`notBefore`, `notAfter`)

## Extract SPKI Pin from PEM Certificate

```bash
openssl x509 -in /path/to/cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

Output value should be recorded as:

```text
sha256/<output-from-command>
```

## Extract SPKI Pin from Live Endpoint

```bash
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

Use this to verify the live edge certificate matches documented pin values.

## Rotation Workflow

1. Generate/provision next certificate key pair and ensure backup pin is ready.
2. Update `backup` pin in [android-pin-bundle.json](./android-pin-bundle.json) before deployment.
3. Notify Android maintainers at least 14 days before cutover.
4. Deploy new certificate.
5. Verify live SPKI hash matches expected `current` after cutover.
6. Promote previous backup to `current`, then register a new `backup`.

## Rollback Workflow

1. Roll back certificate at edge (or native TLS) to last known good key.
2. Re-verify live SPKI hash.
3. Confirm Android can connect without pinning failures.
4. Open follow-up incident and update pin bundle timeline notes.

## Operational Notes

- Pin the certificate presented to Android clients at the network edge.
- If TLS terminates at a reverse proxy/CDN, pin proxy/CDN serving cert public key.
- Do not remove old pins in the same release where a key rotation happens.
- Keep this runbook and bundle updated in the same PR whenever cert/pin data changes.
