# Supply Chain Verification

Use this guide to verify official release assets before execution.

## What to Download

From a tagged release, download:

- `dpuin-linux.zip`, `dpuin-macos.zip`, `dpuin-windows.zip`
- `SHA256SUMS`
- `SHA256SUMS.sig`, `SHA256SUMS.pem`
- `<artifact>.sig`, `<artifact>.pem` for each zip

## 1) Verify checksums

```bash
sha256sum -c SHA256SUMS
```

All files must report `OK`.

## 2) Verify Sigstore keyless signatures (manual)

Install `cosign`, then verify each file. Example for Linux zip:

```bash
cosign verify-blob \
  --certificate dpuin-linux.zip.pem \
  --signature dpuin-linux.zip.sig \
  --certificate-identity-regexp "https://github.com/herb318/autonomous-ai-reward-network/.github/workflows/cross-platform-release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  dpuin-linux.zip
```

Also verify `SHA256SUMS` itself:

```bash
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp "https://github.com/herb318/autonomous-ai-reward-network/.github/workflows/cross-platform-release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

## 3) Verify with the project helper script

```bash
python3 scripts/verify_release_artifacts.py --assets-dir <download-dir> --require-cosign
```

Expected behavior:

- exit code `0`: checksum/signature validation passed
- exit code `1`: checksum/signature validation failed
