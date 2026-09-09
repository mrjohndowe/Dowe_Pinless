# Dowe Pinless signed-build and artifact-verification plan

This plan applies before any production-like distribution. The current POC
builds are not represented as signed production releases.

## Signing identity and custody

- Use a dedicated code-signing certificate held by the accountable release
  owner or an approved signing service.
- Keep private keys in hardware-backed or policy-controlled storage; never put
  them in the repository, source archive, developer workstation checkout, or
  CI logs.
- Require two-person approval for certificate issuance, key rotation, and
  release signing.
- Record certificate thumbprint, validity, issuer, and revocation status in the
  private release record, not in credential-bearing logs.

## Build provenance

Each release candidate must record the source commit, branch, toolchain/SDK
versions, target architecture, reproducible build inputs, dependency versions,
and generated artifact SHA-256 hashes. The provenance record must not contain
TOTP seeds, recovery codes, DPAPI blobs, VM credentials, or private keys.

## Signing and timestamping

Sign the DLLs, service, enrollment utility, installer, and any packaged
metadata after the reproducible build completes. Use a trusted timestamp so
signatures remain verifiable after certificate expiration. Reject unsigned or
unexpectedly signed files during release review.

## CI boundary

CI may build and test unsigned artifacts. Signing must run only in a protected
release environment with short-lived authorization, least-privilege access,
audited approvals, and secret masking. A failed signing step must not publish a
partially signed package.

## Clean-VM verification

On a disposable Windows 10/11 x64 VM, verify certificate chain, signature
validity, timestamp, expected publisher identity, artifact hashes, installer
behavior, service/provider registration, uninstall rollback, and built-in
Password/PIN recovery. Keep a separate administrator and snapshot. Do not
disable built-in providers as part of signature verification.

## Revocation and compromise response

If a signing key or certificate is suspected compromised, stop publication,
revoke or quarantine the identity, identify affected hashes and versions,
publish a signed replacement through a new identity, and document rollback and
customer notification decisions. Never reuse a compromised key merely to
repair an old package.

## Release gate

No production-ready claim is allowed until an artifact verifies on a clean VM,
the provenance record is complete, private signing material is absent from the
repository and CI logs, and an accountable reviewer signs off.
