# Dowe Pinless proof-of-concept architecture

## Security boundary

The V2 Credential Provider DLL runs in LogonUI and owns only presentation and short-lived
user input. It sends a fixed-size versioned request to a local named pipe. The LocalSystem
service loads the account record, asks DPAPI to decrypt the TOTP seed, validates the input,
updates replay/recovery state atomically, and returns only a result enum. No component logs
seeds, TOTP values, recovery codes, DPAPI blobs, or full IPC payloads.

The pipe rejects remote clients and its ACL grants access only to SYSTEM, Administrators,
and authenticated local users. This POC still needs client-token validation and per-account
authorization before production use; otherwise a local authenticated user can submit bounded
validation attempts for another enrolled account. Rate limiting is persisted per account:
five failures cause a 30-second delay.

## Cryptography and state

- RFC 6238 compatibility profile: HMAC-SHA-1, six digits, 30-second period.
- Current time-step plus one step before/after is accepted.
- Numeric digits and recovery hashes are compared in constant time.
- The greatest accepted TOTP counter is persisted; the same or an older counter cannot be
  accepted again, including codes admitted through the drift window.
- A 160-bit random seed is protected with machine-scope DPAPI.
- Ten recovery codes use an unambiguous 32-character alphabet. Only SHA-256 hashes over a
  random per-enrollment salt and normalized code are stored. A successful use marks the code
  consumed before success is returned.
- Record replacement uses a write-through rename. Production should add authenticated record
  framing, stricter ACL creation, rollback resistance, and a transactional store.

## Critical Windows limitation

A Credential Provider is not an authentication package. It gathers and serializes credentials
for Windows; a valid TOTP does not yield the user's password, Windows Hello private key, or an
LSA logon token. Consequently this safe POC validates the second factor and displays success,
then asks the user to finish sign-in with a built-in provider. It deliberately does not cache a
Windows password or pretend that validation completed an interactive logon.

True TOTP-only Windows logon requires a separately designed trust mechanism, such as a custom
LSA authentication package or certificate/key-backed account integration. That expands the
trusted computing base substantially and requires code signing, secure update/recovery design,
penetration testing, and enterprise deployment controls.

## Later provider filtering (not implemented)

Only after enrollment and repeated validation have succeeded should an administrator be offered
an explicit provider-filter option. It must be reversible offline and must never remove all of:

1. a known-good password provider,
2. a separate recovery administrator account, and
3. Windows Recovery Environment access with the applicable disk-recovery key.

Dowe Pinless currently ships no `ICredentialProviderFilter`, no registry policy that hides
Microsoft providers, and no command that changes PIN/password availability.
