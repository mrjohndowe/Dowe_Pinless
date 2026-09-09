# Dowe Pinless validation POC threat model

This document covers the current validation POC. It does not approve replacing
Windows logon providers or disabling PIN/password sign-in.

## Assets

- DPAPI-protected TOTP seed and enrollment metadata.
- Salted hashes and one-use state for recovery codes.
- Replay counter, failure counters, and lockout state.
- LocalSystem validator service and its caller-identity decisions.
- Independent Windows password/PIN and recovery-administrator paths.

## Trust boundaries

1. **LogonUI / Credential Provider → named pipe:** untrusted caller input;
   requests require versioned framing, pipe ACLs, impersonation, and SID/account
   consistency checks.
2. **Enrollment utility → protected records:** elevated enrollment writes
   authenticated DPAPI envelopes with protected ACLs and atomic replacement.
3. **Record store → validator:** corrupted, truncated, tampered, rolled-back,
   or interrupted writes must fail closed without replacing the last good record.
4. **Authenticator/time source → validator:** codes are six-digit RFC 6238
   SHA-1 values with 30-second periods, bounded tolerance, and replay checks.
5. **POC validation → Windows logon:** the provider does not create an LSA logon
   token; built-in providers remain the recovery path.

## Threats and mitigations

| Threat | Mitigation | Residual risk / follow-up |
| --- | --- | --- |
| Replay of a valid TOTP | Accepted-counter tracking and one-use recovery state | Durable rollback protection needs further operational testing |
| Tampered or truncated record | DDP2 authenticated envelope and fail-closed parser | Fuzzing and crash-injection remain open |
| Unauthorized record access | DPAPI machine protection and SYSTEM/Administrators ACL | Local administrators remain highly trusted |
| Pipe spoofing or cross-account validation | Named-pipe ACL, impersonation, caller SID, and account/SID match | Domain/managed-account coverage remains open |
| Brute-force validation | Failure counters and lockout state | Rate-limit policy and alerting need production design |
| Clock drift | ±1 time-step tolerance and VM drift test | Time-change monitoring and policy remain open |
| Recovery-code theft | Salted hashes and single-use consumption | Offline recovery-material handling remains operational risk |
| Enrollment replacement abuse | Explicit consent and prior-state preservation until confirmation | Separate-admin approval workflow is required before production |
| Logging leakage | Allowlisted serializer and redaction tests | Event-log writer is not enabled in the POC |
| Credential-provider removal or crash | Additive installer and tested uninstall/recovery path | Secure upgrade and signed deployment remain open |
| POC mistaken for Windows logon | Documentation and built-in providers retained | A real LSA/certificate architecture is required for TOTP-only logon |

## Accepted POC risks

- The current provider validates a second factor but does not complete Windows
  sign-in itself.
- Local administrators and the host OS can ultimately control the machine and
  may access or replace protected state.
- The POC is not a signed production release and has no independent security
  assessment.

## Release blockers

Do not disable built-in PIN/password providers until an approved logon
architecture, independent recovery administrator, break-glass procedure,
signed artifacts, domain/managed-account coverage, fuzzing, and independent
security review are complete.

## High-risk review dispositions

| Finding | Owner role | Disposition |
| --- | --- | --- |
| Credential Provider cannot create a Windows logon token | Authentication architect | Open: choose and approve an LSA or certificate/key-backed architecture |
| Disabling built-in providers could strand the machine | Operations/recovery owner | Open: drill break-glass recovery and retain an independent administrator |
| Local administrators can control protected machine state | Security reviewer | Accepted for POC; production requires independent review and signed deployment |
| Domain and managed-account identity coverage is incomplete | Identity/test owner | Open: add representative VM/domain coverage |
| Unfuzzed parsers and unreviewed production event writer | Security/test owner | Open: fuzz, add redaction tests for final writer, and retain crash evidence |
