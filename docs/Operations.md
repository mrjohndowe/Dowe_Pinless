# Building and operating Dowe Pinless

## Prerequisites

- Disposable Windows 10/11 x64 VM with a snapshot.
- Visual Studio 18 with **Desktop development with C++**, MSVC v145, and a Windows 10/11 SDK.
- A separate local administrator account with a tested password.
- If BitLocker is enabled, a verified recovery key stored outside the VM.

Build `DowePinless.sln` in `Release|x64`. Run `Install-DowePinless.ps1` elevated and point
`-BuildDirectory` at the folder containing the three binaries. The script installs the local
service and registers only the Dowe Pinless provider CLSID. It does not filter other providers.

## Enrollment and validation

Run `DowePinlessEnroll.exe` from an elevated interactive console. Enrollment is intentionally
explicit and offers three setup choices: a locally rendered QR code, the Base32 secret key for
manual entry, or both. The QR encoder runs inside the enrollment process; it does not contact a
website, save an image, or send the seed over the network.

After adding the entry to an authenticator, enter its current six-digit value when prompted.
Dowe Pinless validates that value against the newly generated seed before it writes anything to
the enrollment store. Three failed confirmation attempts cancel the operation and leave the
previous seed and recovery-code set unchanged. Only after confirmation succeeds are ten new
recovery codes generated and the previous enrollment atomically replaced.

Store all ten recovery codes offline. Run `DowePinlessEnroll.exe --verify` with two consecutive
TOTP values. A repeated value should fail with replay status. Test one recovery code and verify
that attempting to reuse it fails.

## Recovery and removal

If validation is unavailable, select the normal Windows password/PIN tile. From an elevated
session, stop the service or run `Uninstall-DowePinless.ps1`. Enrollment data is preserved by
default; `-RemoveEnrollmentData` permanently deletes it. Restart after uninstall so LogonUI
unloads the DLL.

If LogonUI becomes unstable, boot Safe Mode or Windows Recovery Environment, use the separate
administrator/recovery path, and remove the provider registration for CLSID
`{852F9C7D-92B2-4F93-9CCB-1B707841D702}`. Do not test first on a sole physical workstation.

## Logging policy

The POC emits no operational event log entries yet. Production logging should record only event
type, timestamp, coarse result, provider version, and a non-reversible account correlation ID.
It must never record a secret, TOTP/recovery code, DPAPI blob, QR URI, or raw IPC message.

## Production exit criteria

Before treating Dowe Pinless as a security product: add signed binaries/installers; strict file,
registry, and pipe ACL tests; named-pipe client impersonation and identity binding; event logging
with redaction tests; tamper/rollback protection; time-change handling; domain/Azure AD testing;
secure upgrades; accessibility/localization; fuzzing; external security review; and a documented,
drilled break-glass recovery procedure.
