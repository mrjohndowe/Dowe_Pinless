# Dowe Pinless break-glass recovery

This procedure applies to the validation POC and must be tested on a
disposable VM before any production-like deployment. Built-in Windows password
and PIN providers remain enabled throughout the POC.

## Required recovery paths

Maintain all of the following before installation or upgrade:

1. A separate tested local or domain administrator account with a known
   password-based sign-in path.
2. A current Windows Recovery Environment/Safe Mode path and a tested VM
   snapshot or equivalent rollback point.
3. Protected enrollment recovery material, including unused one-time recovery
   codes stored outside the VM sign-in session.
4. BitLocker recovery material where disk encryption is enabled.

Never store recovery passwords, codes, seeds, or keys in this document, source
control, screenshots, logs, or CI output.

## If validation or LogonUI is unavailable

1. Select the built-in Password provider at the Windows sign-in screen.
2. Sign in using the tested recovery administrator account.
3. Stop the Dowe Pinless service from an elevated console if necessary.
4. Run the documented uninstall script. It preserves enrollment records by
   default; do not pass `-RemoveEnrollmentData` unless permanent deletion is
   explicitly approved and the recovery path is already verified.
5. Restart Windows so LogonUI unloads the provider DLL.
6. Confirm password sign-in still works and record only non-sensitive results.

## Safe Mode/WinRE route

If normal sign-in or service control is unavailable, use the VM snapshot or
Windows Recovery Environment to restore a known-good state. Preserve the
separate administrator and BitLocker recovery paths. Do not delete enrollment
records while diagnosing a provider failure.

## Gate for any future PIN-disabling option

PIN disabling is not implemented or authorized by this POC. A future explicit
configuration option may only be considered after an approved Windows logon
architecture, independent administrator recovery, tested Safe Mode/WinRE
rollback, signed artifacts, domain/managed-account coverage, and independent
security review. The installer must default to preserving built-in providers
and must provide a tested rollback that restores them.
