# Dowe Pinless secure upgrade and rollback design

This design applies to the validation POC and preserves built-in Windows
Password and PIN providers during every operation.

## Forward upgrade

1. Verify the package signature, provenance, architecture, and expected
   publisher before changing files or services.
2. Check that the installed version is not newer than the package unless an
   explicit, reviewed downgrade procedure is being used.
3. Stop the service in a controlled manner and preserve the enrollment record
   before replacing binaries.
4. Install files to a staging location, verify hashes, apply protected ACLs,
   then atomically replace the active files.
5. Register the service/provider and start the service only after verification.
6. Run health checks without disabling built-in providers.

## Enrollment preservation

Enrollment records must remain protected and usable across a compatible
upgrade. A failed upgrade must not replace the last known-good record with an
empty, truncated, unsigned, or downgraded record. Enrollment replacement stays
an explicit, separately confirmed operation.

## Rollback triggers

Rollback is required for signature failure, hash/provenance mismatch, service
start failure, provider registration failure, record-integrity failure, failed
health checks, or loss of the tested password recovery path.

## Rollback procedure

1. Stop the new service and restore the previous signed binaries and registry
   state from the staged backup.
2. Restore the last known-good enrollment record only after its authenticated
   envelope and ACL verify.
3. Start the previous service and verify its status and provider registration.
4. Confirm built-in Password/PIN sign-in and the independent administrator
   path.
5. Restart Windows if necessary to unload the replaced provider DLL.
6. Record only version, result, and non-secret diagnostic detail.

## Downgrade protection

The installer must reject an older package by default when the installed
version is newer. Any reviewed downgrade must preserve authenticated record
framing, prevent replay-state rollback, and require a tested recovery path.

## Acceptance drill

Before production readiness, perform a forward upgrade and a forced rollback on
a disposable Windows 10/11 x64 VM. Confirm service/provider recovery, record
integrity, password/PIN availability, reboot behavior, and no secret-bearing
logs. Keep the rollback snapshot until the drill is accepted.
