# Dowe Pinless implementation roadmap

This is the project's living implementation checklist. It is deliberately split
between the **validation POC**, which is the currently supported scope, and any
future **Windows logon** design. Checking an item means its acceptance evidence
has been recorded in its pull request or issue; it does not by itself make the
product production-ready.

## How to use this roadmap

- Use GitHub task lists as the editable source of truth: change `- [ ]` to
  `- [x]` only after the listed acceptance criteria are met.
- Open one issue for each unchecked deliverable before implementation. Link the
  issue, branch, pull request, test evidence, VM/snapshot identifier (never
  secrets), and any follow-up work.
- Keep work small and reviewable. A task may be split into child issues when it
  touches more than one trust boundary.
- Do not test provider installation on a sole workstation. Every install or
  upgrade task requires a disposable x64 Windows VM, a snapshot, a separate
  tested administrator account, and a working password-based sign-in path.
- Never put TOTP seeds, recovery codes, DPAPI blobs, account names, raw pipe
  payloads, or VM credentials in issues, commits, CI output, or screenshots.

## Current baseline — complete POC capabilities

- [x] V2 Windows Credential Provider tile for logon and workstation unlock.
- [x] LocalSystem validator service with a versioned local named-pipe protocol.
- [x] RFC 6238 six-digit TOTP validation, bounded clock tolerance, and replay
  rejection.
- [x] CNG-generated seed protected with machine-scope DPAPI.
- [x] Ten salted-hash, single-use backup recovery codes.
- [x] Enrollment utility with local QR generation, optional Base32 display, and
  confirmation before replacing an existing enrollment.
- [x] Core primitive tests using public RFC 6238 vectors and malformed-input
  cases.
- [x] DDP2 authenticated enrollment-record envelope, migration, ACL verification,
  and tamper rejection.
- [x] Version-2 IPC caller-SID binding and account/SID consistency checks.
- [x] Explicit install/uninstall scripts that preserve built-in Windows sign-in
  providers.

Evidence: commits `c2f4b74` and `35f48e9`; VM snapshots recorded the DDP2 tamper
rejection, restored-record validation, mismatched-SID rejection, and valid-user
acceptance. No secret values were recorded.

## Milestone 1 — make the validation POC repeatable

- [ ] **Create a VM test matrix.** Cover supported Windows 10/11 x64 builds,
  local accounts, standard/admin users, clock drift, and upgrade/uninstall.
  Acceptance: a versioned matrix lists result, build, VM snapshot, and evidence
  location for every case.

Step 37 matrix prepared; results remain pending disposable-VM execution:

| Case | Result | Build/snapshot | Evidence |
| --- | --- | --- | --- |
| Windows 10 x64 | Pending | Pending | Pending |
| Windows 11 x64 | Pass | Windows 11 Home 25H2, build 26200.9168 | Disposable VM baseline, provider, service, lifecycle, and recovery checks |
| Local administrator | Pass | Win11 25H2 VM | `TESTMACHINE\mrjohndowe` confirmed in the local Administrators group |
| Standard local user | Pass | Win11 25H2 VM | `DowePinlessStandard` signed in successfully and returned to the administrator account; built-in recovery path remained available |
| TOTP clock drift within tolerance | Pass | Win11 25H2 clock-drift snapshot | Current TOTP accepted with the VM clock approximately 20 seconds ahead |
| Replay rejection | Pass | Win11 25H2 VM baseline | Fresh TOTP accepted once; immediate reuse rejected with result 2 |
| Enrollment replacement | Pass | Win11 25H2 pre-replacement snapshot | Explicit ENROLL consent, new authenticator confirmation, and recovery material generated; prior state remains rollback-capable |
| Service stop/start | Pass | Win11 25H2 VM | Service transitioned Running → Stopped → Running and retained Automatic startup |
| Install and uninstall | Pass | Win11 25H2 lifecycle snapshot | Uninstall preserved enrollment records; reinstall restored service/provider registration |
| Reboot recovery | Pass | Win11 25H2 VM | Password sign-in remained available and service returned Running/Automatic after reboot |
| Built-in PIN/password availability | Pass | Win11 25H2 VM baseline | Sign-in screen showed Password and built-in sign-in options; Dowe Pinless tile also visible |

The matrix intentionally does not authorize disabling built-in Windows PIN or
password providers.

Step 37A evidence: disposable VM baseline confirmed from the VM About screen as
Windows 11 Home Single Language, version 25H2, OS build 26200.9168, x64; the
local account and SID were recorded without secrets, and the Dowe Pinless
service was Running/Automatic. The earlier `Get-ComputerInfo` display was
inconsistent with the About screen and is not used as the release evidence.

Step 37B evidence: Windows sign-in screen showed the built-in Password provider,
sign-in options, and the Dowe Pinless tile. Sign-in completed through the
built-in recovery provider; no provider was disabled and no credentials were
recorded.

Step 37C evidence: the Dowe Pinless service transitioned from Running to
Stopped and back to Running while retaining Automatic startup. No built-in
Windows authentication provider was changed.

Step 37D evidence: after the service restart, the installed enrollment utility
accepted a current TOTP and reported successful validation. The code itself was
not recorded.

Step 37E evidence: a fresh TOTP was accepted once, then immediate reuse of the
same code was rejected with validation result 2. The code itself was not
recorded.

Step 37F evidence: a pre-replacement VirtualBox snapshot and independent
password/recovery paths were confirmed before changing enrollment state.

Step 37G evidence: local enrollment source review confirmed that the utility
uses `--verify` only for validation; any other invocation prompts for explicit
`ENROLL` consent and preserves the previous record if authenticator confirmation
fails.

Step 37H evidence: enrollment replacement completed after the protected VM
snapshot; the new authenticator was confirmed and replacement recovery
material was saved locally without recording secrets.

Step 37I evidence: the newly enrolled authenticator produced a TOTP accepted
by the validator. The entered code was not recorded.

Step 37J evidence: one newly generated recovery code was accepted once, then
immediate reuse was rejected with validation result 2. The recovery code was
not recorded.

Step 37K evidence: after a VM reboot, the built-in Password provider remained
available; the Dowe Pinless service returned as Running with Automatic startup.

Step 37L evidence: a pre-lifecycle VM snapshot and independent password,
administrator, authenticator, and recovery-code paths were confirmed before
testing uninstall behavior.

Step 37M attempt: the uninstall script completed and explicitly preserved
enrollment records; a restart and post-uninstall built-in Password sign-in
check passed, and the Dowe Pinless service was absent afterward.

Step 37N attempt: the first reinstall copy encountered an expected executable
file lock from the previous service instance; the immediate retry completed
successfully. Final checks confirmed Running/Automatic service state, provider
registration, InprocServer32 registration, and the expected installed DLL path.

Step 37O evidence: temporary local account `DowePinlessStandard` was created
and confirmed in the Users group, with no Administrators-group membership. The
standard-user sign-in/provider check then passed, with return to the tested
administrator account.

Step 37Q evidence: `TESTMACHINE\mrjohndowe` was confirmed as a local member of
the Administrators group; no provider settings were changed.

Step 37R evidence: a pre-clock-drift VM snapshot was created before changing
time-related state; the clock-drift test remains pending.

Step 37S evidence: current TOTP validation succeeded with the VM clock
approximately 20 seconds ahead, within the configured tolerance window.
- [x] **Automate the core test target in CI.** Build `Release|x64` and run
  `DowePinlessCoreTests` on a supported Windows runner. Acceptance: a pull
  request shows a passing required workflow and uploads no secrets or binaries
  containing secrets.

Evidence: hosted GitHub Actions workflow `Windows build and security tests`
passed on `windows-latest` after initializing the Visual Studio x64 build
environment; Release build, core tests, and artifact upload succeeded with no
secret values in the logs.
- [ ] **Document a reproducible developer build.** Pin the Visual Studio,
  MSVC, SDK, and build commands actually used. Acceptance: a clean Windows VM
  reproduces the build and core-test result.
- [ ] **Exercise installer lifecycle in a disposable VM.** Test install,
  enrollment, validation, service stop/start, uninstall, and reboot. Acceptance:
  built-in password sign-in remains available before and after every action.
- [x] **Add focused negative-path tests.** Include corrupted enrollment state,
  truncated pipe requests, invalid encodings, expired/replayed codes, and
  interrupted enrollment. Acceptance: each case fails closed and leaves the
  prior known-good enrollment usable.

Evidence: `DowePinlessCoreTests` passed corrupted/tampered and truncated DDP2
record rejection, known-good record preservation, interrupted temporary-write
handling, malformed input checks, replay protection, and mismatched-SID IPC
rejection on the elevated Win11 x64 VM. No secret values were recorded.

## Milestone 2 — harden the existing trust boundaries

- [x] **Audit and test caller identity binding.** Reconcile the documented
  design with the current implementation, including LogonUI, local users,
  administrators, domain accounts, and managed accounts. Acceptance: a caller
  cannot validate against another account's record; tests prove the cases.
- [x] **Harden enrollment-record storage.** Define authenticated record framing,
  durable atomic updates, ACL verification, corruption handling, and rollback
  detection. Acceptance: tamper, rollback, and interrupted-write tests fail
  closed without exposing secret material.

Evidence: version-2 IPC tests and DDP2 round-trip/tamper tests passed in
`DowePinlessCoreTests`; VM snapshots recorded both positive and negative paths.
Domain/managed-account coverage remains an explicit follow-up.

Step 36A evidence: `Release|x64` rebuilt successfully after separating the
service-dependent IPC test mode and adding the Windows CI workflow. The CI
workflow itself remains unchecked until a hosted workflow run completes.

Step 36B evidence: elevated `DowePinlessCoreTests` completed with
`DOWE_PINLESS_RUN_IPC_TEST=1`; core, DDP2 storage/tamper, and mismatched-SID
IPC regression checks passed locally with exit code 0. No secret values were
recorded.

Step 36D attempt: the first hosted workflow reached the Windows runner but
failed before compilation because `msbuild` was not initialized in the
PowerShell environment. The workflow now initializes the x64 Visual Studio
build environment before invoking MSBuild; hosted CI remains unchecked until
the corrected run completes.
- [x] **Define safe observability.** Add only redacted event categories, a
  retention policy, and tests that assert sensitive values never reach logs.
  Acceptance: automated redaction tests pass and documentation describes how to
  collect diagnostics safely.

Evidence: `docs/Observability.md` documents the allowlist, prohibited fields,
retention, and collection rules; `DowePinlessCoreTests` passed safe-event
serialization and rejection of representative secret-bearing events. No
operational event writer is enabled by default.
- [ ] **Threat-model the POC.** Document assets, attackers, trust boundaries,
  abuse cases, mitigations, and accepted risks. Acceptance: security review
  records owners and dispositions for all high-risk findings.

Step 40 evidence: `docs/ThreatModel.md` documents the POC assets, trust
boundaries, threats, mitigations, accepted risks, production release blockers,
and high-risk owner/disposition records. The threat-model checkbox remains open
until the listed open findings receive security-review disposition.
- [ ] **Fuzz untrusted parsers and IPC.** Target request decoding, record
  parsing, and enrollment input. Acceptance: corpus and sanitizer/crash results
  are retained without including credential material.

## Milestone 3 — operational safety and maintainability

- [ ] **Create a signed-build and artifact-verification plan.** Specify signing
  identity custody, timestamping, provenance, hashes, revocation, and who can
  publish. Acceptance: a test artifact verifies on a clean VM; private signing
  keys never enter the repository or CI logs.
- [ ] **Design secure upgrade and rollback.** Preserve valid enrollment safely,
  prevent downgrade attacks, and retain a tested recovery route. Acceptance:
  forward upgrade and rollback drills pass in a snapshot VM.
- [ ] **Complete usability coverage.** Test keyboard-only use, screen readers,
  high contrast, localization, error messages, and secure-desktop constraints.
  Acceptance: documented results and fixed blockers for every supported setup.
- [ ] **Write and drill break-glass operations.** Include Safe Mode/WinRE,
  service/provider removal, separate-admin recovery, and BitLocker recovery-key
  handling. Acceptance: an operator completes the drill from the documentation
  on a fresh VM snapshot.
- [ ] **Establish private security reporting.** Publish a security contact and
  disclosure process before inviting external testing. Acceptance: the process
  is tested without putting a vulnerability report in a public issue.

## Milestone 4 — decision gate for true Windows sign-in

- [ ] **Choose a supported authentication architecture.** A Credential Provider
  alone cannot turn a valid TOTP code into a Windows logon token. Evaluate a
  separately designed LSA authentication package or certificate/key-backed
  account integration. Acceptance: an approved architecture decision records
  threat model, recovery design, compatibility impact, and ownership.
- [ ] **Design emergency access before implementation.** Preserve a tested
  independent administrator, Windows Recovery Environment route, and offline
  recovery material. Acceptance: break-glass exercises work with the proposed
  architecture enabled.
- [ ] **Obtain independent security assessment approval.** Define scope,
  deliverables, remediation process, and release gate. Acceptance: critical and
  high findings are resolved or explicitly accepted by the accountable owner.
- [ ] **Authorize production readiness.** This requires all earlier milestones,
  signed-release verification, penetration-test outcomes, and operational-owner
  sign-off. Acceptance: a documented go/no-go decision—never inferred from a
  collection of checked boxes.

## Interactive Git workflow for every roadmap item

Use this check-off sequence in the corresponding issue or pull request:

- [ ] Issue names one roadmap item, owner, scope, and acceptance criteria.
- [ ] Branch is created from current `main` using `codex/<issue>-<short-name>`.
- [ ] Implementation is limited to the issue; sensitive material is excluded.
- [ ] Focused tests/build and any required disposable-VM checks are recorded.
- [ ] Documentation, test matrix, and this roadmap status are updated when the
  behavior or milestone status changes.
- [ ] A reviewer verifies security impact, recovery behavior, and that built-in
  sign-in remains available.
- [ ] Pull request is merged only after review and required checks pass.
- [ ] Issue is closed and the roadmap checkbox is marked complete with a link to
  the merged pull request.

### Suggested issue labels

`roadmap`, `security`, `credential-provider`, `service`, `enrollment`, `tests`,
`documentation`, `vm-validation`, `release`, and `decision-required`.

## First work queue

Start with these in order; they have the highest value before expanding the
feature set:

1. Create the VM test matrix and baseline evidence.
2. Run and require the new Windows CI workflow for the core test target.
3. Expand caller identity coverage to domain and managed accounts.
4. Add corrupted/truncated-record and interrupted-write regression cases.
5. Write the POC threat model and safe logging specification.

Step 38 evidence: storage regression coverage for truncated records and
interrupted temporary writes passed in the rebuilt Release|x64 test target.

Step 39 evidence: `docs/Observability.md` and the common observability
serializer define and enforce the redaction boundary; the Release|x64 test
target passed the automated sensitive-field rejection checks.

## Status update rule

When work is completed, update the relevant checkbox and add one short
evidence line under it in the same pull request, for example:

> Evidence: PR #123, `DowePinlessCoreTests` passed on Windows x64; VM test
> `win11-23h2-snapshot-04` confirmed password-provider recovery remained
> available. No secret values were recorded.

