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
- [ ] **Automate the core test target in CI.** Build `Release|x64` and run
  `DowePinlessCoreTests` on a supported Windows runner. Acceptance: a pull
  request shows a passing required workflow and uploads no secrets or binaries
  containing secrets.
- [ ] **Document a reproducible developer build.** Pin the Visual Studio,
  MSVC, SDK, and build commands actually used. Acceptance: a clean Windows VM
  reproduces the build and core-test result.
- [ ] **Exercise installer lifecycle in a disposable VM.** Test install,
  enrollment, validation, service stop/start, uninstall, and reboot. Acceptance:
  built-in password sign-in remains available before and after every action.
- [ ] **Add focused negative-path tests.** Include corrupted enrollment state,
  truncated pipe requests, invalid encodings, expired/replayed codes, and
  interrupted enrollment. Acceptance: each case fails closed and leaves the
  prior known-good enrollment usable.

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
- [ ] **Define safe observability.** Add only redacted event categories, a
  retention policy, and tests that assert sensitive values never reach logs.
  Acceptance: automated redaction tests pass and documentation describes how to
  collect diagnostics safely.
- [ ] **Threat-model the POC.** Document assets, attackers, trust boundaries,
  abuse cases, mitigations, and accepted risks. Acceptance: security review
  records owners and dispositions for all high-risk findings.
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

## Status update rule

When work is completed, update the relevant checkbox and add one short
evidence line under it in the same pull request, for example:

> Evidence: PR #123, `DowePinlessCoreTests` passed on Windows x64; VM test
> `win11-23h2-snapshot-04` confirmed password-provider recovery remained
> available. No secret values were recorded.

