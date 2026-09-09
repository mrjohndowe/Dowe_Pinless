# Dowe Pinless usability and secure-desktop coverage

This checklist applies to the validation POC on the Windows secure desktop.
It does not authorize disabling built-in Windows Password or PIN providers.

## Keyboard-only use

- Reach the Dowe Pinless tile, code field, submit action, and error state with
  keyboard navigation only.
- Confirm focus order is deterministic and the code field does not expose the
  entered value in labels, clipboard prompts, or diagnostics.
- Confirm Escape, sign-out, and provider switching leave no retained code.

## Screen readers and high contrast

- Verify tile name, field label, submit action, and validation outcome are
  announced by the supported Windows screen reader.
- Verify high-contrast themes preserve focus indicators and readable text.
- Verify the custom tile bitmap remains distinguishable without relying on
  color alone.

## Localization and messages

- Keep user-facing messages free of secrets, account identifiers, raw HRESULTs,
  and pipe payloads.
- Review translated strings for code-entry instructions, failure, lockout,
  recovery, and provider-switch messages.
- Keep diagnostic detail in redacted numeric categories only.

## Secure desktop behavior

- Test tile enumeration and keyboard focus on the Windows logon/unlock desktop,
  not only in an ordinary desktop process.
- Confirm provider switching, sign-out, lock, unlock, and cancellation clear
  transient code state.
- Confirm built-in Password/PIN providers remain visible and usable.

## Acceptance record

Record Windows edition/build, accessibility settings, provider result, snapshot,
and non-sensitive observations for every supported setup. Any issue affecting
recovery, focus, announcement, localization, or secret exposure blocks a
production-readiness claim until fixed or explicitly accepted by the security
and operations owners.
