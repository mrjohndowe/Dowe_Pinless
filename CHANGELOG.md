# Changelog

All notable changes to Dowe Pinless will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project documentation.
- Security guidance for TOTP authentication and backup recovery codes.
- GitHub-ready changelog and wiki documentation workflows.
- Visual Studio C++17 solution with a shared security and IPC library.
- Windows 10/11 V2 Dowe Pinless Credential Provider validation tile.
- LocalSystem service for TOTP and single-use recovery-code validation.
- DPAPI-protected enrollment with ten hashed backup recovery codes.
- Explicit install, uninstall, validation, and break-glass recovery documentation.
- Visual Studio 18/MSVC v145 project targeting for the current Windows development toolchain.

### Security

- Documented secure-storage, replay-protection, recovery-code, and testing expectations.
- Added constant-time comparisons, ±1-step clock tolerance, replay rejection, bounded IPC,
  and persisted failed-attempt delays.
- Kept all built-in Windows credential providers enabled in the proof of concept.

<!-- release-please inserts new release sections above this line -->

[Unreleased]: https://github.com/mrjohndowe/Dowe_Pinless/compare/HEAD...HEAD
