# Changelog

All notable changes to Dowe Pinless will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0](https://github.com/mrjohndowe/Dowe_Pinless/compare/v1.0.0...v1.1.0) (2026-08-30)


### Features

* add maintainer agent instructions and update VSCode extensions recommendations ([2e5f065](https://github.com/mrjohndowe/Dowe_Pinless/commit/2e5f0655db977ad12d987646eb86bab4867cff28))

## 1.0.0 (2026-08-24)


### Features

* add Dowe Pinless credential provider proof of concept ([56d9ae8](https://github.com/mrjohndowe/Dowe_Pinless/commit/56d9ae829b8b62effe1fe105f35c1c50ce3d7efd))
* add VSCode extensions recommendations file ([e236ec2](https://github.com/mrjohndowe/Dowe_Pinless/commit/e236ec24203ce1261e80b7c4212bfd9fb35f19df))


### Bug Fixes

* accept bounded IPC strings in debug builds ([1ab919d](https://github.com/mrjohndowe/Dowe_Pinless/commit/1ab919d7e7fbc4d519028f1fc6ba92dd6f4952b0))
* update submodule URL and add missing extension recommendation ([4366d66](https://github.com/mrjohndowe/Dowe_Pinless/commit/4366d6679ded770d04a8a1857d8e3f35a8de7cb3))

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
- Local console QR-code enrollment with an explicit manual Base32 secret-key option.
- Authenticator confirmation before replacing an existing enrollment or recovery-code set.
- A pinned, provenance-documented copy of Project Nayuki's MIT-licensed C++ QR encoder.

### Security

- Documented secure-storage, replay-protection, recovery-code, and testing expectations.
- Added constant-time comparisons, ±1-step clock tolerance, replay rejection, bounded IPC,
  and persisted failed-attempt delays.
- Kept all built-in Windows credential providers enabled in the proof of concept.
- Made every IPC request field explicitly initialized and added non-sensitive malformed-request
  diagnostics without exposing account secrets or authentication codes.

### Fixed

- Allowed the validator service to finish a pending stop by waking its blocked named-pipe listener.
- Accepted bounded null-terminated IPC strings when the Debug CRT fills unused buffer elements
  with its nonzero diagnostic pattern.

<!-- release-please inserts new release sections above this line -->

[Unreleased]: https://github.com/mrjohndowe/Dowe_Pinless/compare/HEAD...HEAD
