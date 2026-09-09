# Dowe Pinless build-to-release workflow

The `Release successful Windows build` workflow listens for completion of the
`Windows build and security tests` workflow. It runs only when that workflow
finishes successfully for `main`.

The release job downloads the exact `dowe-pinless-release-x64` artifact from
the completed build run, packages it as `DowePinless-Release-x64.zip`, and
creates a GitHub release tagged `build-<workflow-run-number>` at the tested
commit. A failed or pull-request build cannot create a release.

Before packaging, the job verifies that the service, enrollment utility, and
Credential Provider DLL are present and rejects secret-like filenames. Missing
or forbidden files fail the job before release creation. The check deliberately
does not reject the substring `pin`, because it is part of the product name
`DowePinless`; PIN values are prohibited by content policy, not by a product
filename substring.

The release also includes `SHA256SUMS.txt`, containing the ZIP's SHA-256 hash,
the originating workflow run number, and the tested commit SHA. The manifest
is generated after packaging and contains no credentials or enrollment data.

The workflow uses the repository-provided GitHub token for artifact download
and release creation. It does not sign binaries and does not contain private
signing keys; signing remains governed by `docs/SignedArtifacts.md`.
