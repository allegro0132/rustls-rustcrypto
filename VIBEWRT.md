Based on rustls-rustcrypto 0.1.0-pre.0 at upstream commit 0494647098b7106a67dc5c44e3df83e5be23660c; imported by VibeWrt as a pinned Git submodule. Original MIT/Apache-2.0 licenses retained.

Local changes: optional GO_ALGORITHMS profile in src/verify.rs, real P-521/SHA-256/384/512 and P-256/P-384 SHA-512 verifiers in src/verify/ecdsa.rs, p521 dependency, and public profile export. The default provider remains unchanged. Router config_compatible explicitly selects the profile.

Original crate checksum: `c2856ab13701744c79101d343f8cebb5164eec3aafcf3ee1867b5b6033587daa`. Cargo.toml retains the upstream manifest plus the P-521 dependency.
