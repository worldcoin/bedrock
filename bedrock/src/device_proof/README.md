# World ID device proofs

`RootKey.create_world_id_device_proof` signs an account-authentication challenge
for the Auth bridge. It returns public material; the private key stays in Rust.
The app must obtain user approval and supply the expected issuer from trusted
configuration, never from the QR code or decrypted request.

Pass the exact decoded bytes of `device_proof_request.challenge`. The challenge
is JSON with `version` (1), `issuer`, `ceremony_id` (canonical UUID), `nonce`
(32 bytes, unpadded base64url), and `expires_at` (Unix seconds). Challenges expire
within five minutes; validation permits 30 seconds of clock skew on that maximum.

The response uses compressed SEC1 P-256 public keys and low-S DER ECDSA
signatures, both encoded as unpadded base64url. The signed digest is
`SHA256("WORLD-ID/IDP/DEVICE-PROOF/V1\0" || challenge_bytes)`.
The mobile bridge sends these fields inside its existing encrypted response:

```json
{"credential_type":"device","public_key":"…","signature":"…"}
```

Key derivation uses the root key's existing `OXIDEKEY` KDF context and subkey ID
`0x102`. For counter values 0 through 255, hash
`"WORLD-ID/IDP/DEVICE-KEY/V1\0" || subkey || counter_u32_big_endian` with SHA-256
and use the first valid P-256 secret scalar. V0 roots use their existing
normalization. Restoring a root restores the same device credential.

This is account authentication, with no assertion of human verification, Face
Auth, or hardware binding. Native sessions are outside this API's scope.
The [vectors](testdata/v1.json) are also verified by the identity provider's Go implementation.
