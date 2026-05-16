# Security policy

Gemma.Witness is a tamper-evidence system for civic-accountability evidence
capture. Bundles signed by this project may end up in a courtroom, a press
freedom case file, or a labor-incident review. Every signature, every
fingerprint check, and every byte that flows through the verifier is a
trust anchor for someone who may not be able to defend themselves any
other way. If you find a defect in any of that, this document is how to
tell us about it before an adversary uses it.

## Supported versions

| Version line | Support status |
| :--- | :--- |
| `0.1.x` (beta) | Active. Security patches land on `main` and are rolled into the next tag. |
| Pre-beta tags | Unsupported. Update to the latest beta. |

Until a `1.0` line ships, only the current beta is patched. After `1.0`,
the latest minor on the previous major will receive security backports
for 6 months from the release of the new major.

## Reporting a vulnerability

Three channels, in preferred order:

1. **GitHub private vulnerability reports.** Open
   [github.com/moonrunnerkc/gemma-witness/security/advisories/new](https://github.com/moonrunnerkc/gemma-witness/security/advisories/new).
   This is the fastest path and creates an auditable thread the
   maintainer and reporter share. Use it unless you specifically need
   one of the other channels.

2. **Encrypted email.** `security@aftermath.tech`, encrypted with the
   PGP key at [`docs/security-pgp-key.asc`](docs/security-pgp-key.asc).
   Subject line should start with `[gemma-witness]`. Include a Signal
   contact if you would like to switch to that channel for follow-up.

3. **Out-of-band Signal.** For reports that cannot land on a corporate
   email path (for example, you are a journalist whose threat model
   excludes US-jurisdiction email providers), request a Signal contact
   via channel 1 or 2 above and we will switch to a Signal thread for
   the rest of the disclosure.

Do not file a public GitHub issue, post to a public forum, or share the
report on social media before coordinated disclosure has closed. We will
not retaliate or restrict access in response to a report filed in good
faith.

## Service-level expectations

We will:

- acknowledge receipt within **72 hours** of report submission;
- give an initial triage verdict (in-scope, out-of-scope, duplicate,
  need-more-info) within **7 days**;
- aim to ship a fix within **14 days** for critical severity, **30
  days** for high, **90 days** for medium, with extensions only by
  mutual agreement;
- publish a coordinated GitHub Security Advisory once the fix lands on
  `main`, naming the reporter unless you ask to remain anonymous.

If we miss a deadline, you may publish at the agreed disclosure date
without further notice. Quiet failure to follow up is a defect on our
side, not a reason to extend the embargo unilaterally.

## Signed acknowledgements

Maintainer responses on a security thread that name a CVE, a fix commit,
or a coordinated-disclosure timeline are signed with the same cosign
keyless OIDC identity used for releases (see
[`RELEASE.md` §"Trust anchors"](RELEASE.md#trust-anchors)). The signed
blob is attached to the GitHub Security Advisory or sent as a separate
message in the email thread. The signature lets a reporter (or a third
party reading the advisory later) prove the response actually came from
this project's release identity rather than from a compromised maintainer
mailbox. The blob format and `cosign verify-blob` recipe are documented
in [`docs/security-acknowledgement-format.md`](docs/security-acknowledgement-format.md).

## Scope

In scope:

- Bundle integrity: any path by which a `.witness` bundle that has been
  altered after sealing can verify cleanly.
- Signature flow: forgery, malleability, replay, or downgrade in the
  signing or verification paths.
- Canonicalization: any input that produces different bytes between the
  Rust signer and the JavaScript verifier (see the cross-language
  conformance suite at `tests/fixtures/canonicalization-conformance/`).
- Fingerprint registry: a way to land an unaudited model fingerprint in
  the registry, or to bypass the build-time signature gate on the
  registry envelope.
- Verifier behavior: any way the static HTML verifier can be made to
  report green on a bundle that should fail, including via the
  registry-signature row, the signer-identity row, or any of the asset
  and signature rows.
- Sidecar boundary: a way to exfiltrate audio or image data from the
  capture process via the inference sidecar, to bypass the loopback or
  token enforcement, or to OOM the capture process with an unbounded
  sidecar response.
- Supply chain: tampering with the release workflow, the signed
  fingerprint registry envelope, the pinned mistral.rs binary, or the
  embedded trust-anchor configuration.
- Hardware-backed signing path: any way the Secure Enclave / TPM /
  NCrypt backend produces a signature attributable to a device that did
  not in fact perform the signing operation.

Out of scope (the threat model is explicit):

- A reporter signing a false statement of their own free will. The
  bundle proves what the device sealed, not what actually happened.
- Compromise of the capture device before sealing, including kernel
  rootkits, microphone or camera tampering upstream of the file system,
  or signed key extraction from a compromised user account.
- Social engineering of the trust-anchor lists (`trusted-signers.json`,
  `known-fingerprints.json`, the cosign keyless identity in
  `RELEASE.md`). Convincing a maintainer to merge a malicious PR is
  always possible; this policy does not promise to detect that.
- Traffic analysis of who is producing bundles when (the project is
  offline and does not generate network traffic, but inferring that a
  particular host is running the capture app from out-of-band signals
  is not something the bundle format defends against).
- Theoretical cryptographic weaknesses in Ed25519, ECDSA P-256, or
  SHA-256. We follow the consensus libraries (`ed25519-dalek`, `p256`,
  `sha2`) and will rotate as those libraries do.

If your report is on the boundary, file it anyway. We will tell you if
it is out of scope and why, and the conversation alone may surface a
documentation gap worth fixing.

## Reward policy

There is no monetary reward program at this stage. Public credit in the
advisory is offered for every accepted in-scope report, and we are happy
to write a reference letter or LinkedIn recommendation when the reporter
asks. If a sufficient backer materializes a bounty pool, this section
will be updated.

## Hall of fame

| Date | Reporter | Severity | Summary |
| :--- | :--- | :--- | :--- |
| _none yet_ | | | |
