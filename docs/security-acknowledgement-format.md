# Signed acknowledgement format

Maintainer responses on a security disclosure thread that name a CVE, a
fix commit, or a coordinated-disclosure timeline are signed with the
same cosign keyless OIDC identity used for releases. This document
specifies the payload format and the verification recipe so a reporter
or a third party can independently confirm that an acknowledgement came
from this project's release identity.

## Payload shape

The signed blob is a UTF-8 JSON document with the following fields, in
RFC 8785 JCS canonical form before signing:

```json
{
  "schema_version": 1,
  "report_id": "GW-SEC-2026-001",
  "received_at_utc": "2026-05-20T14:32:00Z",
  "responded_at_utc": "2026-05-21T09:15:00Z",
  "scope_verdict": "in_scope",
  "severity_estimate": "high",
  "cve_id": "CVE-2026-12345",
  "fix_commits": ["abc123def456..."],
  "fix_release_tag": "v0.1.1",
  "disclosure_date_utc": "2026-08-19T00:00:00Z",
  "summary": "Free-text summary the reporter may quote in their writeup.",
  "reporter_credit_name": "Lin Park",
  "reporter_credit_anonymous": false
}
```

Fields whose value is `null` may be omitted. `report_id` is a maintainer
counter; `cve_id` is omitted before a CVE is assigned. `severity_estimate`
follows CVSS qualitative bands (`critical` / `high` / `medium` / `low`).

The payload is canonicalized per RFC 8785 (the same canonicalization the
bundle manifests use), serialized to UTF-8, then signed with `cosign
sign-blob --bundle ack.sigstore <(...)`. The reporter receives the
canonical JSON file and the cosign bundle.

## Verification recipe

```bash
cosign verify-blob \
  --bundle ack.sigstore \
  --certificate-identity-regexp '^https://github\.com/moonrunnerkc/gemma-witness/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  ack.json
```

The identity and issuer values are identical to the ones in
[`RELEASE.md` §"Trust anchors"](../RELEASE.md#trust-anchors) and must
stay in lockstep. A `verified` result means the blob was signed by this
project's release identity at the time the certificate was issued.

## Rationale

Email mailboxes can be compromised without the user noticing for weeks.
A signed acknowledgement removes the mailbox as a single point of trust:
if an adversary takes over `security@aftermath.tech`, they cannot
forge an acknowledgement that names the release identity, because they
don't hold the Sigstore OIDC certificate. The reporter who pinned the
identity once trusts every future acknowledgement from the same
identity, even if delivered through a channel the adversary controls.

This is the same trust transfer the release SHASUMS files use. The cost
is one extra command per disclosure thread; the cost of mailbox-only
trust is much higher when the report is consequential.

## When this is overkill

Most security threads do not warrant a signed acknowledgement; an
unsigned email saying "we got it, we are looking" is enough. Sign when:

- the response names a CVE assignment;
- the response sets or extends a disclosure embargo date;
- the response confirms or denies that a specific fix commit closes the
  reported issue;
- the reporter asks for signed acknowledgements explicitly (some
  research groups require this for their own disclosure paperwork).
