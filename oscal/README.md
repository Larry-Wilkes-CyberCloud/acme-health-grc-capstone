# Layer 4 — OSCAL Component Definition

Machine-readable description of what this system implements, tying the actual Terraform resources to HIPAA Security Rule technical safeguards, with evidence URIs pointing at real signed bundles in the Layer 3 vault.

## What's here

| File | Model | Describes |
|---|---|---|
| component-definitions/acme-health-intake-v1/component-definition.json | Component Definition | The acme-health-intake system's 5 implemented requirements (2x 164.312(a)(2)(iv), 164.312(e)(1), 164.308(a)(7), 164.312(a)(1)), each with a real Terraform resource reference and evidence URI |
| profiles/hipaa-minimum/profile.json | Profile | Selects the HIPAA controls this component implements |

## Validation

Both files validate cleanly against trestle's OSCAL schema validator, not just as parsed JSON. Full output: evidence/layer-4/trestle-validate.txt.

## A real limitation, not a shortcut

Unlike NIST 800-53, which publishes a real machine-readable OSCAL catalog (used in the earlier cge-p-capstone labs' Lab 6.1), NIST SP 800-66 — the implementation guide for the HIPAA Security Rule — has no equivalent. It exists only as a human-readable document. The profile's imports.href correctly cites it as the authoritative source, but trestle author profile-resolve genuinely fails to fetch it (404, since it's an HTML page, not JSON), and the profile uses include-all rather than selecting individual control IDs, since HIPAA's citation format (e.g. 164.312(a)(2)(iv)) doesn't match OSCAL's required token format for with-ids anyway. This is a known ecosystem gap, documented rather than worked around.

## The traversal

Each of the 5 implemented-requirements links to a real, currently-verifiable evidence bundle in the Layer 3 vault (run 31727980555, the post-revert green run following the deliberate GAP-04 red-demo PR). Running `EVIDENCE_VAULT=acme-health-intake-evidence-af4ca5c0 bash scripts/verify-evidence.sh 31727980555` (adapted from the cge-p-capstone labs' Lab 4.4 script) against that link confirms integrity, authenticity, and preservation.

## Path

oscal/component-definitions/acme-health-intake-v1/component-definition.json
oscal/profiles/hipaa-minimum/profile.json

## Evidence

evidence/layer-4/trestle-validate.txt
