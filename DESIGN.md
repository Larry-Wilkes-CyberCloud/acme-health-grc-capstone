# Design Doc — Acme Health GRC Capstone

## Primary framework: HIPAA Security Rule

Acme Health is a telehealth company; the intake API ingests PHI on every request. HIPAA Security Rule is the only one of the three candidate frameworks (HIPAA, SOC 2 TSC, CMMC L2) that is directly named as a legal obligation for this business, not just a customer or contract requirement. 7 of the 8 named gaps in GAPS.md map to a HIPAA citation, which strongly suggests the starter was built with HIPAA as the intended primary framework. Catalog reference: NIST SP 800-66 Rev 2 (the official implementation guide for the HIPAA Security Rule; there is no dedicated NIST OSCAL catalog for HIPAA itself).

## Gaps in scope

Closing 5 of 8 gaps, chosen for depth of coverage over breadth:

| Gap | Issue | HIPAA control |
|---|---|---|
| GAP-01 | S3 uploads bucket uses SSE-S3, not a customer-managed key | 164.312(a)(2)(iv) |
| GAP-02 | DynamoDB uses an AWS-owned key, not a CMK | 164.312(a)(2)(iv) |
| GAP-03 | No TLS-only bucket policy on the uploads bucket | 164.312(e)(1) |
| GAP-04 | No versioning on the uploads bucket | 164.308(a)(7) |
| GAP-07 | Lambda IAM role has dynamodb:* and s3:* | 164.312(a)(1) |

GAP-05 (Lambda into the starter's VPC) and GAP-08 (API Gateway access logging/throttling/WAF) are stretch goals if time allows. GAP-06 (concurrency/DLQ/X-Ray) is explicitly out of scope — it maps only to SOC 2/CMMC controls, not HIPAA.

## Architecture decisions

**Object Lock mode: GOVERNANCE.** Matches the pattern already proven in the CGE-P labs (Lab 2.5, Lab 4.4). GOVERNANCE still blocks ordinary deletion/overwrite of retained evidence, while leaving a documented, permissioned bypass path available — the safer choice for an actively-developed 30-day project versus COMPLIANCE mode's irreversible lock.

**Account structure: single AWS account.** The capstone brief calls a single account acceptable for a 30-day timeline. This is a personal sandbox account with no existing multi-account/AWS Organizations structure; standing one up would be scope creep unrelated to what the capstone actually tests (governing a workload, not provisioning account architecture).

**Apply timing: on merge to main.** No team to coordinate a manual-approval workflow with — this is a solo capstone. Automatic apply-on-merge is also consistent with every pipeline pattern already built in Lab 4.3/4.4, so Layer 3 here is a direct extension of proven work rather than a new pattern.

**Evidence vault: new, dedicated to this capstone.** Rather than reusing the existing cge-p-capstone Lab 2.5/4.4 vault, this project stands up its own S3 evidence bucket with Object Lock. Keeping the capstone's evidence chain self-contained in its own repo/account resources makes the submission independently verifiable without depending on a separate repo staying intact.

**KMS: one customer-managed key, shared across S3 and DynamoDB.** A single CMK for both the uploads bucket and the intake table keeps the design simple and auditable — one key policy, one rotation schedule, one place a HIPAA auditor needs to review for "who can decrypt PHI."

## What's deliberately not being built

- GAP-05 and GAP-08 unless time allows in a later week.
- Authentication/authorization at the API layer (explicitly out of scope per WORKLOAD.md).
- Multi-region failover, patient data lifecycle (deletion/export) — both noted as known gaps for the write-up, not solved here.
- A second AWS account for evidence isolation.

## Repo structure (planned)

acme-health-grc-capstone/
  terraform/            # starter's original resources, unmodified where possible
  terraform/grc/         # new: KMS, evidence vault, CloudTrail, gap-closing overrides
  policies/              # new: 5+ Rego policies with tests, HIPAA-cited
  .github/workflows/     # new: grc-gate.yml (plan/policy-check/apply/sign/upload)
  oscal/                 # new: component-definition.json + profile
  WRITEUP.md             # design decisions, control coverage, trade-offs, what's left

## Status

Design locked. Deploy gate passed (make deploy / make test verified against the unmodified starter, then destroyed to avoid idle cost). Next: Layer 1 Terraform GRC baseline.
