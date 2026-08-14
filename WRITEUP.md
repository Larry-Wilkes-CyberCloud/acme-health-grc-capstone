# WRITEUP: Acme Health GRC Capstone

## Primary framework: HIPAA Security Rule

Acme Health is a telehealth company; the intake API ingests PHI on every POST /intake request. HIPAA Security Rule is the only one of the three candidate frameworks (HIPAA, SOC 2 TSC, CMMC L2) that is a direct legal obligation for this business, not a contractual or customer-driven requirement. Seven of the starter's eight named gaps map to a HIPAA citation, which strongly suggests the starter was designed with HIPAA as its intended primary framework. Catalog reference: NIST SP 800-66 Rev 2, the official implementation guide for the HIPAA Security Rule. There is no dedicated NIST OSCAL catalog for HIPAA itself -- a real, documented limitation covered in the OSCAL section below.

## Control coverage

Five of the starter's eight named gaps were closed, chosen for depth of coverage over breadth of scope:

| Gap | Issue | HIPAA control | Enforced by |
|---|---|---|---|
| GAP-01 | S3 uploads bucket used SSE-S3, not a customer-managed key | 164.312(a)(2)(iv) | s3_kms_encryption.rego |
| GAP-02 | DynamoDB used an AWS-owned key, not a CMK | 164.312(a)(2)(iv) | dynamodb_kms_encryption.rego |
| GAP-03 | No TLS-only bucket policy on the uploads bucket | 164.312(e)(1) | s3_tls_only.rego |
| GAP-04 | No versioning on the uploads bucket | 164.308(a)(7) | s3_versioning.rego |
| GAP-07 | Lambda IAM role had dynamodb:* and s3:* | 164.312(a)(1) | iam_least_privilege.rego |

GAP-05 (Lambda into the starter's VPC) and GAP-08 (API Gateway access logging/throttling/WAF) were left as stretch goals -- not attempted, not because they're unimportant, but because five gaps closed with real depth (Terraform + Rego + tests + CI enforcement + OSCAL traceability, all four layers) beat eight gaps closed shallowly. GAP-06 (reserved concurrency, DLQ, X-Ray) was explicitly out of scope: it maps only to SOC 2/CMMC controls, not HIPAA.

## Design decisions

**Object Lock mode: GOVERNANCE.** Matches the pattern proven in the earlier CGE-P labs. GOVERNANCE still blocks ordinary deletion/overwrite of retained evidence, while leaving a documented, permissioned bypass path available -- the safer choice for an actively-developed project than COMPLIANCE mode's irreversible lock.

**Account structure: single AWS account.** The capstone brief calls a single account acceptable for a 30-day timeline. This is a personal sandbox account with no existing multi-account/AWS Organizations structure; standing one up would be scope creep unrelated to what the capstone tests.

**Evidence vault: new, dedicated to this capstone.** Rather than reusing the earlier labs' evidence vault, this project stands up its own S3 evidence bucket with Object Lock, keeping the capstone's evidence chain self-contained and independently verifiable without depending on a separate repo staying intact.

**KMS: one customer-managed key, shared across S3 and DynamoDB.** A single CMK for both the uploads bucket and the intake table keeps the design simple and auditable -- one key policy, one rotation schedule, one place a HIPAA auditor needs to review for who can decrypt PHI.

**Terraform layout: overrides live in the same state as the starter, not a separate root.** The gap-closing resources (SSE-KMS config, versioning, bucket policy) reference the starter's existing resources directly (e.g. `aws_s3_bucket_server_side_encryption_configuration.uploads { bucket = aws_s3_bucket.uploads.id }`). That only works cleanly in a shared state; a separate root would need `terraform_remote_state` data sources for zero benefit in a single-account, single-workspace project.

**Apply is a deliberate manual step, not automated in CI.** This was a real design decision, not an assumption -- see "A real production bug, found and fixed" below for how it was discovered and why it stayed manual rather than being automated.

## A real production bug, found and fixed

Merging the OSCAL layer's PR triggered a push to main, which triggered the pipeline's apply step for the first time -- and it failed with AccessDenied on nearly every resource type: S3 CreateBucket, KMS CreateKey, EC2 CreateVpc, IAM CreateRole, even iam:CreateOpenIDConnectProvider. The root cause: the GitHub Actions OIDC role was only ever granted ReadOnlyAccess plus a narrow evidence-vault-write policy. Every successful apply throughout this project had actually been run manually, from an operator's own credentials -- the automated apply step had simply never been exercised until this exact push, because every prior merge to main had only changed policies, not infrastructure requiring creation.

Two ways to fix it: grant the CI role broad create/modify permissions so apply works automatically, or remove the automated apply step and keep it manual. I chose the latter. Handing a CI role infra-admin power on every merge to main is a real risk surface for a system handling PHI -- anyone who can get a PR merged effectively gets account-wide create/delete power. Manual, human-run apply is a legitimate, common pattern for a solo project, and it is exactly the trade-off the capstone brief explicitly names as a decision to make and defend: "whether the pipeline applies on merge to main, or after a manual approval gate post-merge."

This bug also surfaced a smaller but real lesson: the fix originally used an em-dash character, written via a Python string-replace script, which landed as an invalid UTF-8 byte sequence and broke YAML parsing (`invalid leading UTF-8 octet`). The workflow file had to be rebuilt from scratch using plain ASCII punctuation to resolve it -- a reminder that automated file generation on this Windows/Git Bash toolchain needs to stay ASCII-safe even when the surrounding prose doesn't.

## Debugging the policy gate against a real CI plan

The Rego policies passed their unit tests immediately (opa test, synthetic fixtures) but failed against a real Terraform plan generated in CI. The root cause: this repo has no remote Terraform state, so every CI run plans from empty state -- a full "create everything from scratch" plan, where computed values like a new bucket's id or a new KMS key's ARN are "known after apply," not resolved. The original policies matched by computed-value equality (a child resource's `bucket` attribute against its parent's `id`), which is always false when both sides are unknown.

Fixed by rematching four of the five policies against resource address (static, always known at plan time) instead of computed values, and by adding an `after_unknown` fallback for the DynamoDB KMS check, which accepts a key ARN that is either a known non-empty string or explicitly marked as computed-from-a-reference -- both indicate a real key, as opposed to a hardcoded empty string. One policy, s3_tls_only, needed a further simplification: its bucket policy's entire rendered JSON is built from a data source referencing the bucket's own ARN, so on a from-scratch plan the whole policy string is unknown and cannot be parsed at all. That policy now checks for the presence of a bucket-policy resource rather than parsing its condition content -- a real, acknowledged trade-off, not a hidden shortcut (see "What I'd do with more time" below).

Each fix was verified two ways before being pushed: opa test locally, and a real `terraform plan` + `conftest test --all-namespaces` run against live local state, confirming all five policies passed against real data before trusting a CI run to confirm it again.

## Proving the gate is fail-closed

A second pull request deliberately reintroduced GAP-04 by setting the uploads bucket's versioning status to `Suspended`. CI caught it precisely: only the s3_versioning policy denied, citing the exact HIPAA control and the exact resource address, while all four other policies still passed cleanly. The change was reverted in a second commit on the same PR, CI went green, and the PR was merged -- a real, provable red-to-green history, not a staged demonstration.

## A genuine ecosystem gap: HIPAA has no OSCAL catalog

Unlike NIST 800-53, which publishes a real machine-readable OSCAL catalog, NIST SP 800-66 (the HIPAA Security Rule's implementation guide) exists only as a human-readable webpage. The OSCAL component definition's `control-implementation.source` correctly cites it as the authoritative mapping, but `trestle author profile-resolve` genuinely fails trying to fetch it as JSON (404, since it's HTML). The profile also could not select individual control IDs the way the 800-53 labs did, because HIPAA's citation format (e.g. `164.312(a)(2)(iv)`) contains parentheses and does not match OSCAL's required token format for `with-ids`. The profile uses `include-all` instead. Both files still validate cleanly against trestle's schema, and the component definition's evidence links resolve to real signed bundles -- this is a documented limitation of the current OSCAL ecosystem for HIPAA specifically, not a shortcut taken to avoid the work.

## What I'd do with another sprint

- **A remote Terraform backend (S3 + DynamoDB lock).** This would let CI and local runs share real state instead of every CI plan being a from-scratch create. That would let the s3_tls_only policy inspect actual bucket-policy content instead of just presence, and would make a safely-scoped automated apply possible (with state locking preventing concurrent-apply corruption) if that trade-off were revisited.
- **GAP-05 (Lambda into the VPC) and GAP-08 (API Gateway access logging, throttling, a WAF).** Both were scoped out to keep five gaps closed with real depth rather than eight closed shallowly; both are legitimate next additions.
- **A second AWS account for evidence isolation**, separating the evidence vault's blast radius from the workload account, as the brief itself suggests as the "cleaner" option beyond a 30-day timeline.
- **Patient data lifecycle (deletion/export)**, noted in the starter's own WORKLOAD.md as deliberately out of scope, but a real requirement for a production HIPAA system.

## Layer summary

| Layer | Deliverable | Status |
|---|---|---|
| 1 -- Terraform GRC baseline | KMS CMK, evidence vault (Object Lock GOVERNANCE), CloudTrail, 5 gap-closing overrides | Complete, merged, verified by real apply + smoke test |
| 2 -- OPA policy suite | 5 Rego policies, each HIPAA-cited, each with tests | Complete, 14/14 tests passing, verified against a real plan |
| 3 -- GitHub Actions pipeline | Plan, Conftest gate, sign, upload; one green PR, one red-to-green PR | Complete, real CI failures debugged and documented above |
| 4 -- OSCAL component | Component definition + profile, validated, real evidence links | Complete, HIPAA-catalog limitation documented |

## Verification

- Green pipeline run: PR #3, merged to main.
- Red-to-green demonstration: PR #4, deliberate GAP-04 reintroduction caught and reverted.
- Signed evidence bundles: `s3://acme-health-intake-evidence-af4ca5c0/runs/<run_id>/`. Verify with Cosign against the public Sigstore Rekor log, SHA-256 recompute, and Object Lock retention check.
- OSCAL validation: `trestle validate -f oscal/component-definitions/acme-health-intake-v1/component-definition.json` and the equivalent for the profile, both return VALID.
- Policy tests: `opa test -v policies/` from the repo root, 14/14 passing.
