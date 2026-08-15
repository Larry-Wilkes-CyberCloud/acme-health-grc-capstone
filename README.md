# Acme Health GRC Capstone

Fork of [cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter), wrapped with the four CGE-P GRC layers to make a deliberately non-compliant patient intake API defensible against the **HIPAA Security Rule**. Full reasoning in [WRITEUP.md](WRITEUP.md); design decisions in [DESIGN.md](DESIGN.md).

## What was built

| Layer | What it adds | Where |
|---|---|---|
| 1 -- Terraform GRC baseline | Customer-managed KMS key, S3 evidence vault (Object Lock, GOVERNANCE mode), CloudTrail, 5 gap-closing overrides | terraform/kms.tf, terraform/evidence-vault.tf, terraform/cloudtrail.tf, terraform/gap-overrides.tf, terraform/main.tf |
| 2 -- OPA policy suite | 5 Rego policies, each citing a HIPAA control, each with tests | policies/, policies/tests/ |
| 3 -- GitHub Actions pipeline | Plan, Conftest gate, Cosign sign, upload to vault (apply is manual -- see below) | .github/workflows/grc-gate.yml, scripts/ |
| 4 -- OSCAL component | Component definition + profile citing NIST SP 800-66, real evidence links | oscal/ |

Five of the starter's eight named gaps are closed: GAP-01, GAP-02, GAP-03, GAP-04, GAP-07. See [GAPS.md](GAPS.md) for the full list and [WRITEUP.md](WRITEUP.md) for why these five.

## Verifying this submission

### 1. The pipeline works and enforces policy

- PR #3 -- the pipeline itself, running Plan -> Conftest -> Cosign sign -> vault upload. Merged green.
- PR #4 -- a deliberate reintroduction of GAP-04 (S3 versioning suspended). CI failed, citing only the s3_versioning policy by exact HIPAA control ID, while all four other policies still passed. Reverted in the same PR, CI went green, merged.

Both are visible in the closed-PR history: `gh pr list --state merged` or the Pull Requests tab.

### 2. Policy tests pass

```bash
pip install opa || true  # opa is a standalone binary, not pip -- see https://www.openpolicyagent.org/docs/latest/#running-opa
opa test -v policies/
```
Expect `PASS: 14/14`.

### 3. A signed evidence bundle verifies

Every pipeline run signs its plan + Conftest results and uploads them to `s3://acme-health-intake-evidence-<suffix>/runs/<run_id>/`, protected by S3 Object Lock (GOVERNANCE mode). To verify a bundle: download it, run `cosign verify-blob` against its `.sig.bundle` file (keyless, verifies against the public Sigstore Rekor transparency log), recompute its SHA-256 against the uploaded `.sha256` file, and confirm `ObjectLockRetainUntilDate` is still in the future via `aws s3api head-object`.

### 4. OSCAL validates

```bash
pip install compliance-trestle
cd oscal
trestle validate -f component-definitions/acme-health-intake-v1/component-definition.json
trestle validate -f profiles/hipaa-minimum/profile.json
```
Both return `VALID`. Full output already captured in [evidence/layer-4/trestle-validate.txt](evidence/layer-4/trestle-validate.txt), including the expected `404` from `trestle author profile-resolve` -- HIPAA/NIST SP 800-66 has no machine-readable OSCAL catalog to resolve against, unlike NIST 800-53. See [oscal/README.md](oscal/README.md) for the full explanation.

## Deploying and applying

The pipeline runs Plan, the Conftest policy gate, Cosign signing, and evidence upload automatically on every pull request. **Apply is a deliberate manual step**, not automated -- the CI role is scoped to `ReadOnlyAccess` plus a narrow evidence-vault-write policy, with no create/modify permissions on workload infrastructure. See [WRITEUP.md](WRITEUP.md) for why. To apply locally:

```bash
cd terraform
eval "$(aws configure export-credentials --profile <your-sandbox-profile> --format env)"
terraform init
terraform apply
```

## Cost

Roughly $0 if destroyed within an hour of applying. Lambda, API Gateway, DynamoDB, and S3 are all pay-per-use; CloudTrail and KMS cost cents. `terraform destroy` from the `terraform/` directory (same credential export as above) tears everything down.

## Layout

    acme-health-grc-capstone/
      README.md              # this file
      DESIGN.md              # design decisions, made before building
      WRITEUP.md             # the required capstone write-up
      GAPS.md                # the starter's named flaws (unmodified)
      FRAMEWORKS.md          # HIPAA / SOC 2 / CMMC mapping primer (unmodified)
      Makefile               # make deploy | test | destroy (starter's original)
      terraform/             # starter's workload + Layer 1 GRC baseline
      policies/              # Layer 2: Rego policies + tests
      .github/workflows/     # Layer 3: grc-gate.yml
      scripts/                # Layer 3: bundle-sign-upload.sh, make_receipt.py
      oscal/                  # Layer 4: component definition + profile
      evidence/               # captured trestle validation output

## License

MIT, inherited from the starter.
