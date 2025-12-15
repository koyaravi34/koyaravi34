This design document captures the logic, architecture, and safety protocols of the **Prisma Cloud Auto-Defender** solution. You can present this directly to leadership or your Change Control Board (CCB).

---

#Technical Design Document: Prisma Cloud Auto-Defender**Version:** 2.0
**Status:** Ready for Deployment
**Owner:** Cloud Security Engineering
**Target Service:** AWS Lambda (Serverless)

---

##1. Executive SummaryThis document outlines the automated solution for deploying the **Prisma Cloud Serverless Defender** across our AWS Lambda estate.

**The Problem:** Manually attaching security layers to hundreds of Lambda functions is unscalable, prone to human error, and risky (potential to break applications).
**The Solution:** An intelligent, automated audit-and-remediate script that scans for unprotected functions and attaches the Prisma Defender **only** when safe to do so.
**Business Value:**

* **100% Audit Coverage:** Continuous hourly scanning of all regional functions.
* **Zero Downtime:** "Do No Harm" logic prevents breaking production apps by skipping risky configurations (e.g., low memory, near-timeout).
* **Operational Efficiency:** Eliminates manual security patching for serverless.

---

##2. Solution ArchitectureThe solution utilizes a "Manager-Worker" pattern entirely within AWS Serverless infrastructure to minimize maintenance.

###Core Components1. **EventBridge Scheduler:** Triggers the audit workflow hourly (`cron(0 * * * ? *)`).
2. **Auto-Defender Lambda:** The central "Manager" function containing the logic.
* **Runtime:** Python 3.11
* **Permissions:** Least Privilege IAM Role (See Section 6).


3. **Target Lambdas:** The application functions that require protection.
4. **Prisma Cloud Layer:** The immutable security artifact published by Palo Alto Networks/Prisma.

---

##3. Workflow & Logic (The "Risk Engine")The script does not blindly apply security. It uses a **Risk Assessment Engine** (`assess_risk()`) to validate every function before modification.

###Phase 1: Discovery* Script scans targeted AWS Regions (e.g., `us-east-1`, `us-west-2`).
* Filters for functions that are **not** currently protected (missing Layer or Environment Variables).

###Phase 2: Risk Assessment (Go/No-Go)Every candidate function must pass **five safety checks** to be eligible for auto-protection:

| Check | Criteria | Rationale |
| --- | --- | --- |
| **1. Package Type** | `Zip` only | **Container Images** cannot accept Layers via API; they must be secured at build time (Dockerfile). |
| **2. Architecture** | `x86_64` only | Current Prisma Layers are x86-optimized. Forcing them onto **ARM64 (Graviton)** functions causes immediate crash. |
| **3. Runtime** | Python/Node.js | Only runtimes compatible with the `AWS_LAMBDA_EXEC_WRAPPER` method are supported. |
| **4. Memory Headroom** | `> 256MB` | Defender agent requires ~30-70MB RAM. Functions with default **128MB** are at high risk of **OOM (Out of Memory)** crashes. |
| **5. Timeout Buffer** | `< 870s` | AWS hard timeout is 900s (15 min). If a function runs >14m 30s, adding Defender latency will cause **Timeouts**. |

###Phase 3: RemediationIf **all** checks pass:

1. **Update Config:** Appends the Prisma Layer ARN to the function.
2. **Inject Wrapper:** Adds `AWS_LAMBDA_EXEC_WRAPPER` environment variable.
3. **Tagging:** (Optional) Adds a tag `SecurityProtected: True` for tracking.

---

##4. Technical Limitations & ExclusionsThe following scenarios are **out of scope** for this automation and require manual or CI/CD-based remediation.

###4.1. Container Images* **Limitation:** Lambda functions deployed as Docker containers cannot use Lambda Layers.
* **Impact:** Automation skips these functions.
* **Remediation:** DevOps teams must add `COPY --from=twistlock/defender /usr/local/bin/defender` to their Dockerfiles.

###4.2. ARM64 (Graviton) Architectures* **Limitation:** The standard Prisma Defender Layer is incompatible with ARM64 instruction sets.
* **Impact:** Automation skips `arm64` functions to prevent `Exec format error` crashes.
* **Remediation:** Migrate function to x86_64 OR wait for Prisma ARM64 Layer support.

###4.3. High-Utilization Functions (Edge Cases)* **Limitation:** Functions running at >95% memory or timeout utilization.
* **Impact:** Automation skips these to prevent performance degradation.
* **Remediation:** Application owners must optimize code or increase quotas before security can be applied.

---

##5. Security Specifications###5.1. IAM Least PrivilegeThe automation runs with a highly scoped IAM Role.

* **Allowed:** `lambda:ListFunctions`, `lambda:GetFunctionConfiguration` (Read-only on *)
* **Restricted Write:** `lambda:UpdateFunctionConfiguration` is restricted by Condition keys (if enabled) or Account ID boundaries.
* **Denied:** The script **cannot** modify function code (`UpdateFunctionCode`), preventing it from injecting malicious business logic.

###5.2. Audit Trail* All actions (Skips, Updates, Errors) are logged to **Amazon CloudWatch Logs**.
* **Log Level:** `INFO` for general ops, `WARNING` for skipped risks, `ERROR` for API failures.

---

##6. Operational Roadmap###Deployment Strategy1. **Day 0 (Dry Run):** Deploy with `DRY_RUN = True`. Review CloudWatch logs to see which functions *would* be protected and which are skipped.
2. **Day 1 (Tag-Based Rollout):** Deploy with IAM Policy Condition `aws:ResourceTag/SecurityScan = "true"`. Only protect specific test functions.
3. **Day 7 (General Availability):** Remove IAM Condition. Automation protects all eligible functions hourly.

###Recovery Plan (Rollback)If the Defender causes issues on a specific function:

1. **Immediate:** Manually remove the Layer and `AWS_LAMBDA_EXEC_WRAPPER` variable via AWS Console.
2. **Prevention:** Add the function name to an `EXCLUSION_LIST` in the script configuration to prevent re-attachment.

---

##7. Configuration Reference (Script Variables)| Variable | Recommended Value | Description |
| --- | --- | --- |
| `MAX_LAYERS` | `5` | AWS Hard limit. |
| `MIN_MEMORY_MB` | `256` | Safety floor for memory. |
| `TIMEOUT_BUFFER_SEC` | `30` | Safety buffer for execution time. |
| `ZIPPED_SIZE_THRESHOLD` | `70 MB` | Prevents hitting unzipped code size limits. |
