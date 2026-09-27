# ECDAT — Discovery & Scan Implementation Plan

## 0. Purpose

The `/scans` module is the entry point for the **Discover** stage of ECDAT.

The original problem statement requires ECDAT to identify and catalogue cryptographic artefacts across applications, products and infrastructure, including:

* Algorithms
* Keys
* Certificates
* Protocols
* Libraries
* Hardware modules
* Cloud services
* Source code repositories
* Binaries
* Libraries/dependencies
* Container images
* Internal systems
* External-facing systems

The current implementation primarily supports **folder/source-code scanning and external JSON finding ingestion**.

The goal of this roadmap is to evolve `/scans` into a **general-purpose Enterprise Cryptographic Discovery platform**.

### Core principle

> Discover should collect broad, evidence-backed cryptographic observations. It should not perform the final quantum-risk or migration-priority decision.

Those responsibilities belong to later ECDAT stages:

```text
DISCOVER
    ↓
Raw cryptographic evidence
    ↓
UNDERSTAND
    ↓
Normalized cryptographic intelligence
    ↓
AI RISK & REASONING
    ↓
Risk + migration reasoning
    ↓
ACTION
    ↓
Migration recommendations
```

---

# 1. Current State

The existing `/scans` page contains:

### Header

* Discovery segment eyebrow
* Discovery & scans title
* Discovery workflow description
* Run demo scan action

### Main tabs

* Folder discovery
* External findings

### Folder discovery

Current controls:

* Specified folder
* Quick scan
* Whole workspace
* Discovery engine
* Target folder
* Browse folders
* Maximum files
* Maximum depth
* Maximum file size
* Exclusion rules
* Review/start scan

### Job monitor

Current information:

* Job ID
* Target
* Status
* Progress
* Findings count
* Created time
* Error message
* Cancel action
* Completed-state confirmation

### External findings

Current functionality:

* JSON file picker
* External target/name
* JSON editor
* Example payload
* Findings-array validation
* Ingest action
* Toast feedback

### Scan history

Current information:

* Job ID
* Target
* Source type
* Status
* Progress
* Findings count
* Created time
* View action
* Refresh
* Loading/error/empty states

### Dialogs

* Confirm local scan
* Scope/target summary
* Warning
* Browse local folders
* Path input
* Root navigation
* Folder listing

### Current behaviour

* Scan list scoped to active workspace/session
* View loads job monitor
* Active jobs poll every 3 seconds
* Start/cancel/demo/ingest refresh scan list
* Validation/errors use toast feedback

---

# 2. Target State

The `/scans` module should evolve from:

```text
"Scan this folder for crypto"
```

into:

```text
"Discover cryptographic artefacts across an enterprise"
```

The UI should eventually support multiple discovery sources:

```text
                    DISCOVERY
                        │
       ┌────────────────┼─────────────────┐
       │                │                 │
   Code & Files      Artifacts        Environments
       │                │                 │
       ▼                ▼                 ▼
 Repositories       Certificates       Cloud
 Source code        Keys                Kubernetes
 Binaries           Libraries           Infrastructure
 Firmware            Protocols           Network
 Containers          Hardware            External APIs
 Dependencies
```

However, **do not implement all of these simultaneously**.

Build a discovery framework first.

---

# 3. Discovery Architecture

Create a scanner abstraction.

Every discovery engine should follow the same conceptual lifecycle:

```text
Create Scan
    ↓
Validate Target
    ↓
Discover
    ↓
Extract Evidence
    ↓
Create Findings
    ↓
Deduplicate
    ↓
Persist Findings
    ↓
Complete Scan
```

A scanner should not directly calculate final quantum risk.

Instead:

```text
Scanner
  ↓
Finding
  ↓
Evidence
  ↓
Normalization
```

---

# 4. Canonical Discovery Finding

All discovery engines must eventually produce a common finding structure.

Recommended conceptual schema:

```json
{
  "id": "finding-id",

  "scan_id": "scan-id",

  "workspace_id": "workspace-id",

  "asset": {
    "id": "asset-id",
    "name": "payment-service",
    "type": "application",
    "environment": "production"
  },

  "artifact": {
    "type": "algorithm",
    "name": "RSA",
    "variant": "RSA-2048"
  },

  "usage": {
    "purpose": "JWT signing",
    "protocol": null,
    "operation": "sign"
  },

  "implementation": {
    "library": "OpenSSL",
    "version": "3.x",
    "api": "EVP"
  },

  "location": {
    "path": "src/auth/sign.py",
    "line": 142,
    "function": "sign_token"
  },

  "evidence": {
    "type": "source",
    "value": "...",
    "confidence": 0.94
  },

  "metadata": {
    "scanner": "source-code-scanner",
    "scanner_version": "1.0.0"
  }
}
```

The exact database schema may differ.

The important requirement is that **all scanners converge into a common finding model**.

---

# 5. Discovery Finding Types

The architecture must not assume that every finding is an algorithm.

Support at least:

```text
algorithm
key
certificate
protocol
library
dependency
crypto_api
crypto_configuration
hardware_module
cloud_crypto_service
crypto_implementation
unknown_crypto_artifact
```

Additional types may be introduced later.

---

# 6. Asset Types

Support a broad asset taxonomy.

Initial taxonomy:

```text
application
repository
source_code
binary
firmware
container
library
dependency
certificate
key_reference
cloud_resource
infrastructure
hardware
network_endpoint
external_service
api
unknown
```

The taxonomy should be extensible.

Do not hard-code the UI around only "folder" or "source code".

---

# 7. Scan Sources

Create a scanner/source abstraction.

Example:

```text
Source Type
├── Local Workspace
├── Repository
├── Uploaded Artifact
├── Binary
├── Container Image
├── Cloud
├── Network/Endpoint
├── External Findings
└── Future Sources
```

The current folder scanner becomes:

```text
Local Workspace Scanner
```

rather than defining the entire discovery architecture.

---

# 8. Scanner Registry

Implement a scanner registry.

Conceptually:

```text
DiscoveryEngineRegistry

- source-code
- dependency
- binary
- container
- certificate
- firmware
- cloud
- protocol
- external-findings
```

Each scanner should expose metadata:

```text
id
name
description
supported_targets
supported_artifacts
configuration_schema
capabilities
status
version
```

This allows the UI to dynamically discover available scanners.

Do not hard-code every scanner into the page.

---

# 9. Phase 1 — Stabilize Existing Folder Discovery

Before adding new discovery types, make the current scanner production-quality.

### Keep

* Specified folder
* Quick scan
* Whole workspace
* Max files
* Max depth
* Max file size
* Exclusion rules
* Job monitor
* History
* Cancellation
* Progress
* Findings count

### Improve terminology

Replace overly implementation-specific wording.

Instead of:

```text
Start a source-code scan
```

Use:

```text
Start a discovery scan
```

Instead of:

```text
Target folder
```

Use:

```text
Discovery target
```

Instead of:

```text
Local filesystem
```

Use:

```text
Workspace / connected source
```

The UI should remain technically accurate without making the product appear limited to local folders.

---

# 10. Phase 2 — Discovery Source Selection

Introduce a top-level source selector.

Example:

```text
Discovery source

[ Workspace ]
[ Repository ]
[ Artifact ]
[ Container ]
[ Cloud ]
[ External Findings ]
```

Only show sources that are actually supported.

For unsupported sources:

```text
Coming soon
```

or omit them.

Do not create fake functionality.

---

# 11. Phase 3 — Repository Discovery

Add repository scanning.

Potential sources:

```text
Git repository
GitHub
GitLab
Bitbucket
```

Initial implementation can support a local Git repository.

Later add integrations.

Discovery should inspect:

```text
Current files
Dependency manifests
Configuration
Dockerfiles
Infrastructure-as-Code
Certificates
Keys/references
Crypto APIs
Crypto libraries
Git metadata
```

Optional advanced capability:

```text
Git history
Branches
Tags
Deleted secrets/certificates
```

Do not expose or persist private credentials discovered in repository history.

Store safe evidence/fingerprints where appropriate.

---

# 12. Phase 4 — Dependency Discovery

The source-code scanner should identify dependency manifests.

Examples:

```text
package.json
requirements.txt
pyproject.toml
pom.xml
build.gradle
Cargo.toml
go.mod
*.csproj
Gemfile
composer.json
```

Build:

```text
Application
    ↓
Direct dependency
    ↓
Transitive dependency
    ↓
Crypto library
    ↓
Crypto capability
```

Record:

* Package
* Version
* Dependency relationship
* Crypto relevance
* Evidence
* Confidence

---

# 13. Phase 5 — Binary Discovery

Add binary upload/discovery.

Supported formats should initially include whichever formats the backend can reliably inspect.

Potential formats:

```text
ELF
PE
Mach-O
APK
Shared libraries
Firmware images
```

Scanner should extract:

```text
Architecture
Compiler information
Imported functions
Exported functions
Strings
Embedded certificates
Embedded public keys
Crypto library fingerprints
Known algorithm indicators
Crypto-related symbols
```

Every finding needs evidence.

Example:

```text
Binary:
payment-service

Evidence:
Imported symbol:
EVP_PKEY_sign

Library:
OpenSSL

Confidence:
High
```

---

# 14. Phase 6 — Container Discovery

Allow:

```text
Container image
Dockerfile
OCI image
```

Inspect:

```text
Base image
OS packages
Application packages
Libraries
Binaries
Configuration
Certificates
Crypto libraries
```

Model the relationship:

```text
Container
   ↓
Image
   ↓
Layer
   ↓
Package
   ↓
Library
   ↓
Crypto capability
```

Avoid storing secrets discovered inside image layers.

---

# 15. Phase 7 — Certificate Discovery

Introduce a dedicated certificate scanner.

Discover:

```text
PEM
DER
CRT
CER
P12
PFX
JKS
```

Extract metadata:

```text
Subject
Issuer
Serial
Validity
Expiration
Public-key algorithm
Key size
Curve
Signature algorithm
SAN
Chain
Fingerprint
```

The scanner should identify certificates but must not expose private key material in the UI.

---

# 16. Phase 8 — Cryptographic Key Discovery

Discover key references and key metadata.

Potential sources:

```text
Configuration
Certificate stores
KMS references
HSM references
SSH configuration
Application configuration
Cloud resources
```

Do NOT make "collect every secret/private key" the objective.

Instead:

```text
Detect
Fingerprint
Classify
Reference
Correlate
```

Protect sensitive material.

---

# 17. Phase 9 — Protocol Discovery

Identify cryptographic protocols.

Examples:

```text
TLS
HTTPS
SSH
DTLS
IPsec
mTLS
JWT/JWS
Kerberos
PGP
S/MIME
MQTT/TLS
Database TLS
```

Record:

```text
Protocol
Version
Cipher suite
Authentication mechanism
Key exchange
Certificate
Endpoint
Evidence
```

---

# 18. Phase 10 — Cloud Discovery

Introduce cloud discovery through explicit authenticated integrations.

Potential targets:

```text
AWS
Azure
GCP
Kubernetes
```

Initial AWS examples:

```text
KMS
ACM
CloudHSM
S3 encryption
RDS encryption
EBS encryption
CloudFront
Load balancers
API Gateway
Secrets Manager
```

Do not assume permissions.

The scanner must first determine:

```text
What credentials are available?
What permissions exist?
What can actually be enumerated?
```

If permissions are insufficient, produce:

```text
PARTIAL DISCOVERY
```

rather than pretending the environment was fully scanned.

---

# 19. Phase 11 — Hardware Discovery

Support discovery of:

```text
HSM
TPM
Secure Element
Hardware Crypto Module
Cloud HSM
Crypto Accelerator
```

Record metadata:

```text
Hardware type
Vendor
Model
Firmware
Supported algorithms
Key operations
Applications using it
```

---

# 20. Phase 12 — External Discovery

External discovery should eventually support authorized enterprise-facing discovery.

Potential findings:

```text
Internet-facing TLS
Certificates
TLS configuration
Public endpoints
External APIs
Third-party crypto dependencies
```

This must have strong scope controls.

Before running active discovery:

```text
Target
Scope
Authorization
Allowed network range
Rate limits
```

If scope is ambiguous:

> STOP and ask the human.

Never automatically expand discovery beyond the explicitly authorized target.

---

# 21. External Findings Ingestion

Keep the existing JSON ingestion capability.

However, change its purpose from:

```text
External JSON
```

to:

```text
Import discovery findings
```

Supported inputs can eventually include:

```text
ECDAT JSON
CycloneDX/CBOM
Scanner exports
Cloud discovery exports
Third-party scanner results
```

The importer should map external formats into the canonical finding model.

---

# 22. Scan Job Model

Every discovery operation should become a job.

Conceptually:

```text
ScanJob
├── id
├── workspace_id
├── source_type
├── scanner_type
├── target
├── configuration
├── status
├── progress
├── findings_count
├── created_at
├── started_at
├── completed_at
├── error
└── cancellation_state
```

Statuses:

```text
QUEUED
VALIDATING
RUNNING
CANCELLING
COMPLETED
FAILED
CANCELLED
PARTIAL
```

`PARTIAL` is important.

A discovery scan can succeed technically while being incomplete because:

* Permissions were insufficient
* Files were unreadable
* Some formats were unsupported
* Network access failed
* Cloud APIs were unavailable
* A scanner timed out

---

# 23. Progress Reporting

Do not fake percentage values.

Progress should come from measurable scanner work.

For example:

```text
Files discovered: 1,204 / 5,000
```

or:

```text
Discovery stages:

Asset enumeration       ✓
Source inspection       ████████░░ 80%
Dependency analysis     ███░░░░░░░ 30%
Evidence correlation    ░░░░░░░░░░
```

If exact progress cannot be measured, use:

```text
Discovering...
```

instead of an invented percentage.

---

# 24. Finding Confidence

Every finding should have a confidence value/category.

Example:

```text
HIGH
MEDIUM
LOW
```

Or numerical confidence plus a human-readable level.

Example:

```text
RSA-2048
Evidence: direct API call
Confidence: 0.97
```

versus:

```text
Possible AES implementation
Evidence: binary signature
Confidence: 0.61
```

This becomes important later for AI reasoning.

---

# 25. Evidence Model

Every finding should answer:

> "Why does ECDAT believe this exists?"

Evidence may be:

```text
Source file + line
AST/API call
Binary symbol
Binary offset
Dependency manifest
Package metadata
Certificate fingerprint
Cloud resource
Network endpoint
Configuration
Scanner signature
External scanner report
```

Never create a finding without provenance unless it is explicitly marked as externally supplied.

---

# 26. Deduplication

The same crypto artefact may appear multiple times.

Example:

```text
OpenSSL
 ├── application A
 ├── container B
 ├── binary C
 └── dependency D
```

Do not blindly merge them.

Maintain:

```text
Artifact identity
+
Occurrences
+
Evidence
+
Relationships
```

This allows ECDAT to distinguish:

```text
One algorithm
used in
20 applications
```

from:

```text
20 unrelated findings
```

---

# 27. Discovery Relationship Graph

Build relationships during discovery.

Example:

```text
Business/Application
       ↓
Repository
       ↓
Source File
       ↓
Crypto API
       ↓
Library
       ↓
Algorithm
       ↓
Key
       ↓
Certificate
       ↓
Protocol
       ↓
Endpoint
       ↓
Infrastructure
```

This graph is one of the most important foundations for later:

* CBOM
* Risk analysis
* Migration blast radius
* PQC recommendation
* Dependency analysis
* What-if simulation

---

# 28. Do NOT Put These in Discover

Do not mix the following into the scanner:

### Quantum risk

```text
RSA is quantum vulnerable
```

The scanner can identify RSA.

Risk assessment belongs later.

### Business criticality

The scanner may discover:

```text
production-payment-service
```

but should not independently decide:

```text
business criticality = critical
```

That should come from business-context enrichment.

### Mosca assessment

Do not calculate migration urgency inside the basic scanner.

### ML migration effort

Do not perform ML scoring during discovery.

### P1–P4 priority

Do not assign final priorities during discovery.

### PQC recommendation

Discovery identifies:

```text
ECDSA P-256
```

Later reasoning determines suitable migration alternatives.

---

# 29. Discover → Understand Contract

The scanner output should be sufficient for Understand to answer:

```text
WHAT was discovered?
WHERE was it discovered?
HOW was it discovered?
HOW CONFIDENT are we?
WHAT asset does it belong to?
WHAT does it depend on?
```

Then Understand handles:

```text
Normalization
Classification
Correlation
Deduplication
Metadata enrichment
CBOM construction
```

---

# 30. UI Evolution

The current UI should eventually evolve from:

```text
Folder discovery | External findings
```

to something closer to:

```text
Discover
│
├── Scan
├── Sources
├── Findings
└── History
```

### Scan

Start a new discovery.

### Sources

Manage/configure discovery sources.

### Findings

Browse discovered artefacts.

### History

View previous discovery jobs.

Do not necessarily implement all four screens immediately.

---

# 31. New Scan UI

Recommended flow:

```text
1. Select discovery source
        ↓
2. Select scanner(s)
        ↓
3. Configure target
        ↓
4. Configure scan limits
        ↓
5. Review scope
        ↓
6. Start
        ↓
7. Monitor
```

Example:

```text
Discovery source
[ Workspace ▼ ]

Discovery engines
☑ Source Code
☑ Dependencies
☑ Certificates
☐ Binary Analysis

Target
/enterprise/project

Limits
Max files: 10,000
Max depth: 20
Max file size: 50 MB

Exclusions
node_modules/
.git/
dist/

[ Review Discovery ]
```

---

# 32. Review Before Scan

The review screen should show:

```text
Source
Workspace

Target
/project/payment-service

Engines
Source Code
Dependencies
Certificates

Estimated scope
~4,200 files

Exclusions
node_modules/
.git/

Potential limitations
Binary analysis disabled

[Start Discovery]
[Back]
```

This prevents accidental broad scans.

---

# 33. Human-in-the-Loop Rules

The AI builder MUST NOT guess when an important discovery decision is ambiguous.

Ask the human when:

### Scope is ambiguous

Example:

> "The selected workspace contains multiple projects. Should discovery scan all projects or only `payment-service`?"

### Authorization is unclear

Example:

> "This target appears to be an external endpoint. Please confirm that you are authorized to scan it."

### Credentials are required

Example:

> "AWS discovery requires credentials or an existing connection. Which configured account should be used?"

### Multiple interpretations exist

Example:

> "Two possible repository roots were detected. Which should be treated as the discovery target?"

### Destructive/high-impact operation

Never automatically perform an operation that could:

* Modify infrastructure
* Rotate keys
* Delete data
* Change certificates
* Change cloud configuration
* Deploy software

Discover should be read-only by default.

### Scanner limitation

If a scanner cannot inspect something:

```text
Do not silently ignore it.

Report:
PARTIAL DISCOVERY
Reason
Affected scope
Suggested next action
```

---

# 34. Human Questions Should Be Minimal

Do not constantly interrupt the user.

Only ask when the decision materially affects correctness, scope, security, or completeness.

Good:

> "The workspace contains 3 repositories. Scan all 3 or only `backend`?"

Bad:

> "Should I scan this file?"

when the user's scope already clearly includes it.

---

# 35. Demo Scan

Keep the demo scan.

But make it represent the actual architecture.

It should generate realistic findings such as:

```text
RSA-2048
ECDSA P-256
AES-256-GCM
SHA-256
OpenSSL
TLS 1.2
TLS 1.3
X.509 certificate
Crypto library dependency
```

The demo must clearly indicate:

```text
DEMO DATA
```

and must never be mixed with real enterprise findings.

---

# 36. Error Handling

Every scanner should return structured errors.

Example:

```json
{
  "code": "INSUFFICIENT_PERMISSION",
  "message": "Unable to inspect repository history.",
  "scope": "repository-history",
  "recoverable": true,
  "suggested_action": "Provide repository access or run a local scan."
}
```

UI should distinguish:

```text
Failed
Partial
Completed
Cancelled
```

Do not reduce everything to "Failed".

---

# 37. Security Requirements

Discovery itself is security-sensitive.

Implement:

* Workspace isolation
* Tenant isolation
* Access control
* Audit logs
* Secure credential handling
* No plaintext secret persistence
* Redaction of sensitive evidence
* Scan authorization
* Target validation
* Rate limiting
* Resource limits
* File-size limits
* Timeout handling

Most importantly:

> **Never expose discovered private keys, passwords, API tokens or cloud credentials in findings.**

---

# 38. Scan History Improvements

The existing history should eventually show:

```text
Scan ID
Source
Scanner(s)
Target
Status
Progress
Findings
Assets discovered
Started
Completed
Duration
```

Add:

```text
Partial
```

and:

```text
View findings
```

as separate actions.

---

# 39. Discovery Dashboard Metrics

Eventually the Discover page can show:

```text
Assets discovered       1,284
Crypto findings         4,921
Algorithms              37
Certificates            312
Crypto libraries        84
Protocols               16
Cloud crypto resources  72
Partial scans           3
```

These are discovery metrics only.

Do not put "High Risk" or "P1" here unless those values come from the later risk engine.

---

# 40. Implementation Order

## Milestone 1 — Foundation

Implement:

* Canonical finding model
* Asset model
* Evidence model
* Scan job model
* Scanner interface
* Scanner registry
* Job lifecycle
* Progress handling
* Cancellation
* Error/partial states

Do not add new scanners yet.

### Acceptance criteria

A scanner can:

```text
register
→ receive target
→ run
→ produce findings
→ attach evidence
→ update progress
→ finish
```

---

## Milestone 2 — Existing scanner refactor

Convert the current folder scanner into the new scanner architecture.

Rename concepts where appropriate:

```text
Folder scan
→ Workspace/source discovery

Source-code scan
→ Source discovery engine
```

Maintain existing functionality.

### Acceptance criteria

Existing users can perform the current scan workflow without regression.

---

## Milestone 3 — Source-code discovery

Add:

* Crypto API detection
* Algorithm detection
* Library detection
* Configuration detection
* Certificate detection
* Key-reference detection

Every finding must include evidence.

---

## Milestone 4 — Dependency discovery

Add dependency manifests and dependency graph.

---

## Milestone 5 — Certificate/key discovery

Add dedicated certificate and safe key-reference analysis.

---

## Milestone 6 — Binary discovery

Add:

* ELF
* PE
* Mach-O

where supported.

Then extend toward firmware/IoT.

---

## Milestone 7 — Container discovery

Add OCI/Docker image inspection.

---

## Milestone 8 — External/cloud discovery

Add authenticated integrations.

Start with one provider rather than pretending to support all providers.

---

## Milestone 9 — Protocol/network discovery

Add authorized endpoint/protocol discovery.

---

## Milestone 10 — Correlation

Create the crypto dependency graph.

---

## Milestone 11 — CBOM

Generate standardized cryptographic inventory from the normalized findings.

---

## Milestone 12 — Connect to Understand

Pass the discovery dataset into:

```text
Normalization
Classification
Business enrichment
Risk engine
PQC recommendation
ML migration estimation
Final prioritization
```

---

# 41. Definition of Done for Discover

Discover should be considered mature when it can answer:

### What exists?

```text
Assets
Applications
Repositories
Binaries
Containers
Cloud resources
Infrastructure
Hardware
Endpoints
```

### What cryptography exists?

```text
Algorithms
Keys/references
Certificates
Protocols
Libraries
Crypto APIs
Hardware crypto
Cloud crypto
```

### Where is it?

```text
Repository
File
Line
Binary
Library
Container
Cloud resource
Endpoint
Hardware
```

### How was it discovered?

```text
Static analysis
Dependency analysis
Binary analysis
Certificate analysis
Cloud API
Network/protocol analysis
External ingestion
```

### How confident are we?

```text
Evidence
Confidence
Scanner
Timestamp
```

### What is it connected to?

```text
Application
Library
Algorithm
Certificate
Key
Protocol
Infrastructure
Business asset
```

If Discover can answer those questions, the later risk and migration engines have a strong foundation.

---

# 42. Final Architecture Principle

Do not build:

```text
Folder scanner
+
Some crypto regex
+
Risk score
```

Build:

```text
                  ECDAT DISCOVERY PLATFORM

        ┌──────────────────────────────────────┐
        │          Scanner Registry            │
        └──────────────────┬───────────────────┘
                           │
       ┌───────────┬───────┼────────┬───────────┐
       ▼           ▼       ▼        ▼           ▼
     Source     Binary   Container Cloud     Network
       │           │       │        │           │
       └───────────┴───────┼────────┴───────────┘
                           ▼
                    RAW FINDINGS
                           │
                    ┌──────▼──────┐
                    │   Evidence  │
                    └──────┬──────┘
                           ▼
                    Asset Correlation
                           │
                           ▼
                  Crypto Dependency Graph
                           │
                           ▼
                       UNDERSTAND
                           │
                           ▼
                         CBOM
                           │
                           ▼
                  AI RISK & REASONING
                           │
                           ▼
                         ACTION
```

The **scanner framework is the product foundation**. Individual scanners are plugins into that framework.

---

# 43. AI Builder Operating Rules

When implementing this plan, the AI builder must follow these rules:

1. **Inspect the existing codebase before changing architecture.**
2. **Do not rewrite working functionality unnecessarily.**
3. **Preserve the current `/scans` workflow while extending it.**
4. **Create reusable scanner abstractions rather than page-specific implementations.**
5. **Do not hard-code discovery types into the UI when a registry/configuration model is appropriate.**
6. **Keep Discover separate from risk scoring.**
7. **Every finding should have provenance/evidence whenever technically possible.**
8. **Do not expose discovered secrets/private keys.**
9. **Do not silently skip unsupported artefacts; record limitations.**
10. **Represent incomplete scans as `PARTIAL`, not automatically `FAILED`.**
11. **Do not fake progress percentages.**
12. **Do not perform external/network/cloud discovery without an explicit authorized scope.**
13. **Ask the human whenever scope, authorization, credentials, destructive impact, or an important architectural decision is ambiguous.**
14. **Prefer incremental implementation over a large rewrite.**
15. **After each milestone, run existing tests and verify that existing `/scans` functionality still works.**
16. **Do not invent integrations, scanner capabilities, cloud permissions, or supported file formats.**
17. **If the existing architecture conflicts with this plan, explain the conflict and ask the human before making a large architectural change.**
18. **Keep the UI terminology enterprise-neutral: use discovery source, asset, target, finding, evidence and scanner rather than assuming everything is a local folder/source-code scan.**
19. **When a requirement cannot be implemented reliably, stop at the boundary and ask the human rather than creating a simulated implementation.**
20. **Maintain a clear separation between discovered facts and later AI-derived conclusions.**

---

# 44. Human Escalation Template

Whenever human input is genuinely required, use this format:

> **Decision required**
>
> **What I found:** [concise factual observation]
>
> **Why it matters:** [impact on implementation/scope]
>
> **Options:**
>
> 1. [Option A]
> 2. [Option B]
>
> **Recommended default:** [only an implementation default, not a business/risk judgment]
>
> **Please choose:** [specific question]

If the decision can safely be made from existing requirements, do not ask.

---

# 45. Immediate Next Task

Before implementing new scanners, inspect the current `/scans` implementation and produce:

1. Current frontend component tree
2. Current backend/API structure
3. Current scan-job database schema
4. Current finding schema
5. Current scanner implementation
6. Current polling/cancellation mechanism
7. Current workspace/session isolation
8. Existing tests
9. Existing reusable UI components
10. Any architectural limitations preventing the scanner-registry model

Then produce a short:

```text
CURRENT ARCHITECTURE
        ↓
GAPS
        ↓
REQUIRED CHANGES
        ↓
MILESTONE 1 IMPLEMENTATION
```

**Do not start a large refactor until this assessment is complete.**

If any of the above cannot be determined from the codebase, ask the human for the missing information instead of guessing.
