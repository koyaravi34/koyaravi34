1.2 In-Scope / Out-of-Scope

In scope:

Deployment of DSPM Orchestrator(s) in AWS (in one or more accounts).

Establishing IAM roles / permissions (read-only, scanner roles) in target AWS accounts.

Network connectivity (VPCs, peering, NAT, security groups).

Configuration of data source integrations (S3, RDS, Redshift, etc.).

Enabling required logging and data flow (CloudTrail, CloudWatch, etc.).

Establishing baseline security, monitoring, alerting, and operational procedures.

Documentation, testing, knowledge transfer.

Out of scope (for first version):

Deployment in non-AWS clouds (unless multi-cloud is a later phase).

Deep remediation automation (beyond detection and alerting).

Custom classifier creation (though may be enabled later).

Integration with third-party ticketing / orchestration (unless explicitly requested).

2. Architecture & Components

From public documentation, DSPM in AWS typically comprises the following:

2.1 DSPM Components (AWS)

Orchestrator: Deployed in AWS (e.g. EC2) within a “security / tooling” account or in each monitored account. It performs scanning and classification. 
docs.dig.security
+2
docs.prismacloud.io
+2

Read-Only Permissions / IAM Role: In each monitored AWS account, a least-privilege IAM role that allows DSPM to enumerate AWS resources (S3 buckets, databases, etc.) and ingest metadata. 
docs.dig.security
+2
docs.prismacloud.io
+2

Scanner Permissions / IAM Role: For accounts where scanning of unmanaged assets is required, roles with required permissions to access storage volumes, DB engine metadata, or file systems. 
docs.dig.security
+3
docs.dig.security
+3
docs.prismacloud.io
+3

Networking / VPC / NAT / Peering: The Orchestrator must have network connectivity to target accounts and possibly to on-prem or file shares. Use of NAT, peering, or public egress (Elastic IP) is required. 
docs.prismacloud.io
+2
docs.prismacloud.io
+2

Logging & Event Ingestion: Enable CloudTrail, CloudWatch, S3, or other logs so that DSPM’s DDR engine can detect anomalous data events. 
docs.dig.security
+3
docs.dig.security
+3
docs.prismacloud.io
+3

Secret Management / Credential Storage: Use AWS Secrets Manager or parameter store to store credentials (e.g. for on-prem file share, database access) securely. 
docs.prismacloud.io
+1

Connectivity to External / On-Prem File Shares / Datastores (if required): For scenarios where file shares or other non-cloud assets are in scope. 
docs.prismacloud.io
+1

2.2 Deployment Topologies & Options

Single Orchestrator vs multiple per region.

Orchestrator placed in a dedicated Security / Tooling AWS account vs in each monitored account.

Use of cross-account IAM trust (delegation) to allow scanning from central Orchestrator.

Use of VPC peering or Transit Gateway for network connectivity across accounts / regions.

Use of public egress (Elastic IP / NAT Gateway) for Orchestrator to communicate with DSPM backend or external services (if needed). 
docs.prismacloud.io
+1

2.3 Data Flow & Control Flow

Orchestrator invokes AWS APIs via IAM roles in target accounts to enumerate and fetch metadata of managed assets.

For unmanaged assets (e.g. DB on EC2), Orchestrator connects to volumes / instances (with scanner role) to scan content (in a read-only mode) and apply classification.

Classification results, metadata, and findings are sent (only metadata, no raw data) to the DSPM backend (hosted by Prisma) or collection service.

DSPM dashboards, alerts, risk scoring, etc., operate on those metadata and classification results.

DDR accesses logs / event streams (CloudTrail, S3 events, etc.) to detect anomalies or exfiltration patterns.

3. Requirements & Prerequisites

Below is a consolidated requirements checklist.

Category	Requirement	Notes / Comments
AWS Accounts Structure	A tooling / security account (or designated account) to host Orchestrator	Centralized or per account model, depending on scale
IAM & Permissions	Creation of IAM roles in monitored accounts: read-only and scanner roles	Use least privilege; limit permissions. DSPM only needs metadata, not write access. 
docs.prismacloud.io
+2
docs.prismacloud.io
+2

IAM Trust / Delegation	Cross-account trust so Orchestrator account can assume roles in target accounts	
VPC & Networking	VPC for Orchestrator with required subnet(s), NAT, routing tables, IGW/EIP or peering	If on-prem / external connectivity is needed, set up peering/NAT etc. 
docs.prismacloud.io
+2
docs.prismacloud.io
+2

Security Groups / NACLs	Allow outbound connectivity (for metadata upload, control plane) and inbound if management access is needed	Use strict rules
NAT / Internet Egress	If Orchestrator needs to talk to DSPM backend, require egress (NAT with public IP) or use proxy	
Logging / Monitoring	Enable CloudTrail, S3 access logs, CloudWatch, etc. in monitored accounts	Required for DDR and auditing. 
docs.dig.security
+1

Secrets Management	Use AWS Secrets Manager or KMS to store credentials (for DBs, file shares)	When connecting to on-prem or file shares, password storage needed. 
docs.prismacloud.io
+1

OS / Instance Requirements	Orchestrator EC2 instance sizing, OS, disk/io, capacity planning	Must meet performance for scanning workloads.
Network Connectivity to Data Sources	If databases, file shares, or other data stores are in private subnets or on-prem, ensure connectivity (VPN, Direct Connect, VPC peering)	
Security / Compliance	Ensure encrypted in transit, endpoint security, patching	
High Availability / DR	Plan redundancy for Orchestrator (multi-AZ) and backup / recovery strategy	
Testing & Validation	Plan for staging environment, test scans, validate results	
Access Control / RBAC	Define user roles in DSPM console (administrators, data owners, auditors)	
Scalability & Growth	Plan for adding new AWS accounts, future cloud providers, increased data volumes	

Additionally, the official Prisma docs note that for file shares, DSPM requires a user account (e.g. in AD) and network connectivity between the orchestrator and file share systems (via internet / peering). 
docs.prismacloud.io
+1

4. Deployment Steps (High Level)

Here's a proposed stepwise plan. In the Word deliverable you can have more narrative; in Excel you can have a project plan with timelines, dependencies, owners.

Step	Description	Deliverable / Output	Dependencies / Prereqs
1	Kickoff & Requirements Gathering	Finalized scope, list of AWS accounts, data sources, connectivity maps	Stakeholder inputs
2	AWS Account Setup & Networking	Create VPC, subnets, NAT / EIP or peering, routing, security groups	Networking team input
3	Instance Provisioning	Provision EC2 instance(s) for Orchestrator in designated account	IAM, networking in place
4	IAM Role Setup in Monitored Accounts	Create cross-account IAM roles (read-only, scanner) with trust policies	Access to target accounts
5	Orchestrator Installation / Registration	Install or enable DSPM Orchestrator, register it with DSPM platform	Access to DSPM portal / license
6	Secrets / Credentials Setup	Configure AWS Secrets Manager or other secret stores for DB / file share credentials	Access / accounts ready
7	Configure Data Sources	In DSPM console, onboard AWS accounts, set up connectors/integrations for S3, RDS, etc.	IAM roles active, network ready
8	Run Initial Discovery / Scan	Execute full scan, classify data, assess baseline	Monitor performance, logs
9	Enable DDR / Monitoring	Hook up event sources (CloudTrail, S3 logs), validate anomaly detection	Logging enabled
10	Validate & Tune	Validate scan results, tune classifiers, prune false positives, refine roles	Security / data owner review
11	Set up Alerts / Notifications	Configure thresholds, alerts, dashboards, integration to SIEM / ticketing	DSPM capabilities / APIs
12	Operational Readiness / Handover	Document runbooks, backup, DR, training, support process	Completed deployment
13	Rollout to Additional Accounts / Regions	Add new accounts, scale scanning and orchestration	Experience / tweaks

You may break these further into sub-tasks, dates, owners, etc., in Excel.

5. Risks & Considerations

Network latency / bandwidth: Scanning large datasets across VPCs / accounts could incur performance or network bottlenecks.

IAM misconfiguration: Granting overly broad permissions is a risk; ensuring least privilege is critical.

Data leakage / privacy: Only metadata should leave customer environment — ensure no raw data is exfiltrated.

Scaling & performance: As data grows, the Orchestrator may need resource tuning or horizontal scaling.

Compatibility & connectivity: On-prem file shares, legacy DBs, or databases in isolated networks may need special connectivity (VPN, Direct Connect).

DR / backup: Orchestrator state, secrets, configurations must be backed up and recoverable.

Operational burden: Ongoing maintenance, patching, classifier updates, false positive tuning.

Cost management: EC2, data transfer, storage costs must be monitored.

6. Proposed Document Structure
Word Document (Design & Narrative)

Introduction / Purpose

Scope, Objectives, In/Out of Scope

Logical Architecture & Components

Data Flow Diagrams

Detailed Requirements & Constraints

Deployment Plan & Phases

Risks, Mitigations, Assumptions

Operational / Support Plan & Next Steps

Appendices (e.g. AWS account mappings, connectivity diagram)

Excel Workbook

Tab 1: Project Plan / Gantt (Steps, Start/End, Duration, Owner, Dependencies)

Tab 2: Requirement Checklist / Traceability (Requirement, Status, Owner)

Tab 3: IAM Role Matrix (account, role name, permissions, trust relationships)

Tab 4: Network / VPC Design (VPCs, subnets, peering, NAT, routing)

Tab 5: Data Sources Onboarding (account, service, connector status, issues)

Tab 6: Risks / Mitigations (Risk, Likelihood, Impact, Mitigation, Owner)
