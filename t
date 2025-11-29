### 1. AI Lifecycle Security Controls

#### 1.1 Model Supply-Chain & Integrity

**SC-LC-001: Cryptographic Verification of Imported Models**
* **Description:** Implement a strict "Deny-by-Default" admission controller in the Model Ops pipeline. Before any model artifact (weights, config files, tokenizers) enters the internal MinIO storage, the system must validate its cryptographic signature against a trusted internal root of trust or a pre-approved vendor key (e.g., Hugging Face Verified Organization GPG keys). This process must verify not just the file integrity (hash check) but also the signer's identity. If a model lacks a signature or the signature does not match the allowed allow-list of signers, the ingestion pipeline must strictly reject the artifact and trigger a security alert.
* **Rationale:** Prevents Model Supply Chain Compromise (MITRE ATLAS AML.T0010) and tampering with model weights which could introduce backdoors.
* **Priority:** **Must-Have**
* **Primary Component:** MinIO / CI/CD Pipeline
* **Implementation:** Use tools like GPG or Sigstore (Cosign). Reject any `.pt`, `.bin`, or `.safetensors` file without a valid matching signature file.

**SC-LC-002: Static Analysis for Model Serialization Attacks**
* **Description:** Mandate a comprehensive static analysis scan of all model files within an ephemeral, sandboxed environment prior to storage. This scan must specifically target known serialization vulnerabilities, such as Python `pickle` logic that allows arbitrary code execution upon loading. The scanner must traverse the model file structure to identify suspicious opcodes, unauthorized import calls (e.g., `os.system`, `subprocess`), or "zip bombs" designed to exhaust system memory. The system should enforce the use of safer serialization formats like `safetensors` wherever possible and flag usage of `pickle` as a high-severity exception requiring manual security officer approval.
* **Rationale:** Mitigates Arbitrary Code Execution via compromised model files (OWASP LLM05).
* **Priority:** **Must-Have**
* **Primary Component:** Ingestion Pipeline (prior to MinIO)
* **Implementation:** Utilize scanners like `Picklescan` or `ModelScan`. Mandate the use of `safetensors` format over `pickle` where technically feasible.

#### 1.2 Model Validation & Testing

**SC-LC-003: Adversarial Red Teaming & Stress Testing**
* **Description:** Conduct systematic, automated adversarial testing sessions against the model endpoint in a staging environment. This involves subjecting the model to a battery of attack vectors, including "Do Anything Now" (DAN) prompts, suffix attacks, polyglot injection attempts, and competitive probing to extract memorized training data (PII extraction). The process must measure the model's refusal rate against a predefined safety baseline. A model version cannot be promoted to production unless it achieves a specific pass rate (e.g., >99% refusal of known jailbreaks) and demonstrates resilience against high-volume input fuzzing.
* **Rationale:** Identifies vulnerabilities to Prompt Injection (OWASP LLM01) and Model Denial of Service (OWASP LLM04).
* **Priority:** **Must-Have**
* **Primary Component:** Alibaba OpenTrek (Staging Env)
* **Implementation:** Integrate tools like Giskard or PyRIT into the testing pipeline to automate prompt injection attacks against the candidate model.

#### 1.3 RAG-Specific Security Controls

**SC-LC-004: Context-Aware Access Control List (ACL) Propagation**
* **Description:** Enforce a "Zero Trust" data retrieval model where the RAG pipeline validates user permissions at the point of query, not just at the application front-end. When a user submits a prompt, the system must extract their identity tokens (e.g., OIDC/JWT claims). These claims must be passed down to the vector database query execution. The database must filter search results so that chunks are only retrieved if the user has read-access to the *original source document*. This ensures that even if a chunk is semantically relevant, it is physically excluded from the context window if the user lacks the necessary entitlements, preventing the LLM from summarizing confidential documents the user shouldn't see.
* **Rationale:** Prevents Sensitive Information Disclosure (OWASP LLM06) and Broken Access Control.
* **Priority:** **Must-Have**
* **Primary Component:** pgvector / Elasticsearch / Alibaba OpenTrek
* **Implementation:** Store Access Control Lists (ACLs) or Role IDs as metadata alongside vector embeddings. Enforce filtering queries in `pgvector` and `Elasticsearch` using the authenticated user's JWT claims.

**SC-LC-005: RAG Data Sanitization & PII Redaction**
* **Description:** Deploy a dual-phase data sanitization engine. **Phase 1 (Ingestion):** Scan all incoming documents for high-sensitivity patterns (Credit Card Numbers, IBANs, Tax IDs) and redact or tokenize them *before* embedding and indexing. **Phase 2 (Inference):** Implement an output scanner that analyzes the LLM's generated response for leaked PII or toxic content before it is returned to the user. This ensures that even if the model "hallucinates" a credit card number or retrieves a missed piece of PII, it is masked in real-time before reaching the UI.
* **Rationale:** Mitigates Data Leakage and non-compliance with GLBA/GDPR/DORA.
* **Priority:** **Should-Have**
* **Primary Component:** Ingestion Pipeline / OpenTrek Output Guardrails
* **Implementation:** Use NLP-based PII analyzers (e.g., Microsoft Presidio) in the ingestion pipeline.

#### 1.4 Inference / Serving Security Controls

**SC-LC-006: Input Guardrails & Prompt Injection Defense**
* **Description:** Establish a dedicated AI Security Gateway layer that intercepts all API traffic destined for the model serving infrastructure. This layer performs deep inspection of input prompts to detect malicious intent. This includes heuristic checks for prompt injection patterns (e.g., "Ignore previous instructions"), token length anomalies, and hidden character attacks. It should also perform semantic analysis to classify the *intent* of the prompt; if the intent is classified as "malicious" or "jailbreak attempt," the request is blocked immediately, and an alert is generated without the prompt ever reaching the expensive model inference layer.
* **Rationale:** Mitigates Prompt Injection (OWASP LLM01) and Jailbreaking (MITRE ATLAS AML.T0054).
* **Priority:** **Must-Have**
* **Primary Component:** Alibaba OpenTrek / API Gateway
* **Implementation:** Implement "Nvidia NeMo Guardrails" or "Lakera Guard" logic within the OpenTrek serving layer to intercept and sanitize prompts.

**SC-LC-007: Inference Rate Limiting & Resource Quotas**
* **Description:** Implement granular, identity-based rate limiting to protect GPU resources. This goes beyond simple HTTP request throttling; it limits the *compute cost* allowed per user. Controls should define maximum tokens generated per minute, maximum concurrent requests per tenant, and strict timeouts for inference operations. This prevents "noisy neighbor" scenarios where one malicious or buggy application consumes all available GPU memory, causing a Denial of Service for critical banking applications sharing the platform.
* **Rationale:** Mitigates Model Denial of Service (OWASP LLM04).
* **Priority:** **Must-Have**
* **Primary Component:** Alibaba OpenTrek
* **Implementation:** Configure token-bucket rate limiting at the API Gateway level; set hard timeout limits on model inference execution.

#### 1.5 Monitoring, Auditing & Explainability

**SC-LC-008: Full Traceability & Audit Logging (Prompts/Responses)**
* **Description:** Create a tamper-evident audit trail that captures the complete interaction lifecycle. Every log entry must link the **User Identity**, **Timestamp**, **Input Prompt** (sanitized if necessary), **Retrieved Context IDs** (which documents were used), **Model Version Hash**, **Hyperparameters** (Temperature/Top-P), and the **Generated Response**. These logs must be shipped asynchronously to a WORM (Write-Once-Read-Many) compliant storage bucket to prevent modification by administrators or attackers covering their tracks.
* **Rationale:** Essential for Forensics, Regulatory Reporting (DORA/EU AI Act), and detecting Model Theft or Abuse (OWASP LLM10).
* **Priority:** **Must-Have**
* **Primary Component:** PostgreSQL (Metadata) / MinIO (Log Storage)
* **Implementation:** Middleware in OpenTrek that asynchronously writes request/response pairs to MinIO (WORM locked) and metadata to Postgres.

---

### 2. Platform Component AI-Specific Hardening



#### 2.1 MinIO – Model and Data Integrity

**SC-PC-001: Object Locking (WORM) for Model Artifacts**
* **Description:** Enable strict **Compliance Mode** Object Locking on MinIO buckets designated for "Golden" model artifacts and audit logs. In Compliance Mode, not even the root user can delete or overwrite the objects until the retention period (e.g., 7 years for logs, indefinite for released models) expires. This creates an immutable history of exactly which model binaries were deployed at any point in time, critical for post-incident forensics.
* **Rationale:** Prevents ransomware or malicious insiders from altering or deleting approved models/logs.
* **Priority:** **Must-Have**
* **Implementation:** Enable MinIO Object Locking in "Compliance Mode" with a retention period matching bank policy (e.g., 7 years).

**SC-PC-002: Server-Side Encryption (SSE-KMS)**
* **Description:** Enforce mandatory Server-Side Encryption (SSE) for all objects using Key Management Service (KMS). The system must use a dual-key envelope encryption architecture: MinIO generates a Data Encryption Key (DEK) for the object, and that DEK is encrypted using a Key Encryption Key (KEK) stored securely in the bank’s Hardware Security Module (HSM). This ensures that if physical drives are stolen or decommissioned improperly, the data remains cryptographically unrecoverable.
* **Rationale:** Data Confidentiality.
* **Priority:** **Must-Have**
* **Implementation:** Configure MinIO with SSE-KMS utilizing the bank's standard KMS provider.

#### 2.2 Elasticsearch – Secure Document Retrieval

**SC-PC-003: Field-Level Security & Document Level Security (DLS)**
* **Description:** Configure granular Role-Based Access Control (RBAC) within Elasticsearch using Document Level Security (DLS). This involves defining query templates that automatically append filter clauses to every search request based on the user's role. For example, a query from a "Retail Banker" will transparently be rewritten by the engine to include `AND department == 'Retail'`. This ensures that security logic is enforced by the database engine itself, preventing application-layer bugs from exposing unauthorized data.
* **Rationale:** Prevents unauthorized data access via search bypassing.
* **Priority:** **Must-Have**
* **Implementation:** Map LDAP/AD groups to Elasticsearch Roles and define DLS queries (e.g., `{"term": {"department": "user_dept"}}`).

**SC-PC-004: Disable Dynamic Scripting**
* **Description:** Explicitly disable or strictly limit the execution of dynamic scripts (e.g., Painless, Groovy) within search queries. If scripting is required for custom scoring of search results, only allow pre-stored, administrator-reviewed scripts identified by ID. Dynamic inline scripting is a common vector for Remote Code Execution (RCE) in search engines and must be turned off to reduce the attack surface.
* **Rationale:** Reduces attack surface for injection attacks.
* **Priority:** **Should-Have**
* **Implementation:** Set `script.allowed_types: none` or restrict to stored scripts only in `elasticsearch.yml`.

#### 2.3 pgvector – Vector Store Access Control & Anti-Leakage

**SC-PC-005: Row-Level Security (RLS) on Vector Tables**
* **Description:** Implement native PostgreSQL Row-Level Security (RLS) on the tables storing high-dimensional vector embeddings. The RLS policy acts as a mandatory firewall for every `SELECT` query. Before the database engine performs the computationally expensive similarity search (e.g., Cosine Similarity), it filters the eligible rows based on the `user_id` or `group_id` of the current SQL session. This guarantees that a user cannot mathematically discover the existence of a sensitive document through vector proximity if they do not have read access to it.
* **Rationale:** The deepest layer of defense against Data Leakage in RAG.
* **Priority:** **Must-Have**
* **Implementation:** `CREATE POLICY vector_access ON embeddings FOR SELECT USING (group_id = current_setting('app.current_user_group'));`

**SC-PC-006: IVFFlat/HNSW Index Isolation**
* **Description:** Physically isolate vector indexes by storing them in dedicated PostgreSQL Tablespaces mapped to separate, encrypted storage volumes (LUNs). This ensures that heavy I/O operations associated with vector search do not impact the performance of transactional tables (metadata), and provides an additional layer of physical security—if the storage volume for the "Private Banking" vectors is unmounted, that data is physically inaccessible to the database instance.
* **Rationale:** Defense in depth for physical media theft.
* **Priority:** **Nice-to-Have**
* **Implementation:** PostgreSQL Tablespace management.

#### 2.4 Redis – Cache Security for AI Workloads

**SC-PC-007: Encrypted Semantic Caching**
* **Description:** If Redis is used for "Semantic Caching" (storing previous LLM prompts and responses to save costs on similar future queries), the entire cache layer must be treated as highly sensitive. Implement TLS 1.3 for all data in transit and enable transparent disk encryption for Redis persistence files (RDB/AOF). Additionally, the application should hash or encrypt the cache keys if they contain raw prompt text to prevent visibility into user queries by Redis administrators.
* **Rationale:** Cache Poisoning and Sensitive Data Leakage. LLM responses often contain summarized PII.
* **Priority:** **Must-Have**
* **Implementation:** Enable Redis TLS/SSL and configure disk encryption if persistence is enabled.

**SC-PC-008: Strict TTL for Conversation History**
* **Description:** Configure aggressive Time-To-Live (TTL) expiration policies for all conversation history keys stored in Redis. This ensures that sensitive chat contexts are ephemeral and are automatically purged from memory after the user session ends or after a short inactivity period (e.g., 15 minutes). This reduces the "blast radius" if the Redis instance is compromised or memory-scraped, as long-term history is not resident in memory.
* **Rationale:** Minimizes the window of opportunity for session hijacking attacks to retrieve past conversation context.
* **Priority:** **Should-Have**
* **Implementation:** Set global TTL defaults or application-level logic to expire keys after user session inactivity (e.g., 15 minutes).

#### 2.5 PostgreSQL – Model Registry & Provenance Protection

**SC-PC-009: Immutable Audit Trails (pgaudit)**
* **Description:** Deploy the `pgaudit` extension to capture a granular, immutable log of all Data Definition Language (DDL) and Data Modification Language (DML) operations performed on the Model Registry. This includes logging exactly *who* changed a model's status from "Staging" to "Production" and the precise SQL statement used. These logs provide the legal proof of non-repudiation required by banking auditors to verify that no unapproved models were surreptitiously activated.
* **Rationale:** Accountability for Model Governance.
* **Priority:** **Must-Have**
* **Implementation:** Configure `pgaudit` extension to log `WRITE` and `DDL` on the `model_registry` schema.

#### 2.6 Alibaba OpenTrek – Agent, API & Prompt Security

**SC-PC-010: Egress Filtering & SSRF Protection**
* **Description:** Enforce a strict "No Egress" network policy for the Alibaba OpenTrek serving environment. The inference containers must be air-gapped from the public internet to prevent "Indirect Prompt Injection" attacks where the model is tricked into fetching malicious external URLs (SSRF) or exfiltrating internal data to an attacker-controlled server. Any required external connectivity (e.g., to a specific internal API) must be explicitly allow-listed by destination IP and port.
* **Rationale:** Prevents Server-Side Request Forgery (SSRF) and data exfiltration (MITRE ATLAS AML.T0024).
* **Priority:** **Must-Have**
* **Implementation:** Network firewalls blocking 0.0.0.0/0 egress; OpenTrek configuration to disable arbitrary URL fetching.

**SC-PC-011: Multi-Tenancy Isolation**
* **Description:** Leverage the native multi-tenancy capabilities of the platform to logically isolate different banking units (e.g., Retail vs. Wealth Management). This involves utilizing Kubernetes namespaces, separate service accounts, and distinct storage paths for each tenant. Ensure that a model loaded into memory for Tenant A cannot be queried by Tenant B's API keys, and that shared caches (like Redis) are namespaced or physically separated to prevent cross-tenant data leakage.
* **Rationale:** Internal segregation of duties (Chinese Wall).
* **Priority:** **Should-Have**
* **Implementation:** Use OpenTrek's native multi-tenancy/namespace features mapped to Kubernetes namespaces or separate service instances.
