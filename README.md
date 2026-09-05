# Vault → AWS credentials, with no secrets in your application

Working reference implementations for delivering AWS credentials to a workload without ever
placing a secret in the application, its image, its manifest or its repository.

- **Phase 1 — rotate what you already have.** Vault takes ownership of an *existing* IAM
  user's access key and replaces it on a schedule. The IAM user, its ARN and its policies are
  untouched. This maps directly onto a fleet of long-lived access keys rotated by hand today.
- **Phase 2 — remove the standing credential.** Workloads receive a just-in-time credential
  that Vault mints on demand and that expires by itself.

Everything runs against real Vault and real AWS. Each implementation presents as a single
browser page so the behaviour is visible without switching windows.

---

## Choose an implementation

All three share the AWS resources, the secrets engine, the roles and the policy configured in
sections 3 and 4 below. They differ only in **how the credential reaches the workload**.

| | Platform | The application contains | Start here if |
|---|---|---|---|
| **[kubernetes-agent-injector/](kubernetes-agent-injector/)** | Kubernetes | **no Vault code** — a sidecar writes credentials to files | you run Kubernetes and want the production pattern |
| **[ec2/](ec2/)** | EC2 / any VM | **no Vault code** — Vault Agent writes credentials to files | your workloads are virtual machines, not containers |
| **[kubernetes-direct-api/](kubernetes-direct-api/)** | Kubernetes | login, token handling and API calls | you want every step visible for explanation |

The first two are the same design on different platforms, and the point of having both is that
**the developer experience does not change when the platform does** — in each case the
application reads a file. The third exists because seeing the login, the token and each
credential read on screen explains *what is happening* better than a file appearing.

---

## Placeholder values

**Every environment-specific value in this repository is a placeholder.** Replace them with
your own before running anything. Nothing here is a real address, account or credential.

| Placeholder | What it stands for |
|---|---|
| `vault.example.com` | Your Vault address |
| `apps` | Vault Enterprise namespace holding the secrets engine. Omit `-namespace` entirely on Vault Community Edition |
| `111122223333` | AWS account containing the IAM users, roles and policies |
| `444455556666` | AWS account running the Kubernetes cluster (may be the same account) |
| `my-cluster` | EKS cluster name |
| `demo-apps` | Kubernetes namespace the workload runs in |
| `aws-demo` | Mount path of the AWS secrets engine |
| `demo-app` | Used throughout as the ServiceAccount, IAM user, Vault role and static role name |
| `kubernetes` | Mount path of the Kubernetes auth method |
| `demo-data-a1b2c3d4`, `demo-logs-a1b2c3d4` | S3 buckets the workload lists to prove authorization |
| `AKIAIOSFODNN7EXAMPLE`, `ASIAIOSFODNN7EXAMPLE`, `AIDAIOSFODNN7EXAMPLE` | Example AWS identifiers |
| `EXAMPLED539D4633E53DE1B71EXAMPLE` | Example EKS OIDC provider ID |

The demo spans two AWS accounts because the Kubernetes cluster and the IAM resources are
commonly separated. If yours are in one account, use the same value for both.

---

## 1. How Vault authenticates to AWS

Vault issues AWS credentials to workloads, which means Vault itself needs a way to reach the
AWS API. Removing static keys from applications only counts for something if you also know
what the system doing the removing holds — so that is where this documentation starts.

This section sets out the four available options, which one this demo runs, and how to reach
the strongest of them. The running demo reports its own answer in a band beneath the page
header, read from `aws-demo/config/root` at runtime rather than from documentation.

### Two credentials, two different jobs

Two separate AWS credentials are involved in this design, and they do different things. The
table below shows what each one is for, where it is kept, who can read it and how long it
lasts.

| | **Vault's own credential** (used by Vault to create and replace keys on your behalf) | **The workload's credential** (used by your application to do its work in AWS) |
|---|---|---|
| Where it is kept | inside Vault, at `aws-demo/config/root` | in a file inside the pod, only while the pod is running |
| Who can read it | nobody — not your team, and not an administrator | only the application that asked for it |
| How long it lasts | long-lived, but Vault can replace it at any time without anyone handling it | 60 seconds (Phase 1) or 15 minutes (Phase 2) |

`aws-demo` is the path the AWS secrets engine is mounted at in Vault. The steps to configure
it are in section 4.

> **Vault's own credential is never handed to an application.**

### The four ways to configure it

These are set on `aws-demo/config/root` and are mutually exclusive.

| | How Vault authenticates | Static secret held? | Works outside AWS? |
|---|---|---|---|
| **Static key** | `access_key` + `secret_key` you supply | Yes — one, and you have seen it | Yes |
| **Self-rotated key** | the same, then `config/rotate-root` | Yes — but Vault generated it and nobody has seen it | Yes |
| **Ambient identity** | leave the keys unset; the AWS SDK chain picks up IRSA, EKS Pod Identity or an instance profile | No | **No** — AWS only |
| **Workload identity federation** | `role_arn` + `identity_token_audience` | No | Yes |

The last column is the deciding one. Ambient identity is excellent when Vault runs inside AWS,
but it is a platform-specific answer. Workload identity federation is the only option that
removes the static credential *and* keeps working when Vault runs on-premises or in another
cloud.

**This demo uses the self-rotated key**, which is the most portable starting point:

```bash
# supply a bootstrap credential once...
vault write aws-demo/config/root \
    access_key="AKIAIOSFODNN7EXAMPLE" \
    secret_key="<bootstrap secret>" \
    region=us-east-1

# ...then hand it straight back to Vault
vault write -f aws-demo/config/rotate-root
```

After that second command, Vault has generated a replacement key, stored the secret in its own
storage and deleted the original. The secret half no longer exists outside Vault, and Vault
does not return `secret_key` to anyone — a root token included. This can be confirmed at any
time with `vault read aws-demo/config/root`, which returns the access key ID and no secret.

> Rotation requires Vault's key to be the **only** access key on that IAM user, and AWS caps a
> user at two. Delete any other key on the user first.

### Workload identity federation

The recommended destination. Instead of holding a key, Vault proves who it is with a signed
token and AWS returns temporary credentials.

Vault Enterprise runs its own OIDC identity provider. Every namespace publishes a standard
discovery document and a public JWKS, both unauthenticated and containing only public keys:

```
https://vault.example.com/v1/apps/identity/oidc/plugins/.well-known/openid-configuration
https://vault.example.com/v1/apps/identity/oidc/plugins/.well-known/keys
```

1. **Register Vault as an identity provider in AWS IAM**, pointing at that issuer URL, with an
   audience of your choosing and the TLS chain's CA thumbprint.
2. **Create an IAM role** whose trust policy permits `sts:AssumeRoleWithWebIdentity` from that
   provider, conditioned on the audience, carrying the permissions Vault needs.
3. **Configure the engine** with `identity_token_audience` and `role_arn`, and no keys.
4. **At runtime** Vault mints a short-lived JWT describing the plugin, calls
   `sts:AssumeRoleWithWebIdentity`, and AWS verifies the signature against Vault's published
   keys and returns temporary credentials — one hour, refreshed automatically.

```bash
vault write aws-demo/config/root access_key="" secret_key="" \
    identity_token_audience="vault-aws-demo" \
    role_arn="arn:aws:iam::111122223333:role/vault-wif" \
    region=us-east-1
```

Note the empty strings: `config/root` merges rather than replaces, so an existing static key
must be cleared explicitly in the same write.

There is no AWS credential in Vault's configuration to steal, leak or rotate. Trust is
cryptographic rather than a shared secret, and revocable from the AWS side alone — delete the
identity provider and Vault's access ends immediately. Requires Vault Enterprise, and the
issuer must be reachable from AWS.

**This changes only how the engine authenticates.** Phase 1 and Phase 2 behave identically
either way — same roles, same rotation, same leases, same API.

---

## 2. Prerequisites

- Vault Enterprise, unsealed, reachable from the cluster.
- The **Vault Agent Injector** installed (it ships with the official Vault Helm chart:
  `injector.enabled=true`).
- A Kubernetes cluster, and `kubectl` access to it.
- An AWS account where you can create IAM users, roles and policies.
- An **existing IAM user** for Phase 1. Vault rotates an existing user's key; it does not
  create the user.

---

## 3. Configure AWS

Policy documents are in [`aws/`](aws/). Replace the account ID first.

```bash
export ACCT=111122223333

# What the workload may do. Deliberately minimal: prove identity, prove authorization.
aws iam create-policy --policy-name workload-policy \
  --policy-document file://aws/workload-policy.json

# What Vault may do. Scoped to named entities only - not an administrator credential.
aws iam create-policy --policy-name vault-permissions-policy \
  --policy-document file://aws/vault-root-policy.json

# Phase 1 target: stands in for a manually rotated key you already have.
aws iam create-user --user-name demo-app
aws iam attach-user-policy --user-name demo-app \
  --policy-arn arn:aws:iam::$ACCT:policy/workload-policy
aws iam create-access-key --user-name demo-app

# Vault's own identity.
aws iam create-user --user-name vault-root
aws iam attach-user-policy --user-name vault-root \
  --policy-arn arn:aws:iam::$ACCT:policy/vault-permissions-policy
aws iam create-access-key --user-name vault-root      # bootstrap only; rotated away below

# Phase 2 target: the role Vault assumes on demand.
aws iam create-role --role-name dynamic-role \
  --assume-role-policy-document file://aws/dynamic-role-trust-policy.json \
  --max-session-duration 3600
aws iam attach-role-policy --role-name dynamic-role \
  --policy-arn arn:aws:iam::$ACCT:policy/workload-policy
```

Optionally create two S3 buckets so `s3:ListAllMyBuckets` returns something real.

---

## 4. Configure the Vault AWS secrets engine

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps          # omit on Community Edition
```

### 4.1 Enable and configure the AWS secrets engine

```bash
vault secrets enable -path=aws-demo aws

vault write aws-demo/config/root \
    access_key="AKIAIOSFODNN7EXAMPLE" \
    secret_key="<the vault-root bootstrap secret>" \
    region=us-east-1

# Governs iam_user credential TTLs. Without this they inherit the system default (~32 days).
vault write aws-demo/config/lease lease=15m lease_max=1h

# Hand the bootstrap credential back to Vault. From here nobody has seen the secret.
vault write -f aws-demo/config/rotate-root
```

### 4.2 Define the credentials

```bash
# Phase 1 - take ownership of an existing IAM user's access key.
# 1m is a demo value; production would use rotation_schedule (cron, Enterprise).
vault write aws-demo/static-roles/demo-app \
    username=demo-app \
    rotation_period=1m

# Phase 2 - just-in-time credentials by assuming a role. No IAM entity is created.
vault write aws-demo/roles/dynamic-sts \
    credential_type=assumed_role \
    role_arns=arn:aws:iam::111122223333:role/dynamic-role \
    default_sts_ttl=15m max_sts_ttl=1h

# Optional - just-in-time credentials as a throwaway IAM user. Slower, but truly revocable.
vault write aws-demo/roles/dynamic-iam-user \
    credential_type=iam_user \
    policy_arns=arn:aws:iam::111122223333:policy/workload-policy \
    user_path=/vault-dynamic/
```

### 4.3 Policy

Grants read on exactly the credential paths the workload needs, and nothing else.

```bash
vault policy write demo-app-policy - <<'EOF'
path "aws-demo/static-creds/demo-app"  { capabilities = ["read"] }
path "aws-demo/static-roles/demo-app"  { capabilities = ["read"] }
path "aws-demo/creds/dynamic-sts"      { capabilities = ["read"] }
path "aws-demo/creds/dynamic-iam-user" { capabilities = ["read"] }
path "aws-demo/config/root"            { capabilities = ["read"] }
path "sys/leases/lookup"               { capabilities = ["update"] }
path "sys/leases/revoke"               { capabilities = ["update"] }
EOF
```

`config/root` is readable so the page can display how Vault authenticates. It never exposes
secret material. Remove it if you prefer.

## 5. Now choose an implementation

The shared foundation is in place. Continue in one of:

- **[kubernetes-agent-injector/](kubernetes-agent-injector/)** — Kubernetes, credentials
  delivered by an injected sidecar. Adds the Kubernetes auth method.
- **[ec2/](ec2/)** — a virtual machine, credentials delivered by Vault Agent under systemd.
  Adds the AWS auth method.
- **[kubernetes-direct-api/](kubernetes-direct-api/)** — Kubernetes, the application calls
  Vault's API itself. Uses the same Kubernetes auth method as the injector implementation.

---

## What is in this repository

```
README.md                        this file: shared AWS and Vault configuration
aws/*.json                       IAM policy documents used by all implementations
scripts/setup.sh, teardown.sh    scripted build and removal of the shared foundation

kubernetes-agent-injector/       Kubernetes, sidecar-delivered credentials
kubernetes-direct-api/           Kubernetes, application calls Vault directly
ec2/                             EC2 / virtual machine, Vault Agent under systemd
```

Each implementation folder contains its own README, application, deployment configuration and
helper script, and can be followed on its own once sections 3 and 4 are done.
