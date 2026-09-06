# Vault → AWS credentials, with no secrets in your application

Working reference implementations for delivering AWS credentials to a workload without ever
placing a secret in the application, its image, its manifest or its repository.

This page is the map: what the demonstrations show, how they work in outline, and which one to
follow. **Every configuration step lives in the implementation folder you choose** — pick one
below and it will take you from an empty AWS account to a running demonstration.

---

## The two phases

Each implementation shows both.

<a id="phase-1"></a>
### Phase 1 — rotate what you already have

Vault takes ownership of an **existing** IAM user's access key and replaces it on a schedule.
The IAM user, its ARN, its policies and its CloudTrail history are untouched — only the
credential material becomes disposable. This maps directly onto a fleet of long-lived access
keys that are rotated by hand today, and requires no change to the AWS estate.

<a id="phase-2"></a>
### Phase 2 — remove the standing credential

The workload receives a **just-in-time** credential that Vault mints on demand and that expires
by itself. There is no long-lived key left to leak, steal or rotate.

Phase 1 is the bridge; Phase 2 is the destination. Most estates run both — Phase 1 for the
legacy fleet, Phase 2 for everything new.

---

## How it works, in outline

The same three steps in every implementation, whatever the platform:

```
  1. PROVE            2. ISSUE                    3. USE
  The workload        Vault checks the identity   The workload calls AWS
  proves the          against a policy and        with a credential that
  identity its        issues an AWS credential    rotates or expires
  platform already    for it                      underneath it
  gave it
       │                       │                          │
  Kubernetes: the        Phase 1: rotates an        No credential was ever
  ServiceAccount         existing user's key        created by a person,
  token                                             written to a file by
  EC2: the IAM role      Phase 2: mints a new       hand, or copied
  on the instance        short-lived one            anywhere
```

Nothing in that chain requires a human to create, transport or store a secret. The workload
proves what it already is, and receives something short-lived in return.

---

## Choose an implementation

The three differ only in **how the credential reaches the workload**. All use the same secrets
engine, the same roles and the same policy.

| | Platform | The application contains | Use this when |
|---|---|---|---|
| **[kubernetes-agent-injector/](kubernetes-agent-injector/)** | Kubernetes | **no Vault code** — an injected sidecar writes credentials to files | you run Kubernetes. This is the pattern to put into production |
| **[ec2/](ec2/)** | EC2, or any VM | **no Vault code** — Vault Agent writes credentials to files | your workloads are virtual machines rather than containers |
| **[kubernetes-direct-api/](kubernetes-direct-api/)** | Kubernetes | login, token handling and API calls | your application must talk to Vault itself — a sidecar or agent is not an option — or you want to see the login, token and credential fetch explicitly while learning the API |

The first two are the same design on two platforms, and that is the point: **the developer
experience does not change when the platform does.** In both, the application reads a file.

Each folder is self-contained. Follow one from top to bottom; there is no need to read the
others.

---

## Prerequisites

**For every implementation:**

- **Vault Enterprise**
- An AWS account where you can create IAM users, roles and policies.
- An **existing IAM user** for Phase 1 — Vault rotates an existing user's key; it does not
  create the user.
- The AWS CLI, and `vault` on your path.

**Additionally, depending on the implementation:**

| | Also needs |
|---|---|
| **kubernetes-agent-injector/** | a Kubernetes cluster with `kubectl` access, and the **Vault Agent Injector** installed — it ships with the official Vault Helm chart (`injector.enabled=true`). Configures the **Kubernetes auth method** |
| **ec2/** | permission to launch an EC2 instance, and **AWS Systems Manager** for access without opening a port. Configures the **AWS auth method** |
| **kubernetes-direct-api/** | a Kubernetes cluster with `kubectl` access. Configures the **Kubernetes auth method** |

Note the difference in the last column: the auth method you configure depends on how the
workload proves its identity, so it belongs to the implementation rather than to this page.

---

## Placeholder values

**Every environment-specific value in this repository is a placeholder.** Replace them with
your own before running anything. Nothing here is a real address, account or credential.

| Placeholder | What it stands for |
|---|---|
| `vault.example.com` | Your Vault address |
| `apps` | The Vault namespace holding the secrets engine |
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

## How Vault itself reaches AWS

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

`aws-demo` is the path the AWS secrets engine is mounted at in Vault. Each implementation's
README walks through configuring it.

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
identity provider and Vault's access ends immediately. Requires Vault Enterprise 1.17 or
later, and the issuer must be reachable from AWS.

**This changes only how the engine authenticates.** [Phase 1](#phase-1) and [Phase 2](#phase-2)
behave identically either way — same roles, same rotation, same leases, same API.

---

## What is in this repository

```
README.md                        this page: concepts, prerequisites, navigation
aws/*.json                       IAM policy documents used by all implementations
scripts/setup.sh, teardown.sh    scripted build and removal of the shared AWS and Vault objects

kubernetes-agent-injector/       Kubernetes, credentials delivered by an injected sidecar
ec2/                             EC2 or any VM, credentials delivered by Vault Agent
kubernetes-direct-api/           Kubernetes, the application calls Vault's API itself
```

Each implementation folder contains its own README with the complete configuration, the
application, the deployment configuration and a helper script.
