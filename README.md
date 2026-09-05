# Vault → AWS credentials, with no secrets in your application

A working reference implementation of two patterns for getting AWS credentials into a
workload without ever placing a secret in the application, its image, its manifest or its
repository:

- **Phase 1 — rotate what you already have.** Vault takes ownership of an *existing* IAM
  user's access key and replaces it on a schedule. The IAM user, its ARN and its policies
  are untouched. This maps directly onto a fleet of long-lived access keys that are rotated
  by hand today.
- **Phase 2 — remove the standing credential.** Workloads receive a just-in-time credential
  that Vault mints on demand and that expires by itself. There is no long-lived key left to
  leak or rotate.

Everything here runs against real Vault Enterprise and real AWS. Nothing is mocked. The demo
presents as a single browser page so the behaviour is visible without switching windows.

The application in this repository contains **no Vault code at all** — a Vault Agent sidecar
authenticates on the pod's behalf and writes credentials to files. A second variant, where the
application calls Vault's API directly, is documented in
[README-direct-api.md](README-direct-api.md).

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

These are routinely confused, and the confusion inverts the whole story.

| | Vault's own credential | The workload's credential |
|---|---|---|
| Where it lives | `aws-demo/config/root` | a file inside the pod |
| What it is for | calling `iam:CreateAccessKey`, `iam:DeleteAccessKey`, `sts:AssumeRole` — **manufacturing** credentials | doing actual work in AWS |
| Who sees it | nobody | the workload, in memory, at runtime |
| Lifetime | long-lived but machine-managed | 60 seconds (Phase 1) or 15 minutes (Phase 2) |

> **Vault's own credential is never handed to an application.** Think of a key-cutting
> machine: it needs a power supply, and the keys it cuts are what your workloads carry.
> Nobody distributes the power supply.

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
does not return `secret_key` to anyone — a root token included. Prove it live with
`vault read aws-demo/config/root`, which shows the access key ID and no secret.

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

## 2. Architecture

```
  Kubernetes cluster (account 444455556666)          AWS account 111122223333
 ┌────────────────────────────────────────┐
 │ namespace: demo-apps                   │
 │  ┌──────────────────────────────────┐  │
 │  │ pod                              │  │
 │  │   vault-agent  (injected sidecar)│──┼──▶ logs in, reads secrets
 │  │        │ writes files            │  │
 │  │        ▼                         │  │
 │  │   /vault/secrets/*.json          │  │
 │  │        │ read                    │  │        ┌──────────────────────────┐
 │  │   application                    │──┼───────▶│ user/demo-app     (P1)   │
 │  └──────────────────────────────────┘  │        │ role/dynamic-role (P2)   │
 │                                        │        └──────────────────────────┘
 │ namespace: vault                       │                     ▲
 │   Vault Enterprise ─────────────────────────────────────────┘
 └────────────────────────────────────────┘   rotates the key / mints credentials
```

`/vault/secrets` is an in-memory volume; credentials never touch disk on the node.

---

## 3. Prerequisites

- Vault Enterprise, unsealed, reachable from the cluster.
- The **Vault Agent Injector** installed (it ships with the official Vault Helm chart:
  `injector.enabled=true`).
- A Kubernetes cluster, and `kubectl` access to it.
- An AWS account where you can create IAM users, roles and policies.
- An **existing IAM user** for Phase 1. Vault rotates an existing user's key; it does not
  create the user.

---

## 4. Configure AWS

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

## 5. Configure Vault — Kubernetes workloads

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps          # omit on Community Edition
```

### 5.1 Enable and configure the AWS secrets engine

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

### 5.2 Define the credentials

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

### 5.3 Policy

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

### 5.4 Kubernetes auth

```bash
vault auth enable -path=kubernetes kubernetes

# Run from inside the cluster, Vault uses its own ServiceAccount and CA to call TokenReview.
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc:443"

vault write auth/kubernetes/role/demo-app \
    bound_service_account_names=demo-app \
    bound_service_account_namespaces=demo-apps \
    token_policies=demo-app-policy \
    token_ttl=1h \
    alias_name_source=serviceaccount_uid
```

`alias_name_source=serviceaccount_uid` keys the Vault identity to the ServiceAccount's UID, so
it stays the same across pod restarts and redeploys — which is what makes per-workload audit
and policy meaningful.

**How a login works.** The kubelet projects a signed, short-lived token into the pod naming
its ServiceAccount. Vault Agent presents it to `auth/kubernetes/login`. Vault calls the
Kubernetes `TokenReview` API to verify it — delegating to the cluster that issued it — then
checks the role's bindings and issues a Vault token carrying `demo-app-policy`. No credential
was ever created, distributed or stored by a person.

---

## 6. Deploy

```bash
kubectl create namespace demo-apps
kubectl create serviceaccount demo-app -n demo-apps
./scripts/demo-agent.sh deploy
./scripts/demo-agent.sh start          # http://localhost:8081
```

### The integration, in full

Everything that talks to Vault is in the pod annotations in
[`k8s/deployment-agent.yaml`](k8s/deployment-agent.yaml):

```yaml
vault.hashicorp.com/agent-inject: "true"
vault.hashicorp.com/namespace: "apps"
vault.hashicorp.com/auth-path: "auth/kubernetes"
vault.hashicorp.com/role: "demo-app"
vault.hashicorp.com/template-static-secret-render-interval: "20s"

vault.hashicorp.com/agent-inject-secret-aws-static.json: "aws-demo/static-creds/demo-app"
vault.hashicorp.com/agent-inject-template-aws-static.json: |
  {{- with secret "aws-demo/static-creds/demo-app" -}}
  {"access_key":"{{ .Data.access_key }}","secret_key":"{{ .Data.secret_key }}"}
  {{- end }}
```

- The **filename is the annotation's key suffix**, not its value:
  `agent-inject-secret-aws-static.json` produces `/vault/secrets/aws-static.json`. The value
  is only the Vault path to read. `vault.hashicorp.com/secret-volume-path` changes the
  directory, which is how you place a file exactly where an application already expects one.
- The **template** controls the file's format. It can emit JSON, a `.env` file, Java
  properties, XML — you shape the secret to fit the application rather than changing the
  application.
- **`template-static-secret-render-interval`** matters because the Phase 1 credential has no
  lease. See section 8.

---

## 7. What a developer writes

1. Ask the platform team for a Vault role.
2. Add the annotation block to the deployment manifest.
3. Read a file.

That is the entire list. For an existing application the change is usually smaller still —
most already read AWS credentials from a file or environment variable, so the template is
written to match the format the application already expects and the application code does not
change at all.

**What is no longer needed:** no Vault SDK or dependency on one; no authentication code, token
storage, renewal or re-authentication; no secret in the image, manifest, repository or CI
system; no rotation logic; no AWS credential handling of any kind.

**The one thing to handle:** re-read the file. A long-running process that reads a credential
once at startup and caches it forever will keep using a key that has since been rotated away.
In order of effort: read the file each time you need the credential (what this demo does);
watch it for changes and refresh in place; or have the agent restart the process on change
with `vault.hashicorp.com/agent-inject-command`.

---

## 8. How the credentials refresh

The two phases refresh by different mechanisms, for a good reason: one has a lease and one
does not.

**Phase 1 — no lease, so the agent polls.** `static-creds` returns `lease_duration: 0`. There
is nothing to renew and no expiry to anticipate, so the agent re-reads on a fixed timer,
`template-static-secret-render-interval`. Each cycle it renders the template and compares the
result to what is on disk, writing atomically **only if it differs**. The file's timestamp is
therefore a truthful signal that the credential actually changed. Freshness is bounded by the
interval you choose — the default is 5 minutes, which would be far too slow against a 1-minute
rotation, hence 20s here.

**Phase 2 — leased, so the agent works to a deadline.** `creds/dynamic-sts` returns a lease
(≈900s) that is not renewable, so the agent fetches an entirely new credential before the
current one expires, at roughly 90% of the lease. Tune with
`vault.hashicorp.com/template-lease-renewal-threshold`.

Nothing is pushed. Vault does not notify the agent, and the agent does not notify the
application. The agent asks Vault on a schedule and rewrites a file only when the answer has
changed; the application simply reads a file whose contents occasionally differ.

---

## 9. Where the credential lives

The rendered files are how the credential reaches the application, so it is worth knowing
exactly what they are, where they exist and who can read them.

### A memory-backed volume

The injector mounts `/vault/secrets` as `emptyDir` with `medium: Memory` — a tmpfs, mounted
`noswap`:

```
$ kubectl exec -n demo-apps deploy/demo-app-agent -c app -- mount | grep /vault/secrets
tmpfs on /vault/secrets type tmpfs (rw,relatime,noswap)
```

The credential therefore exists in RAM for the lifetime of the pod and nowhere else. It is
never written to the node's disk, so it cannot appear in a volume snapshot, a disk backup, or
an image of the node, and it is never paged out to swap. When the pod stops, it is gone.

### Owner-only file permissions

By default the agent renders files world-readable within the container (`0644`). Two
annotations tighten that, and the manifest in this repository sets both:

```yaml
vault.hashicorp.com/agent-inject-perms-aws-static.json: "0400"
vault.hashicorp.com/agent-inject-perms-aws-dynamic.json: "0400"
vault.hashicorp.com/agent-run-as-same-user: "true"
```

`agent-inject-perms-<name>` sets the file mode. `agent-run-as-same-user` runs the Vault Agent
under the same UID as the application container, so that the "owner" who may read a `0400`
file is the application itself. That second annotation requires the application container to
declare a UID explicitly, which it does:

```yaml
securityContext:
  runAsUser: 1000
  runAsGroup: 1000
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

Running as an ordinary user is what makes the file mode meaningful — root would be able to
read the file whatever its permissions say. The result:

```
$ kubectl exec -n demo-apps deploy/demo-app-agent -c app -- sh -c 'id; ls -l /vault/secrets/'
uid=1000 gid=1000 groups=1000
-r--------. 1 1000 1000 1054 aws-dynamic.json
-r--------. 1 1000 1000  140 aws-static.json
```

One identity can read the credential: the process that needs it.

### Why a file rather than an environment variable

Environment variables are a common alternative and a weaker one. They are readable through
`/proc/<pid>/environ`, are inherited by every child process, appear in crash dumps and core
files, and are frequently captured by logging agents, error trackers and orchestrator tooling
that prints process metadata. A file has an owner and a mode; an environment variable has
neither. If an application can only accept an environment variable, the agent's
`agent-inject-command` annotation can source the file into the process at startup, keeping the
credential out of the pod spec either way.

### What this adds up to

A credential exists where it is used, for as long as it is needed, readable by the process
that needs it. It is valid for 60 seconds (Phase 1) or 15 minutes (Phase 2), it was generated
by machines with no person in the path, and it maps to one identity with a minimal policy that
CloudTrail attributes back to this workload.

Just as importantly, it is absent from the places credentials are usually found: source
repositories, CI job logs, container images, chat and email, ticketing systems, configuration
management and developer machines. It could not be committed by accident, because it did not
exist until the pod started and will not exist after it stops.

Access to a running container is the remaining path to the file, and that is governed by
Kubernetes RBAC — `pods/exec` is the permission to audit and restrict, and it is a control you
already own.

---

## 10. Non-Kubernetes workloads — EC2

Kubernetes auth works because the kubelet gives each pod a signed token proving its
ServiceAccount. An EC2 instance has neither, so it needs a different way to prove identity —
but **everything after that point is the same**, including the developer experience.

### The AWS auth method

An EC2 instance already has a machine identity: its **IAM role**, delivered through the
instance profile. The `iam` login flavour turns that into a Vault login.

1. The instance holds AWS credentials from its instance profile. AWS put them there.
2. Vault Agent builds an `sts:GetCallerIdentity` request and **signs it** with those
   credentials, then sends Vault the *signed request* — not the credentials.
3. Vault forwards it to AWS STS, which replies with the caller's ARN.
4. Vault matches the ARN against a role and issues a token.

Vault never sees the instance's AWS credentials, and the signature is self-proving.

### Vault configuration

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps

vault auth enable aws

# Only needed if Vault must call AWS to resolve role ARNs to unique IDs, or for ec2 login.
# Supports the same options as the secrets engine, including workload identity federation.
vault write auth/aws/config/client \
    identity_token_audience="vault-aws-auth" \
    role_arn="arn:aws:iam::111122223333:role/vault-wif"

vault write auth/aws/role/ec2-app \
    auth_type=iam \
    bound_iam_principal_arn="arn:aws:iam::111122223333:role/ec2-app-role" \
    token_policies=demo-app-policy \
    token_ttl=1h
```

That is the exact counterpart of the Kubernetes role in section 5.4 — same policy, same TTL, a
different way of proving identity landing on identical authorization.

### On the instance

Install Vault Agent and run it as a service with this configuration:

```hcl
vault { address = "https://vault.example.com" }

auto_auth {
  method "aws" {
    mount_path = "auth/aws"
    namespace  = "apps"
    config = {
      type = "iam"
      role = "ec2-app"
    }
  }
  sink "file" { config = { path = "/etc/vault-agent/token" } }
}

template_config { static_secret_render_interval = "20s" }

template {
  destination = "/etc/app/secrets/aws-static.json"
  perms       = "0400"
  contents    = <<EOT
{{- with secret "aws-demo/static-creds/demo-app" -}}
{"access_key":"{{ .Data.access_key }}","secret_key":"{{ .Data.secret_key }}"}
{{- end }}
EOT
}

template {
  destination = "/etc/app/secrets/aws-dynamic.json"
  perms       = "0400"
  contents    = <<EOT
{{- with secret "aws-demo/creds/dynamic-sts" -}}
{"access_key":"{{ .Data.access_key }}","secret_key":"{{ .Data.secret_key }}","session_token":"{{ .Data.session_token }}"}
{{- end }}
EOT
}
```

Compare that with the annotations in section 6. It is the same agent, the same templates and
the same files — the `auto_auth` stanza is the only difference, and a platform team writes it
once into a base image or configuration-management role.

The protections described in section 9 apply here too, with the same effect by different
mechanics. `perms = "0400"` is the `template` stanza's equivalent of the
`agent-inject-perms-<name>` annotation, and the agent should run under the service account
that owns the application so that the file's owner is the process that reads it. On a virtual
machine the directory is ordinary disk rather than tmpfs, so place it on a `tmpfs` mount if
you want the same memory-only property.

### Developer experience on EC2

**Identical.** The application reads `/etc/app/secrets/aws-static.json` and calls AWS. It has
no Vault code, no AWS credential, and no awareness that any of this is happening.

> Kubernetes workloads prove who they are with a ServiceAccount. EC2 instances prove who they
> are with their IAM role. On-premises systems use AppRole, a TLS certificate or JWT/OIDC.
> Every one of them ends up holding the same thing — a file — and every one lands on the same
> policy and the same secrets engine. The developer experience does not change when the
> platform does.

### Where there is no cloud identity

For on-premises systems, the options are **AppRole** (a role ID plus a delivered secret ID),
**TLS certificate auth** (the machine's existing certificate), or **JWT/OIDC** (an existing
identity provider — how most CI systems authenticate). All terminate in the same Vault Agent
and the same file on disk.

---

## 11. Running the demo

```bash
./scripts/demo-agent.sh start     # http://localhost:8081
./scripts/demo-agent.sh files     # the files the sidecar wrote, secrets masked
./scripts/demo-agent.sh config    # the agent configuration the injector generated
./scripts/demo-agent.sh logs      # the sidecar's log: every render and lease renewal
./scripts/demo-agent.sh status    # the injected init container and sidecar
```

### What the page shows

**The top panel — "What this application knows about Vault".** The answer is nothing. It lists
both credential files with their contents and how recently each was written, which is the
whole of the application's integration with Vault.

**Phase 1, once a minute.** The file's age resets, the card flashes, and a row is added to the
rotation table recording the old and new access key IDs. The identity line underneath is
unchanged: the credential was replaced beneath a running application, and neither the
application nor anything downstream was notified.

**Phase 2, on each issue.** The identity is an STS session of `role/dynamic-role` rather than
an IAM user, so nothing was created in AWS and nothing needs cleaning up afterwards. The
session name carries the Vault namespace, auth mount and Kubernetes namespace that requested
it, so CloudTrail attributes every subsequent action back to the originating workload.

Reading [`k8s/deployment-agent.yaml`](k8s/deployment-agent.yaml) alongside
[`app-agent/app.py`](app-agent/app.py) shows the division of responsibility directly: all
Vault knowledge lives in annotations owned by the platform team, and none of it is in the
application.

### A note on revoking Phase 2 credentials

**AWS cannot recall an STS credential.** Revoking the Vault lease for an `assumed_role`
credential removes the lease, but AWS honours the credential until it expires. This is an AWS
constraint rather than a Vault limitation, and it applies to any tool issuing STS
credentials.

The control for STS credentials is that they are short-lived. Where you need true revocation,
`credential_type=iam_user` provides it — Vault deletes the IAM user, and access stops
immediately. The trade-off is IAM entity churn, a few seconds of propagation delay before a
new credential works, and AWS's limit of two access keys per user. Both are configured here so
the difference can be shown.

---

## 12. Security notes

- Vault's credential is scoped to named IAM entities and one user path. It is not an
  administrator credential, and the policy document is in the repository for review.
- `config/rotate-root` means the credential Vault holds was generated by Vault. Re-run it any
  time; there is nothing to distribute afterwards.
- The workload's Vault policy grants read on specific credential paths only.
- Vault tokens issued to workloads are short-lived (1h here). Renewal is available, but
  re-authenticating is cheap when identity is platform-issued, and re-proving identity is
  preferable to extending trust in an old token.
- Credentials are rendered to an in-memory volume, readable only by the application's own
  user. See section 9 for how this is configured and what it means.
- `rotation_period=1m` is a demonstration value. Production deployments should use
  `rotation_schedule` with a cron expression.

---

## 13. What is in this repository

```
app-agent/app.py              the application - contains no Vault code
k8s/deployment-agent.yaml     the annotations; this is the entire integration
scripts/demo-agent.sh         deploy / start / files / config / logs / reload
aws/*.json                    IAM policy documents
README-direct-api.md          the variant where the application calls Vault's API directly
app/, k8s/deployment.yaml     that variant's application and manifest
scripts/setup.sh, teardown.sh scripted build and removal of the whole environment
```
