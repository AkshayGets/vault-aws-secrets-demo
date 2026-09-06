# Kubernetes — credentials delivered by the Vault Agent Injector

The production pattern. The application contains **no Vault code at all**: an injected sidecar
authenticates on the pod's behalf and writes credentials to files, and the application reads
files.

> This folder is self-contained: sections 2 to 5 take you from an empty AWS account to a
> running demonstration. See the [top-level README](../README.md) for the concepts,
> prerequisites and [placeholder values](../README.md#placeholder-values).

Open `app/app.py` and search it for the word "vault". You will find it only in file paths and
comments.

---

## 1. Architecture

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

## 2. Configure AWS

Policy documents are in [`../aws/`](../aws/). Replace the account ID first.

```bash
export ACCT=111122223333

# What the workload may do. Deliberately minimal: prove identity, prove authorization.
aws iam create-policy --policy-name workload-policy \
  --policy-document file://../aws/workload-policy.json

# What Vault may do. Scoped to named entities only - not an administrator credential.
aws iam create-policy --policy-name vault-permissions-policy \
  --policy-document file://../aws/vault-root-policy.json

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
  --assume-role-policy-document file://../aws/dynamic-role-trust-policy.json \
  --max-session-duration 3600
aws iam attach-role-policy --role-name dynamic-role \
  --policy-arn arn:aws:iam::$ACCT:policy/workload-policy
```

Optionally create two S3 buckets so `s3:ListAllMyBuckets` returns something real.

---

## 3. Configure the Vault AWS secrets engine

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps          # omit on Community Edition
```

### 3.1 Enable and configure the AWS secrets engine

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

### 3.2 Define the credentials

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

### 3.3 Policy

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

## 4. Configure the Kubernetes auth method

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

## 5. Deploy

```bash
kubectl create namespace demo-apps
kubectl create serviceaccount demo-app -n demo-apps
./scripts/demo-agent.sh deploy
./scripts/demo-agent.sh start          # http://localhost:8081
```

### The integration, in full

Everything that talks to Vault is in the pod annotations in
[`k8s/deployment.yaml`](k8s/deployment.yaml):

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
  lease. See section 7.

---

## 6. What a developer writes

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

## 7. How the credentials refresh

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

## 8. Running it

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

Reading [`k8s/deployment.yaml`](k8s/deployment.yaml) alongside
[`app/app.py`](app/app.py) shows the division of responsibility directly: all
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

## 9. Security notes

- Vault's credential is scoped to named IAM entities and one user path. It is not an
  administrator credential, and the policy document is in the repository for review.
- `config/rotate-root` means the credential Vault holds was generated by Vault. Re-run it any
  time; there is nothing to distribute afterwards.
- The workload's Vault policy grants read on specific credential paths only.
- Vault tokens issued to workloads are short-lived (1h here). Renewal is available, but
  re-authenticating is cheap when identity is platform-issued, and re-proving identity is
  preferable to extending trust in an old token.
- Credentials are rendered to an in-memory volume (`emptyDir` with `medium: Memory`), so they
  are never written to node disk. The `agent-inject-perms-*` annotations render them `0400`,
  and `agent-run-as-same-user` plus the container's `runAsUser` make the application's own
  user their owner — so the only identity that can read a credential is the process using it.
- `rotation_period=1m` is a demonstration value. Production deployments should use
  `rotation_schedule` with a cron expression.

---


---

## What is in this folder

```
app/app.py               the application - contains no Vault code
k8s/deployment.yaml      the annotations; this is the entire integration
scripts/demo.sh          deploy / start / files / config / logs / reload
```

## The same thing on a virtual machine

**[../ec2/](../ec2/)** is this identical design on an EC2 instance: the same application shape,
the same Vault configuration and the same policy, with Vault Agent running under systemd
instead of as a sidecar, and the instance proving its identity with its IAM role instead of a
ServiceAccount. Running both is the clearest way to show that the developer experience does not
change with the platform.

**[../kubernetes-direct-api/](../kubernetes-direct-api/)** is the variant where the application
calls Vault's API itself, which makes each step visible on screen.
