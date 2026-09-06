# Variant: the application calls Vault's API directly

The same demonstration as [../kubernetes-agent-injector/](../kubernetes-agent-injector/) — the
same Vault configuration, the same AWS resources, the same two phases — but here the
application authenticates to Vault itself instead of receiving credentials from a sidecar.

**Use [the Agent Injector implementation](../kubernetes-agent-injector/) for production
guidance.** This variant exists because it
makes every step visible on screen: the login, the token, each credential read, and each AWS
call, with real latencies. It is the better one for explaining *what is happening*; the
injector version is the better one for showing *what a developer actually writes*.

This folder is self-contained. Sections 1 to 3 below configure AWS, the secrets engine and the
Kubernetes auth method; section 4 runs it. See the [top-level README](../README.md) for the
concepts, prerequisites and [placeholder values](../README.md#placeholder-values).

---

## 1. Configure AWS

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

## 2. Configure the Vault AWS secrets engine

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps          # omit on Community Edition
```

### 2.1 Enable and configure the AWS secrets engine

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

### 2.2 Define the credentials

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

### 2.3 Policy

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

## 3. Configure the Kubernetes auth method

This is identical to the Agent Injector implementation, and the two can share one mount and
role. If you have already followed
[that folder](../kubernetes-agent-injector/README.md#4-configure-the-kubernetes-auth-method),
skip this step.

```bash
vault auth enable -path=kubernetes kubernetes

vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc:443"

vault write auth/kubernetes/role/demo-app \
    bound_service_account_names=demo-app \
    bound_service_account_namespaces=demo-apps \
    token_policies=demo-app-policy \
    token_ttl=1h \
    alias_name_source=serviceaccount_uid
```

---

## 4. Running it

---

```bash
kubectl create configmap demo-app-code -n demo-apps --from-file=app.py=app/app.py
kubectl apply -f k8s/deployment.yaml
./scripts/demo.sh start        # http://localhost:8080
```

The injector implementation runs on 8081, so both can run at once — which is the clearest way to
show the difference.

```bash
./scripts/demo.sh auth      # how Vault itself authenticates to AWS
./scripts/demo.sh status    # pod, static role, current key, and the AWS-side truth
./scripts/demo.sh rotate    # force an immediate rotation instead of waiting
./scripts/demo.sh slow      # rotation every 5m, for a slower walkthrough
./scripts/demo.sh fast      # back to 1m
```

---

## How the two variants differ

| | This variant | Agent Injector |
|---|---|---|
| Who authenticates to Vault | the application | a sidecar container |
| Vault code in the application | login, token cache, re-auth on expiry, API calls | none |
| Application knows Vault's address | yes | no |
| Application knows the secret paths | yes | no — two file paths |
| Obtains a credential by | HTTPS call to Vault | `open()` |
| Handles token expiry | yes | no |
| Reacts to rotation | re-reads Vault on a timer | notices the file changed |

Both use the same ServiceAccount, Vault role and policy. Only the delivery mechanism differs.

---

## How the application authenticates to Vault

The statement that the pod holds no secret is only meaningful once the chain behind it is
visible, so here it is in full.

**The token the pod holds.** The manifest says only `serviceAccountName: demo-app`. From that,
the kubelet projects a signed, short-lived token into the pod at
`/var/run/secrets/kubernetes.io/serviceaccount/token`, with claims of this shape:

```
alg  RS256
iss  https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE
aud  ["https://kubernetes.default.svc"]
sub  system:serviceaccount:demo-apps:demo-app
     kubernetes.io.namespace       demo-apps
     kubernetes.io.serviceaccount  demo-app  uid <uid>
     kubernetes.io.pod             demo-app-...  uid <uid>
     kubernetes.io.node            <node>
rotated by the kubelet before it expires
```

The issuer is the cluster's own OIDC issuer: the cluster signs the identity of its own
workloads. The token is bound to this ServiceAccount and names the exact pod and node.

**The exchange**, all visible in the page's call log:

1. **Kubernetes issues the identity.** No human, pipeline or manifest handles a credential.
2. **The application reads the file** and posts it to `auth/kubernetes/login` with
   `role=demo-app`. This is the entirety of its authentication code.
3. **Vault asks Kubernetes to verify it** via the `TokenReview` API, authenticating as its own
   ServiceAccount. Vault does not check the signature itself — it delegates to the cluster
   that issued the token.
4. **Kubernetes returns the identity**: `system:serviceaccount:demo-apps:demo-app` plus the
   ServiceAccount UID. An expired or revoked token, or one from a deleted ServiceAccount,
   fails here.
5. **Vault applies the role's bindings.** A pod in another namespace, or using another
   ServiceAccount, is rejected even with a valid token.
6. **Vault issues its own token** carrying `demo-app-policy` with a 1h TTL. Because
   `alias_name_source` is `serviceaccount_uid`, the Vault identity is keyed to the
   ServiceAccount UID and survives restarts and redeploys.

The application's token handling is a single behaviour: on a 401 or 403 it discards the token
and logs in again. It never renews. Re-proving the pod's platform identity is cheaper and
safer than extending trust in an old token.

---

## What the application does with the credential

Two AWS calls, chosen deliberately:

- **`sts:GetCallerIdentity`** returns the ARN, proving *which identity* the credential maps
  to. This is the key moment for Phase 1 — the access key ID changes every minute while the
  ARN underneath stays identical. Stable identity, disposable credential.
- **`s3:ListAllMyBuckets`** proves the credential is *authorized*, not merely well-formed. A
  credential that authenticates but can do nothing would prove very little.

Both are signed with SigV4 written inline, so nothing is hidden inside a library. The
functions are deliberately trivial: the point is not what the application does in AWS, but
that a credential nobody ever handled is real, works, and keeps working while it is being
rotated underneath.

---

## Notes

- This variant disables TLS verification when calling Vault, because the demo runs on a stock
  `python:3.12-slim` image that ships without a CA bundle. **Remove this for any real
  deployment** — it is `_ssl.verify_mode = ssl.CERT_NONE` near the top of `app/app.py`. The
  injector variant does not have this concern, because the sidecar reaches Vault over the
  in-cluster service address.
- The application is stdlib-only Python run from a ConfigMap on a stock image, so there is no
  image to build or registry to publish to. Edit `app/app.py` and run `./scripts/demo.sh
  reload`.

## Related

- **[../kubernetes-agent-injector/](../kubernetes-agent-injector/)** — the same demonstration
  with no Vault code in the application.
- **[../ec2/](../ec2/)** — the same design on a virtual machine.
