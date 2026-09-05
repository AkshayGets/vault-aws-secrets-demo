# Variant: the application calls Vault's API directly

The same demonstration as [../kubernetes-agent-injector/](../kubernetes-agent-injector/) — the
same Vault configuration, the same AWS resources, the same two phases — but here the
application authenticates to Vault itself instead of receiving credentials from a sidecar.

**Use [the Agent Injector implementation](../kubernetes-agent-injector/) for production
guidance.** This variant exists because it
makes every step visible on screen: the login, the token, each credential read, and each AWS
call, with real latencies. It is the better one for explaining *what is happening*; the
injector version is the better one for showing *what a developer actually writes*.

All setup is shared: the AWS resources, secrets engine, roles and policy are in
[sections 3 and 4 of the top-level README](../README.md), and the Kubernetes auth method is in
[section 2 of the Agent Injector README](../kubernetes-agent-injector/README.md). Nothing extra
is required for this variant, and [the placeholder values](../README.md#placeholder-values) are
the same.

---

## Running it

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
