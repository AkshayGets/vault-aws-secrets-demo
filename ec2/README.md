# AWS credentials on a virtual machine, with no secrets on the host

A working reference implementation for delivering AWS credentials to an application running on
an **EC2 instance** — no Kubernetes, no container platform, and no secret placed on the host,
in its image, or in its configuration management.

The application reads two files. Everything else is done by Vault Agent, running as an
ordinary systemd service.

- **Phase 1 — rotate what you already have.** Vault takes ownership of an existing IAM user's
  access key and replaces it on a schedule. The IAM user, its ARN and its policies are
  untouched.
- **Phase 2 — remove the standing credential.** The instance receives a just-in-time credential
  that Vault mints on demand and that expires by itself.

> This is deliberately the same application, the same Vault configuration and the same policy
> as [../kubernetes-agent-injector/](../kubernetes-agent-injector/). Only the way the instance
> proves its identity is different. That is the point: **the platform changes, the developer
> experience does not.**

> Complete [sections 3 and 4 of the top-level README](../README.md) first — the AWS resources,
> the secrets engine, the roles and the policy are shared by every implementation here.

---

## Placeholder values

Every environment-specific value here is a placeholder, and the table is maintained once in
[the top-level README](../README.md#placeholder-values). Two are specific to this folder:

| Placeholder | What it stands for |
|---|---|
| `aws-ec2` | Mount path of the AWS auth method |
| `ec2-demo-role` | IAM role attached to the instance — its identity |

---

## 1. How the instance proves who it is

A Kubernetes pod is given a signed token naming its ServiceAccount, which is how
[../kubernetes-agent-injector/](../kubernetes-agent-injector/) authenticates. An EC2 instance
has no such thing — so it uses the identity it already has: **the IAM role attached through its
instance profile.**

The AWS auth method's `iam` login type turns that into a Vault login:

1. AWS places credentials on the instance through its instance profile. Nobody put them there.
2. Vault Agent builds an `sts:GetCallerIdentity` request and **signs it** with those
   credentials, then sends Vault the *signed request* — never the credentials themselves.
3. Vault relays that request to AWS STS, which replies with the caller's ARN.
4. Vault matches the ARN against the role's `bound_iam_principal_arn` and issues a token.

Two properties follow, and both are worth knowing:

- **Vault never sees the instance's AWS credentials.** The signature proves the caller without
  disclosing anything, and it cannot be usefully replayed because Vault inspects the request it
  was handed.
- **Vault needs no AWS credentials of its own to do this.** `auth/aws-ec2/config/client` is
  left empty in this implementation. AWS STS validates the signature; Vault is the courier.

The instance's IAM role carries **only** `AmazonSSMManagedInstanceCore` — no S3, no IAM, no
data access of any kind. Every AWS permission the workload eventually exercises arrives from
Vault at runtime.

---

## 2. Prerequisites

- Vault Enterprise or Community Edition, reachable from the instance.
- An AWS account where you can create IAM roles and launch an instance.
- An **existing IAM user** for Phase 1 — Vault rotates an existing user's key; it does not
  create the user.
- The AWS resources, secrets engine, roles and policy from
  [sections 3 and 4 of the top-level README](../README.md) — all reused here unchanged.

---

## 3. Configure AWS — the instance's identity

```bash
export AWS_REGION=us-east-1

aws iam create-role --role-name ec2-demo-role \
  --assume-role-policy-document file://aws/ec2-trust-policy.json \
  --description "Identity of the demo host; Vault AWS auth binds to this ARN"

# SSM only. This role needs no AWS permissions in order to log in to Vault.
aws iam attach-role-policy --role-name ec2-demo-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

aws iam create-instance-profile --instance-profile-name ec2-demo-profile
aws iam add-role-to-instance-profile --instance-profile-name ec2-demo-profile \
  --role-name ec2-demo-role
```

---

## 4. Configure Vault

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps          # omit on Community Edition

vault auth enable -path=aws-ec2 aws

vault write auth/aws-ec2/role/ec2-demo-app \
    auth_type=iam \
    bound_iam_principal_arn="arn:aws:iam::111122223333:role/ec2-demo-role" \
    resolve_aws_unique_ids=false \
    token_policies=demo-app-policy \
    token_ttl=1h
```

`demo-app-policy` is the **same policy [the Kubernetes implementation](../kubernetes-agent-injector/)
uses**. The authorization is identical; only the method of proving identity changed.

**About `resolve_aws_unique_ids`.** With the default (`true`), Vault resolves the ARN to the
IAM role's unique ID when the role is created, which requires Vault to hold AWS credentials of
its own. Setting it to `false` stores the ARN as written and keeps `config/client` empty. The
trade-off is that an IAM role deleted and recreated with the same name would still match; if
that matters in your environment, leave it `true` and give Vault credentials with
`iam:GetRole`.

---

## 5. Launch the instance

[`bootstrap/user-data.sh`](bootstrap/user-data.sh) installs Vault, creates an unprivileged `demoapp` user,
writes the agent configuration and two systemd units, and starts the agent.

```bash
aws ec2 run-instances \
  --image-id <latest Amazon Linux 2023 AMI> \
  --instance-type t3.small \
  --subnet-id subnet-EXAMPLE1234 \
  --security-group-ids sg-EXAMPLE1234 \
  --iam-instance-profile Name=ec2-demo-profile \
  --user-data file://bootstrap/user-data.sh \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=vault-ec2-demo}]'
```

The security group needs **no inbound rules**. Access is entirely through **SSM Session
Manager**, so there is no open port and no SSH key to distribute — which is worth noting, since
key distribution is the same class of problem this whole design removes.

Then push the application (it exceeds the 16 KB user-data limit, so it is copied separately;
in a real deployment it would arrive from S3, a package, or be baked into the AMI):

```bash
./scripts/demo.sh reload
```

---

## 6. The agent configuration

[`vault-agent/agent.hcl`](vault-agent/agent.hcl), run by systemd as the `demoapp` user:

```hcl
vault {
  address   = "https://vault.example.com"
  namespace = "apps"
}

auto_auth {
  method "aws" {
    mount_path = "auth/aws-ec2"
    config = {
      type   = "iam"
      role   = "ec2-demo-app"
      region = "us-east-1"
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
```

Four things in there are load-bearing:

- **`namespace` belongs in the `vault` stanza**, not only inside `auto_auth`. Placed only in
  the login block, the agent authenticates correctly and then reads secrets from the wrong
  namespace.
- **`template_config.static_secret_render_interval`** matters because the Phase 1 credential
  carries no lease, so nothing drives a refresh except this timer. The default is five minutes,
  which is far too slow against a one-minute rotation.
- **`perms = "0400"`** renders the file readable only by its owner.
- The agent **runs as the same unprivileged user as the application**, so that owner is the
  process that uses the credential. Running the agent as root would make `0400` meaningless.

The template also controls the file's *format*. It can emit JSON, a `.env` file, Java
properties or XML — you shape the secret to fit the application rather than changing the
application.

---

## 7. What a developer writes

1. Ask the platform team for a Vault role.
2. Read a file.

That is the entire list on a virtual machine. The agent configuration is written once by the
platform team into a base image or a configuration-management role, exactly as they already
manage any other host-level service.

**No longer needed:** a Vault SDK or any dependency on one; authentication code, token storage,
renewal or re-authentication; a secret in the image, the repository, the CI system or a
configuration-management variable; any rotation logic; any AWS credential handling.

**The one thing to handle:** re-read the file. A long-running process that reads a credential
once at startup and caches it forever will keep using a key that has since been rotated away.
Options, in order of effort: read the file each time you need the credential (what this
implementation does), watch it for changes, or have the agent restart the process on change
with a `command` in the template stanza.

---

## 8. How the credentials refresh

The two phases refresh by different mechanisms, because one carries a lease and one does not.

**Phase 1 — no lease, so the agent polls.** `static-creds` returns `lease_duration: 0`, so
nothing signals a change. The agent re-reads every 20 seconds, renders the template, and
compares the result to what is on disk — writing **only when it differs**. The file's timestamp
is therefore a truthful signal that the credential actually changed.

**Phase 2 — leased, so the agent works to a deadline.** The dynamic credential carries a lease
of roughly 900 seconds that is not renewable, so the agent fetches an entirely new credential
before the current one expires, at about 90% of the lease.

Nothing is pushed. Vault does not notify the agent, and the agent does not notify the
application. The agent asks Vault on a schedule and rewrites a file only when the answer has
changed; the application simply reads a file whose contents occasionally differ.

---

## 9. Where the credential lives on the host

The rendered files are how the credential reaches the application, so it is worth knowing what
they are and who can read them.

```
$ ls -l /etc/app/secrets/
-r--------. 1 demoapp demoapp aws-dynamic.json
-r--------. 1 demoapp demoapp aws-static.json
```

One identity can read them: the process that uses them. The credential is valid for 60 seconds
(Phase 1) or 15 minutes (Phase 2), it was generated by machines with no person in the path, and
it maps to one identity with a minimal policy that CloudTrail attributes back to this host.

It is also absent from the places credentials are usually found — source repositories, CI logs,
machine images, configuration-management variables, chat and ticketing systems. It cannot be
committed by accident because it did not exist until the agent started.

On a virtual machine `/etc/app/secrets` is ordinary disk. The Kubernetes implementation gets a
memory-backed volume for free; to get the same property here, place the directory on a `tmpfs`
mount. Access to the host
itself is the remaining path to the file, governed by your existing controls — here, SSM
Session Manager and IAM.

---

## 10. Running it

The helper uses the `EC2_PROFILE` variable (default `iam-account`) to choose an AWS profile,
deliberately *not* `AWS_PROFILE` — so a profile exported for a different account cannot be
picked up here by mistake. Override it if your profile is named differently:
`EC2_PROFILE=my-profile ./scripts/demo.sh start`.

```bash
./scripts/demo.sh start      # port-forward the page to http://localhost:8082
./scripts/demo.sh files      # the two credential files on the host, secrets masked
./scripts/demo.sh renders    # render events - run twice a minute apart
./scripts/demo.sh logs       # agent log: login, renewals, every render
./scripts/demo.sh config     # the agent configuration in force
./scripts/demo.sh session    # an interactive shell, over SSM
./scripts/demo.sh destroy    # terminate the instance and remove its IAM role
```

### What to look at

`./scripts/demo.sh files` shows two ordinary files on an ordinary Linux host. Run it again a
minute later: the Phase 1 access key has changed underneath a running application, which was
never notified.

`./scripts/demo.sh logs` shows one authentication at boot, then a stream of renders. There is
no repeated login, because the token is renewed rather than re-issued.

The page itself opens with the panel *"What this application knows about Vault"*. The answer is
nothing — there is no Vault address, token, login or library anywhere in
[`app/app.py`](app/app.py).

### A note on revoking Phase 2 credentials

**AWS cannot recall an STS credential.** Revoking the Vault lease removes the lease, but AWS
honours the credential until it expires. This is an AWS constraint rather than a Vault
limitation, and it applies to any tool issuing STS credentials. The control for STS credentials
is that they are short-lived; where true revocation is required, `credential_type=iam_user`
provides it, because Vault deletes the IAM user and access stops immediately.

---

## 11. Security notes

- The instance's IAM role holds only `AmazonSSMManagedInstanceCore`. It grants no data access;
  every AWS permission the workload uses is issued by Vault at runtime.
- The AWS auth method is configured with **no AWS credentials of its own** — the caller's
  signed request is self-proving.
- Credential files are rendered `0400` and owned by the application's unprivileged user. The
  agent runs as that same user, which is what makes the file mode meaningful.
- The Vault token is short-lived (1h) and renewed by the agent; the application never sees it.
- The security group has no inbound rules; access is through SSM Session Manager.
- `rotation_period` of one minute is a demonstration value. Production deployments should use
  `rotation_schedule` with a cron expression.

---

## 12. What is in this repository

```
app/app.py                      the application - contains no Vault code
vault-agent/agent.hcl           the agent configuration; this is the integration
vault-agent/*.service           systemd units for the agent and the application
bootstrap/user-data.sh          bootstrap: installs Vault, writes config, starts the agent
aws/ec2-trust-policy.json       trust policy for the instance's IAM role
scripts/demo.sh                 start / files / renders / logs / config / reload / destroy
```

---

## The same thing on Kubernetes

**[../kubernetes-agent-injector/](../kubernetes-agent-injector/)** is this identical design on
Kubernetes: the same application shape, the same Vault configuration and the same policy, with
the agent injected as a sidecar instead of running under systemd, and the pod proving its
identity with a ServiceAccount instead of an IAM role.

The two run on different ports (8081 and 8082), so they can be run side by side — which is the
clearest way to see that the developer experience does not change with the platform.

**[../kubernetes-direct-api/](../kubernetes-direct-api/)** is the variant where the application
calls Vault's API itself.
