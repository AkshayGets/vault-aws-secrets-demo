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

> This folder is self-contained: sections 3 to 7 take you from an empty AWS account to a
> running demonstration.

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

### Reviewing the configuration

Four commands show the whole of it. Run them against your own Vault to confirm what is in
force — this is also the quickest way to explain the design to someone else.

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps
```

**The mount.** The AWS auth method, enabled at a path of your choosing:

```bash
$ vault auth list
Path        Type    Accessor              Description
aws-ec2/    aws     auth_aws_a29547eb     n/a
```

**Its client configuration.** Empty, and deliberately so — for `iam` login the caller's signed
request is self-proving, so Vault stores no AWS credentials for this mount:

```bash
$ vault read auth/aws-ec2/config/client
No value found at auth/aws-ec2/config/client
```

**The roles on it.** One per distinct set of permissions, not one per instance:

```bash
$ vault list auth/aws-ec2/role
Keys
----
ec2-demo-app
```

**The role itself** — the mapping, and the only part that names AWS:

```bash
$ vault read auth/aws-ec2/role/ec2-demo-app
Key                               Value
---                               -----
auth_type                         iam
bound_iam_principal_arn           [arn:aws:iam::111122223333:role/ec2-demo-role]
resolve_aws_unique_ids            false
token_policies                    [demo-app-policy]
token_ttl                         1h
bound_account_id                  []
bound_region                      []
bound_vpc_id                      []
bound_subnet_id                   []
bound_ami_id                      []
bound_iam_instance_profile_arn    []
```

### How this maps to the instance profile

The chain runs: **instance → instance profile → IAM role → the ARN in
`bound_iam_principal_arn`.**

An instance profile is a container that carries exactly one IAM role. Attaching the profile to
an instance is what causes AWS to place credentials *for that role* on the instance. So although
you attach a *profile*, the identity the instance actually holds is the **role**.

That matters when reading the role above. When Vault relays the signed request, STS returns a
temporary session ARN of the form:

```
arn:aws:sts::111122223333:assumed-role/ec2-demo-role/i-0abc123def456
```

Vault reduces that to the underlying **IAM role ARN** before matching:

```
arn:aws:iam::111122223333:role/ec2-demo-role
```

which is why `bound_iam_principal_arn` names the role — not the instance profile, and not the
per-instance session. The instance ID is deliberately not part of the match, which is what makes
the next point work.

> One matching detail: with `resolve_aws_unique_ids=false`, as configured here, the ARN is
> compared as written — so specify it **without any path component**. Section 6 covers why this
> implementation sets it to `false` and what that trades away.

### A fleet of instances

**Nothing above is per-instance.** The unit of identity is the IAM role behind the instance
profile, so a thousand instances sharing one instance profile all match the same Vault role and
receive the same policy. No registration step, no per-instance configuration, and an instance
that is replaced by an autoscaling group authenticates immediately because its identity is the
role, not the machine.

When fleets differ, you have three options, in increasing order of blast radius:

| Approach | Configuration | Use when |
|---|---|---|
| **One role per fleet** | a Vault role per instance profile, each with its own policy | different fleets need different secrets — the usual answer |
| **Several ARNs on one role** | `bound_iam_principal_arn` takes a **list** of ARNs | several fleets legitimately share one set of permissions |
| **A wildcard** | `bound_iam_principal_arn="arn:aws:iam::111122223333:role/app-*"` | a naming convention already separates your fleets |

```bash
# several instance profiles, one shared set of permissions
vault write auth/aws-ec2/role/payments-fleet \
    auth_type=iam \
    bound_iam_principal_arn="arn:aws:iam::111122223333:role/payments-api,arn:aws:iam::111122223333:role/payments-worker" \
    resolve_aws_unique_ids=false \
    token_policies=payments-policy
```

Two cautions on wildcards. A trailing `*` matches everything below it, so
`arn:aws:iam::111122223333:role/*` grants that policy to **every role in the account** — scope
the prefix deliberately. And when the ARN ends in a wildcard, `resolve_aws_unique_ids` is
ignored, because there is no single role to resolve.

Where a wildcard is too broad on its own, the role fields left empty in the output above exist
to narrow it further — `bound_account_id`, `bound_region`, `bound_vpc_id`, `bound_subnet_id`,
`bound_ami_id` and `bound_iam_instance_profile_arn`. A common production shape is a wildcard on
a role-name prefix combined with `bound_vpc_id`, so that only instances of the right fleet *in
the right network* can authenticate.

The practical guidance: **the number of Vault roles should track the number of distinct access
requirements, not the number of instances.**

---

## 2. Prerequisites

The [common prerequisites](../README.md#prerequisites), plus two specific to this
implementation:

- Permission to launch an EC2 instance.
- **AWS Systems Manager**, so the instance can be reached without opening an inbound port.

---

## 3. Configure AWS

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

## 4. Configure the Vault AWS secrets engine

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps
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

## 5. Configure the instance's IAM identity

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

## 6. Configure the AWS auth method

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps

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

## 7. Launch the instance

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

## 8. The agent configuration

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

### Inspecting it from the instance

Everything the agent does is visible on the box. Get a shell with
`./scripts/demo.sh session`, or directly:

```bash
aws ssm start-session --target i-EXAMPLE1234
```

Session Manager logs you in as **`ssm-user`**, while the agent runs as the unprivileged
**`demoapp`** user and its files are owner-only — so most of what follows needs `sudo`.

**Where everything lives:**

| Path | What it is | Mode |
|---|---|---|
| `/etc/vault-agent/agent.hcl` | the agent configuration | `0640 demoapp` |
| `/etc/vault-agent/token` | the Vault token the agent obtained and renews | `0640 demoapp` |
| `/etc/app/secrets/*.json` | the rendered AWS credentials | `0400 demoapp` |
| `/etc/systemd/system/vault-agent.service` | the unit that runs it | root |
| `/usr/bin/vault` | the binary — the agent and the CLI are the same one | — |
| `journalctl -u vault-agent` | every login, renewal and render | — |

**Is it running, and as whom?**

```bash
$ sudo systemctl status vault-agent
● vault-agent.service - Vault Agent
     Loaded: loaded (/etc/systemd/system/vault-agent.service; enabled; preset: disabled)
     Active: active (running) since Sat 2026-09-05 10:29:45 UTC; 22h ago
   Main PID: 2221 (vault)

$ sudo systemctl show vault-agent -p User -p ExecStart --no-pager
User=demoapp
ExecStart={ ... argv[]=/usr/bin/vault agent -config=/etc/vault-agent/agent.hcl ... }
```

`ExecStart` is the authoritative answer to *"which configuration is actually in force?"* — read
the path from there rather than assuming, then:

```bash
sudo cat /etc/vault-agent/agent.hcl
```

**Did it authenticate?** The agent writes its Vault token to the sink file. Its existence is
the evidence that the AWS login succeeded:

```bash
$ sudo ls -l /etc/vault-agent/token
-rw-r-----. 1 demoapp demoapp 110 Sep  5 10:29 /etc/vault-agent/token
```

You can use that token to interrogate Vault from the instance. Note that a bare
`vault token lookup` prints the token itself, so filter it if anyone is watching:

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_NAMESPACE=apps

$ sudo cat /etc/vault-agent/token | \
    VAULT_TOKEN=$(cat -) vault token lookup -format=json | \
    python3 -c 'import sys,json; d=json.load(sys.stdin)["data"]; print(json.dumps({k:d[k] for k in ("policies","ttl","renewable","display_name")}, indent=2))'

{
  "policies": ["default", "demo-app-policy"],
  "ttl": 3304,
  "renewable": true,
  "display_name": "apps-auth-aws-ec2-ec2-demo-role/i-EXAMPLE1234"
}
```

Three things worth reading in that output. The **policies** are the ones the Vault role granted,
so authorization is confirmed end to end. The **ttl** counts down and the agent renews it, which
is why there is only one login in the log rather than one per hour. And the **display_name**
records the auth mount, the IAM role *and the instance ID* — so although the match is on the
role ARN and nothing is per-instance, the resulting token still identifies which machine
obtained it. That is what makes a fleet sharing one role auditable.

**What has it rendered?**

```bash
$ sudo ls -l /etc/app/secrets/
-r--------. 1 demoapp demoapp 1054 Sep  6 09:06 aws-dynamic.json
-r--------. 1 demoapp demoapp  140 Sep  6 09:07 aws-static.json

$ sudo -u demoapp cat /etc/app/secrets/aws-static.json     # contains a live credential
```

The timestamps are meaningful: the agent rewrites a file **only when its contents change**, so
`aws-static.json` changing every minute is the Phase 1 rotation arriving.

**The log.** This is where a failed login or a template error will be, and it is the first place
to look when something is wrong:

```bash
sudo journalctl -u vault-agent -n 50 --no-pager    # recent activity
sudo journalctl -u vault-agent -f                  # follow live
sudo journalctl -u vault-agent | grep rendered     # just the renders
sudo journalctl -u vault-agent | grep -i auth      # the login and renewals
```

A healthy start looks like this — one authentication, then renders:

```
agent.auth.handler: authenticating
agent.auth.handler: authentication successful, sending token to sinks
agent.sink.file: token written: path=/etc/vault-agent/token
agent: (runner) rendered "(dynamic)" => "/etc/app/secrets/aws-static.json"
agent: (runner) rendered "(dynamic)" => "/etc/app/secrets/aws-dynamic.json"
```

**The application** is a separate unit, so its health is separate from the agent's:

```bash
sudo systemctl status demo-app
sudo journalctl -u demo-app -n 30 --no-pager
```

**After changing the configuration**, restart the agent and watch it come back:

```bash
sudo systemctl restart vault-agent
sudo journalctl -u vault-agent -n 20 --no-pager
```

If you prefer not to open a shell at all, `./scripts/demo.sh config`, `status`, `logs`,
`renders` and `files` run these same commands remotely over SSM.

---

## 9. What a developer writes

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

## 10. How the credentials refresh

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

## 11. Running it

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

## 12. Security notes

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

## 13. What is in this folder

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
