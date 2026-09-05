#!/bin/bash
set -euxo pipefail

VAULT_ADDR_="https://vault.example.com"
VAULT_NS_="apps"
AWS_MOUNT_="aws-demo"
AUTH_MOUNT_="auth/aws-ec2"
VAULT_ROLE_="ec2-demo-app"
STATIC_ROLE_="demo-app"
DYNAMIC_ROLE_="dynamic-sts"

# ---------------------------------------------------------------- install Vault
dnf install -y dnf-plugins-core >/dev/null
dnf config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
dnf install -y vault python3 >/dev/null
vault version

# ---------------------------------------------------------------- unprivileged user
id demoapp >/dev/null 2>&1 || useradd --system --create-home --shell /sbin/nologin demoapp
install -d -o demoapp -g demoapp -m 0750 /etc/vault-agent
install -d -o demoapp -g demoapp -m 0750 /etc/app/secrets
install -d -o demoapp -g demoapp -m 0755 /opt/demo

# ---------------------------------------------------------------- Vault Agent config
cat > /etc/vault-agent/agent.hcl <<EOF
# Vault Agent on a virtual machine. The equivalent of the Kubernetes sidecar:
# it logs in on the instance's behalf and renders credentials to files.

vault {
  address   = "${VAULT_ADDR_}"
  namespace = "${VAULT_NS_}"
}

# The instance proves who it is with the IAM role attached to it. Vault Agent signs
# an sts:GetCallerIdentity request with the instance-profile credentials and sends
# Vault the SIGNED REQUEST - never the credentials themselves.
auto_auth {
  method "aws" {
    mount_path = "${AUTH_MOUNT_}"
    config = {
      type   = "iam"
      role   = "${VAULT_ROLE_}"
      region = "us-east-1"
    }
  }
  sink "file" {
    config = { path = "/etc/vault-agent/token" }
  }
}

# The Phase 1 credential carries no lease, so tell the agent how often to re-read it.
template_config {
  static_secret_render_interval = "20s"
}

template {
  destination = "/etc/app/secrets/aws-static.json"
  perms       = "0400"
  contents    = <<EOT
{{- with secret "${AWS_MOUNT_}/static-creds/${STATIC_ROLE_}" -}}
{"access_key":"{{ .Data.access_key }}","secret_key":"{{ .Data.secret_key }}","expiration":"{{ .Data.expiration }}"}
{{- end }}
EOT
}

template {
  destination = "/etc/app/secrets/aws-dynamic.json"
  perms       = "0400"
  contents    = <<EOT
{{- with secret "${AWS_MOUNT_}/creds/${DYNAMIC_ROLE_}" -}}
{"access_key":"{{ .Data.access_key }}","secret_key":"{{ .Data.secret_key }}","session_token":"{{ .Data.session_token }}","arn":"{{ .Data.arn }}","ttl":"{{ .Data.ttl }}"}
{{- end }}
EOT
}
EOF
chown demoapp:demoapp /etc/vault-agent/agent.hcl
chmod 0640 /etc/vault-agent/agent.hcl

# ---------------------------------------------------------------- systemd units
cat > /etc/systemd/system/vault-agent.service <<'EOF'
[Unit]
Description=Vault Agent
After=network-online.target
Wants=network-online.target

[Service]
User=demoapp
Group=demoapp
ExecStart=/usr/bin/vault agent -config=/etc/vault-agent/agent.hcl
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/demo-app.service <<'EOF'
[Unit]
Description=Vault AWS credential demo application
After=vault-agent.service

[Service]
User=demoapp
Group=demoapp
Environment=STATIC_CRED_FILE=/etc/app/secrets/aws-static.json
Environment=DYNAMIC_CRED_FILE=/etc/app/secrets/aws-dynamic.json
Environment=AWS_REGION=us-east-1
ExecStart=/usr/bin/python3 -u /opt/demo/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vault-agent
touch /var/log/user-data-complete
