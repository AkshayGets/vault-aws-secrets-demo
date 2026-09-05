# Vault Agent on a virtual machine. The equivalent of the Kubernetes sidecar:
# it logs in on the instance's behalf and renders credentials to files.

vault {
  address   = "https://vault.example.com"
  namespace = "apps"
}

# The instance proves who it is with the IAM role attached to it. Vault Agent signs
# an sts:GetCallerIdentity request with the instance-profile credentials and sends
# Vault the SIGNED REQUEST - never the credentials themselves.
auto_auth {
  method "aws" {
    mount_path = "auth/aws-ec2"
    config = {
      type   = "iam"
      role   = "ec2-demo-app"
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
{{- with secret "aws-demo/static-creds/demo-app" -}}
{"access_key":"{{ .Data.access_key }}","secret_key":"{{ .Data.secret_key }}","expiration":"{{ .Data.expiration }}"}
{{- end }}
EOT
}

template {
  destination = "/etc/app/secrets/aws-dynamic.json"
  perms       = "0400"
  contents    = <<EOT
{{- with secret "aws-demo/creds/dynamic-sts" -}}
{"access_key":"{{ .Data.access_key }}","secret_key":"{{ .Data.secret_key }}","session_token":"{{ .Data.session_token }}","arn":"{{ .Data.arn }}","ttl":"{{ .Data.ttl }}"}
{{- end }}
EOT
}
