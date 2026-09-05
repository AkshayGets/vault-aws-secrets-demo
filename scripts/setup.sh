#!/usr/bin/env bash
# Rebuilds the whole demo from scratch, so it is reproducible after a teardown or in
# a different AWS account.
#
#   VAULT_TOKEN=<root>  ./scripts/setup.sh
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com}"
export VAULT_NAMESPACE="${VAULT_NAMESPACE:-apps}"
K8S_PROFILE="${K8S_PROFILE:-vault-demo}"   # profile that can reach the EKS cluster
IAM_PROFILE="${IAM_PROFILE:-iam-account}"      # profile for the IAM account
ACCT="${ACCT:-111122223333}"
REGION="${REGION:-us-east-1}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

: "${VAULT_TOKEN:?set VAULT_TOKEN}"

echo "=== 1/5  AWS: policies, users, role ==="
export AWS_PROFILE=$IAM_PROFILE AWS_REGION=$REGION
aws iam create-policy --policy-name workload-policy \
  --policy-document file://"$HERE"/aws/workload-policy.json >/dev/null 2>&1 || echo "  workload policy exists"
aws iam create-policy --policy-name vault-permissions-policy \
  --policy-document file://"$HERE"/aws/vault-root-policy.json >/dev/null 2>&1 || echo "  vault-root policy exists"

for u in demo-app vault-root; do
  aws iam create-user --user-name $u --tags Key=purpose,Value=vault-aws-demo >/dev/null 2>&1 || echo "  user $u exists"
done
aws iam attach-user-policy --user-name demo-app --policy-arn arn:aws:iam::$ACCT:policy/workload-policy
aws iam attach-user-policy --user-name vault-root   --policy-arn arn:aws:iam::$ACCT:policy/vault-permissions-policy

aws iam create-role --role-name dynamic-role \
  --assume-role-policy-document file://"$HERE"/aws/dynamic-role-trust-policy.json \
  --max-session-duration 3600 >/dev/null 2>&1 || echo "  role exists"
aws iam attach-role-policy --role-name dynamic-role --policy-arn arn:aws:iam::$ACCT:policy/workload-policy

# the "legacy" key the customer would be rotating by hand today
aws iam create-access-key --user-name demo-app >/dev/null 2>&1 || true
VK=$(aws iam create-access-key --user-name vault-root --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
VK_ID=$(echo "$VK" | cut -f1); VK_SECRET=$(echo "$VK" | cut -f2)
echo "  waiting 10s for IAM propagation"; sleep 10

echo "=== 2/5  Vault: AWS secrets engine ==="
vault secrets enable -path=aws-demo aws 2>/dev/null || echo "  aws-demo already enabled"
vault write aws-demo/config/root access_key="$VK_ID" secret_key="$VK_SECRET" region=$REGION >/dev/null
vault write aws-demo/config/lease lease=15m lease_max=1h >/dev/null

# Hand the bootstrap credential straight back to Vault. From here the secret exists only
# inside Vault - not in this script's memory, not in your shell history. See README section 2.
# Requires Vault's key to be the ONLY access key on vault-root, which it is at this point.
vault write -f aws-demo/config/rotate-root >/dev/null && echo "  rotated root credential - the bootstrap key is now dead"

echo "=== 3/5  Vault: roles ==="
# Phase 1 - Vault takes over the existing IAM user's access key
vault write aws-demo/static-roles/demo-app username=demo-app rotation_period=1m >/dev/null
# Phase 2a - JIT credentials via STS (cannot be recalled; short TTL is the control)
vault write aws-demo/roles/dynamic-sts \
  credential_type=assumed_role \
  role_arns=arn:aws:iam::$ACCT:role/dynamic-role \
  default_sts_ttl=15m max_sts_ttl=1h >/dev/null
# Phase 2b - JIT credentials as throwaway IAM users (hard-revocable)
vault write aws-demo/roles/dynamic-iam-user \
  credential_type=iam_user \
  policy_arns=arn:aws:iam::$ACCT:policy/workload-policy \
  user_path=/vault-dynamic/ >/dev/null

echo "=== 4/5  Vault: policy + Kubernetes auth role ==="
vault policy write demo-app-policy - <<'EOF' >/dev/null
path "aws-demo/static-creds/demo-app"  { capabilities = ["read"] }
path "aws-demo/static-roles/demo-app"  { capabilities = ["read"] }
path "aws-demo/creds/dynamic-sts"          { capabilities = ["read"] }
path "aws-demo/creds/dynamic-iam-user"     { capabilities = ["read"] }
path "sys/leases/lookup"                  { capabilities = ["update"] }
path "sys/leases/revoke"                  { capabilities = ["update"] }
EOF
vault write auth/kubernetes/role/demo-app \
  bound_service_account_names=demo-app \
  bound_service_account_namespaces=demo-apps \
  token_policies=demo-app-policy token_ttl=1h >/dev/null

echo "=== 5/5  Kubernetes ==="
export AWS_PROFILE=$K8S_PROFILE
kubectl create namespace demo-apps --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create serviceaccount demo-app -n demo-apps --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create configmap demo-app-code -n demo-apps --from-file=app.py="$HERE"/kubernetes-direct-api/app/app.py \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f "$HERE"/kubernetes-direct-api/k8s/deployment.yaml >/dev/null
kubectl rollout status deploy/demo-app -n demo-apps --timeout=180s

echo
echo "Done.  Run:  ./scripts/demo.sh start   then open http://localhost:8080"
