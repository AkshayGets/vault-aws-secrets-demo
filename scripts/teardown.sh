#!/usr/bin/env bash
# Removes everything this demo created, in both Vault and AWS.
# Usage: ./scripts/teardown.sh   (prompts before destroying anything)
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com}"
export VAULT_NAMESPACE="${VAULT_NAMESPACE:-apps}"
K8S_PROFILE="${K8S_PROFILE:-vault-demo}"
IAM_PROFILE="${IAM_PROFILE:-iam-account}"
ACCT=111122223333

read -rp "Destroy the demo (k8s ns 'demo-apps', Vault aws-demo mount, AWS demo IAM)? [y/N] " ok
[[ "$ok" == "y" || "$ok" == "Y" ]] || { echo "aborted"; exit 0; }

echo "--- kubernetes ---"
AWS_PROFILE=$K8S_PROFILE kubectl delete namespace demo-apps --ignore-not-found

echo "--- vault ---"
# revoke outstanding dynamic leases first so Vault cleans up the IAM users it made
vault lease revoke -prefix aws-demo/creds/ 2>/dev/null || true
vault delete auth/kubernetes/role/demo-app 2>/dev/null || true
vault policy delete demo-app-policy              2>/dev/null || true
vault secrets disable aws-demo                    2>/dev/null || true

echo "--- aws iam (account $ACCT) ---"
export AWS_PROFILE=$IAM_PROFILE
for u in demo-app vault-root; do
  for k in $(aws iam list-access-keys --user-name "$u" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
    aws iam delete-access-key --user-name "$u" --access-key-id "$k" 2>/dev/null || true
  done
  for p in $(aws iam list-attached-user-policies --user-name "$u" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
    aws iam detach-user-policy --user-name "$u" --policy-arn "$p" 2>/dev/null || true
  done
  aws iam delete-user --user-name "$u" 2>/dev/null && echo "  deleted user $u" || true
done

# any dynamic iam_user leftovers Vault did not clean up
for u in $(aws iam list-users --path-prefix /vault-dynamic/ --query 'Users[].UserName' --output text 2>/dev/null); do
  for k in $(aws iam list-access-keys --user-name "$u" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
    aws iam delete-access-key --user-name "$u" --access-key-id "$k" 2>/dev/null || true
  done
  for p in $(aws iam list-attached-user-policies --user-name "$u" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
    aws iam detach-user-policy --user-name "$u" --policy-arn "$p" 2>/dev/null || true
  done
  aws iam delete-user --user-name "$u" 2>/dev/null && echo "  deleted orphan $u" || true
done

aws iam detach-role-policy --role-name dynamic-role \
  --policy-arn arn:aws:iam::$ACCT:policy/workload-policy 2>/dev/null || true
aws iam delete-role --role-name dynamic-role 2>/dev/null && echo "  deleted role dynamic-role" || true

# WIF scaffolding (README section 2) - present whether or not WIF is switched on
for r in vault-wif vault-wif vault-wif-diagnostic; do
  for p in $(aws iam list-attached-role-policies --role-name "$r" \
             --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
    aws iam detach-role-policy --role-name "$r" --policy-arn "$p" 2>/dev/null || true
  done
  aws iam delete-role --role-name "$r" 2>/dev/null && echo "  deleted role $r" || true
done
for oidc in $(aws iam list-open-id-connect-providers \
              --query 'OpenIDConnectProviderList[?contains(Arn,`identity/oidc`)].Arn' --output text 2>/dev/null); do
  aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "$oidc" 2>/dev/null \
    && echo "  deleted OIDC provider $(basename "$oidc")" || true
done

for pol in workload-policy vault-permissions-policy vault-wif-test-policy; do
  arn=arn:aws:iam::$ACCT:policy/$pol
  for v in $(aws iam list-policy-versions --policy-arn "$arn" \
             --query 'Versions[?!IsDefaultVersion].VersionId' --output text 2>/dev/null); do
    aws iam delete-policy-version --policy-arn "$arn" --version-id "$v" 2>/dev/null || true
  done
  aws iam delete-policy --policy-arn "$arn" 2>/dev/null && echo "  deleted policy $pol" || true
done

echo
echo "Left in place on purpose:"
echo "  - the demo S3 buckets (demo-data-*, demo-logs-*) - delete manually if you want them gone"
echo "  - the kubernetes Kubernetes auth mount (pre-existing, shared)"
echo "  - your cli-user"
echo "done."
