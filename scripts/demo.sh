#!/usr/bin/env bash
# Demo helper. Usage: ./scripts/demo.sh <command>
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com}"
export VAULT_NAMESPACE="${VAULT_NAMESPACE:-apps}"
export AWS_PROFILE="${AWS_PROFILE:-vault-demo}"     # profile that can reach the EKS cluster
IAM_PROFILE="${IAM_PROFILE:-iam-account}"               # profile for AWS account 111122223333
NS=demo-apps

case "${1:-help}" in

start)   # the only command you need during a demo
  echo "Opening http://localhost:8080 ..."
  echo "Ctrl-C to stop."
  kubectl port-forward -n $NS svc/demo-app 8080:8080
  ;;

auth)    # how does Vault itself authenticate to AWS?  (README section 2)
  echo "--- aws-demo/config/root ---"
  vault read aws-demo/config/root | grep -E "access_key|role_arn|identity_token_audience|region"
  echo
  echo "access_key set          -> static credential (run rotate-root so nobody has seen it)"
  echo "role_arn + audience set -> plugin WIF, no static credential at all"
  echo "neither set             -> ambient identity from the AWS SDK chain (IRSA)"
  ;;

status)
  echo "--- pod ---";        kubectl get pods -n $NS
  echo "--- static role ---"; vault read aws-demo/static-roles/demo-app
  echo "--- current key ---"; vault read aws-demo/static-creds/demo-app
  echo "--- aws truth ---"
  AWS_PROFILE=$IAM_PROFILE aws iam list-access-keys --user-name demo-app \
    --query 'AccessKeyMetadata[].[AccessKeyId,CreateDate]' --output table
  ;;

logs)
  kubectl logs -f deploy/demo-app -n $NS
  ;;

rotate)  # force an immediate rotation instead of waiting for the period
  # NOTE: the AWS secrets engine has no on-demand rotate endpoint for static roles
  # (unlike the database engine's rotate-role). Re-writing the role with the same
  # or different parameters does NOT rotate either - only creation does. So we
  # delete and recreate, which triggers an immediate takeover of the IAM user's key.
  vault delete aws-demo/static-roles/demo-app >/dev/null
  vault write  aws-demo/static-roles/demo-app username=demo-app rotation_period=1m >/dev/null
  sleep 2
  vault read aws-demo/static-creds/demo-app
  ;;

slow)    # switch to a calmer rotation period for a long talk track
  vault write aws-demo/static-roles/demo-app username=demo-app rotation_period=5m
  echo "rotation_period is now 5m"
  ;;

fast)    # back to demo speed
  vault write aws-demo/static-roles/demo-app username=demo-app rotation_period=1m
  echo "rotation_period is now 1m"
  ;;

reload)  # push local app.py changes into the cluster
  kubectl create configmap demo-app-code -n $NS \
    --from-file=app.py="$(dirname "$0")/../app/app.py" \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl rollout restart deploy/demo-app -n $NS
  kubectl rollout status deploy/demo-app -n $NS
  ;;

leases)
  vault list sys/leases/lookup/aws-demo/creds/dynamic-sts       2>/dev/null || echo "(no assumed_role leases)"
  vault list sys/leases/lookup/aws-demo/creds/dynamic-iam-user  2>/dev/null || echo "(no iam_user leases)"
  ;;

*)
  cat <<'EOF'
Vault demo helper

  ./scripts/demo.sh start    port-forward to localhost:8080  <-- use this to demo
  ./scripts/demo.sh auth     how Vault itself authenticates to AWS (README section 2)
  ./scripts/demo.sh status   pod, static role, current key, and the AWS-side truth
  ./scripts/demo.sh logs     tail the app log
  ./scripts/demo.sh rotate   force an immediate key rotation
  ./scripts/demo.sh slow     rotation_period -> 5m (long talk track)
  ./scripts/demo.sh fast     rotation_period -> 1m (default demo speed)
  ./scripts/demo.sh reload   push local app/app.py into the cluster
  ./scripts/demo.sh leases   list outstanding dynamic leases
EOF
  ;;
esac
