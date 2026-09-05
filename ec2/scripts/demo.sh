#!/usr/bin/env bash
# EC2 / non-Kubernetes demo helper.  Usage: ./scripts/demo.sh <command>
set -euo pipefail

# The demo host lives in the IAM account. Use a dedicated variable so an AWS_PROFILE
# inherited from the Kubernetes reference implementation (which points at the cluster account) cannot be picked
# up here by mistake. Override with EC2_PROFILE=... if your profile is named differently.
export AWS_PROFILE="${EC2_PROFILE:-iam-account}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
export VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com}"
export VAULT_NAMESPACE="${VAULT_NAMESPACE:-apps}"
NAME_TAG=vault-ec2-demo
LOCAL_PORT="${LOCAL_PORT:-8082}"          # v1=8080, v2=8081, EC2=8082
HERE="$(cd "$(dirname "$0")/.." && pwd)"

iid() {
  local id
  id=$(aws ec2 describe-instances \
        --filters "Name=tag:Name,Values=$NAME_TAG" "Name=instance-state-name,Values=running" \
        --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || true)
  if [[ -z "$id" || "$id" == "None" ]]; then
    cat >&2 <<EOF
No running instance tagged "$NAME_TAG" is visible.

  profile in use : $AWS_PROFILE   (account $(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo '?'))
  region         : $AWS_REGION

Check that:
  - the profile points at the account holding the demo host (override with EC2_PROFILE=...)
  - the credentials have not expired
  - the instance is running:  aws ec2 describe-instances --filters Name=tag:Name,Values=$NAME_TAG
EOF
    exit 1
  fi
  printf '%s' "$id"
}

ssm_run() {   # ssm_run '["cmd1","cmd2"]'
  local id cmd status
  id=$(iid)
  cmd=$(aws ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript \
        --parameters "commands=$1" --query 'Command.CommandId' --output text)
  for _ in $(seq 1 30); do
    status=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" \
             --query 'Status' --output text 2>/dev/null || echo Pending)
    [[ "$status" == "Success" || "$status" == "Failed" ]] && break
    sleep 4
  done
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" \
      --query 'StandardOutputContent' --output text
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" \
      --query 'StandardErrorContent' --output text | sed '/^$/d'
}

case "${1:-help}" in

start)   # port-forward the demo page over SSM - no inbound ports, no SSH key
  echo "Opening http://localhost:${LOCAL_PORT} ...   Ctrl-C to stop."
  aws ssm start-session --target "$(iid)" \
    --document-name AWS-StartPortForwardingSession \
    --parameters "{\"portNumber\":[\"8080\"],\"localPortNumber\":[\"${LOCAL_PORT}\"]}"
  ;;

files)   # what Vault Agent wrote onto the instance, secrets masked
  ssm_run '["ls -l /etc/app/secrets/; echo; for f in /etc/app/secrets/*; do echo \"== $f\"; sudo -u demoapp cat $f; echo; done"]' \
   | sed -E 's/"secret_key":"[^"]*"/"secret_key":"<MASKED>"/g; s/"session_token":"[^"]*"/"session_token":"<MASKED>"/g'
  ;;

status)
  echo "instance: $(iid)"
  ssm_run '["systemctl is-active vault-agent demo-app; echo; systemctl status vault-agent --no-pager -n 3 | head -6"]'
  ;;

logs)    # the agent log: every login, renewal and render
  ssm_run '["journalctl -u vault-agent --no-pager -n 40"]'
  ;;

renders) # just the render events - run twice a minute apart to show rotation
  ssm_run '["journalctl -u vault-agent --no-pager | grep rendered | tail -12"]'
  ;;

applogs)
  ssm_run '["journalctl -u demo-app --no-pager -n 30"]'
  ;;

config)  # the agent configuration in force
  ssm_run '["cat /etc/vault-agent/agent.hcl"]'
  ;;

session) # interactive shell on the instance
  aws ssm start-session --target "$(iid)"
  ;;

reload)  # push a local app/app.py change onto the instance
  python3 - "$HERE/app/app.py" <<'PY' > /tmp/ec2-params.json
import base64, json, sys
b64 = base64.b64encode(open(sys.argv[1], "rb").read()).decode()
cmds = ["rm -f /tmp/app.b64"]
cmds += [f"printf '%s' '{b64[i:i+3000]}' >> /tmp/app.b64" for i in range(0, len(b64), 3000)]
cmds += ["base64 -d /tmp/app.b64 > /opt/demo/app.py",
         "chown demoapp:demoapp /opt/demo/app.py",
         "python3 -m py_compile /opt/demo/app.py && echo compiled",
         "systemctl restart demo-app", "sleep 4", "systemctl is-active demo-app"]
json.dump({"commands": cmds}, open("/dev/stdout", "w"))
PY
  id=$(iid)
  cmd=$(aws ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript \
        --parameters file:///tmp/ec2-params.json --query 'Command.CommandId' --output text)
  for _ in $(seq 1 30); do
    s=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query Status --output text 2>/dev/null || echo Pending)
    [[ "$s" == Success || "$s" == Failed ]] && break; sleep 4
  done
  echo "[$s]"
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query StandardOutputContent --output text
  ;;

destroy)
  read -rp "Terminate the EC2 demo host and its IAM role? [y/N] " ok
  [[ "$ok" == y || "$ok" == Y ]] || { echo aborted; exit 0; }
  id=$(iid); aws ec2 terminate-instances --instance-ids "$id" >/dev/null
  aws ec2 wait instance-terminated --instance-ids "$id"; echo "terminated $id"
  aws ec2 delete-security-group --group-name ec2-demo-sg 2>/dev/null && echo "sg deleted" || true
  aws iam remove-role-from-instance-profile --instance-profile-name ec2-demo-profile --role-name ec2-demo-role 2>/dev/null || true
  aws iam delete-instance-profile --instance-profile-name ec2-demo-profile 2>/dev/null || true
  aws iam detach-role-policy --role-name ec2-demo-role --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null || true
  aws iam delete-role --role-name ec2-demo-role 2>/dev/null && echo "iam role deleted" || true
  echo "Vault objects left in place: auth/aws-ec2 and its role. Remove with:"
  echo "  vault auth disable aws-ec2"
  ;;

*)
  cat <<'EOF'
Vault on EC2 - demo helper

  ./scripts/demo.sh start      port-forward the page to localhost:8082  <-- use this to demo
  ./scripts/demo.sh files      the credential files Vault Agent wrote (masked)
  ./scripts/demo.sh renders    just the render events - run twice to show rotation
  ./scripts/demo.sh status     vault-agent and demo-app service state
  ./scripts/demo.sh logs       full agent log: login, renewals, renders
  ./scripts/demo.sh applogs    application log
  ./scripts/demo.sh config     the agent configuration on the host
  ./scripts/demo.sh session    interactive shell on the instance (SSM)
  ./scripts/demo.sh reload     push local app/app.py to the instance
  ./scripts/demo.sh destroy    terminate the instance and remove its IAM role

No inbound ports and no SSH key: everything goes through SSM Session Manager.
EOF
  ;;
esac
