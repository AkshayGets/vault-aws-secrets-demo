#!/usr/bin/env bash
# Demo v2 (Vault Agent Injector) helper.  Usage: ./scripts/demo-agent.sh <command>
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-https://vault.example.com}"
export VAULT_NAMESPACE="${VAULT_NAMESPACE:-apps}"
export AWS_PROFILE="${AWS_PROFILE:-vault-demo}"
NS=demo-apps
DEP=demo-app-agent
HERE="$(cd "$(dirname "$0")/.." && pwd)"

case "${1:-help}" in

start)   # port 8081, so v1 on 8080 can run side by side
  echo "Opening http://localhost:8081 ...  (v1 runs on 8080 - show them together)"
  echo "Ctrl-C to stop."
  kubectl port-forward -n $NS svc/$DEP 8081:8080
  ;;

files)   # the money shot: what the sidecar actually wrote into the pod
  echo "--- /vault/secrets (secrets masked) ---"
  kubectl exec -n $NS deploy/$DEP -c app -- sh -c 'ls -l /vault/secrets/; echo; for f in /vault/secrets/*; do echo "== $f"; cat "$f"; echo; done' \
    | sed -E 's/"secret_key":"[^"]*"/"secret_key":"<MASKED>"/g; s/"session_token":"[^"]*"/"session_token":"<MASKED>"/g'
  ;;

config)  # what the injector actually generated - the only reliable way to verify annotations
  POD=$(kubectl get pod -n $NS -l app=$DEP --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}')
  echo "pod: $POD"
  kubectl exec -n $NS "$POD" -c vault-agent -- sh -c 'echo "$VAULT_CONFIG" | base64 -d' \
    | python3 -m json.tool
  ;;

status)
  kubectl get pods -n $NS -l app=$DEP
  echo "--- containers (app + injected sidecar) ---"
  kubectl get pod -n $NS -l app=$DEP \
    -o jsonpath='{range .items[0].spec.initContainers[*]}init: {.name}{"\n"}{end}{range .items[0].spec.containers[*]}     {.name}{"\n"}{end}'
  ;;

logs)    # the sidecar's own log - shows each render and lease renewal
  kubectl logs -f -n $NS deploy/$DEP -c vault-agent
  ;;

applogs)
  kubectl logs -f -n $NS deploy/$DEP -c app
  ;;

reload)  # push local app-agent/app.py into the cluster
  kubectl create configmap demo-app-agent-code -n $NS \
    --from-file=app.py="$HERE"/app-agent/app.py --dry-run=client -o yaml | kubectl apply -f -
  kubectl rollout restart deploy/$DEP -n $NS
  kubectl rollout status  deploy/$DEP -n $NS
  ;;

deploy)  # first-time (or after teardown) deploy of v2
  kubectl create configmap demo-app-agent-code -n $NS \
    --from-file=app.py="$HERE"/app-agent/app.py --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -f "$HERE"/k8s/deployment-agent.yaml
  kubectl rollout status deploy/$DEP -n $NS --timeout=180s
  ;;

delete)
  kubectl delete -f "$HERE"/k8s/deployment-agent.yaml --ignore-not-found
  kubectl delete configmap demo-app-agent-code -n $NS --ignore-not-found
  ;;

*)
  cat <<'EOF'
Vault demo v2 - Vault Agent Injector

  ./scripts/demo-agent.sh start     port-forward to localhost:8081  <-- use this to demo
  ./scripts/demo-agent.sh files     show the files the sidecar wrote into the pod
  ./scripts/demo-agent.sh config    show the agent config the injector generated
  ./scripts/demo-agent.sh status    pod + the injected init container and sidecar
  ./scripts/demo-agent.sh logs      tail the vault-agent sidecar (renders, renewals)
  ./scripts/demo-agent.sh applogs   tail the application container
  ./scripts/demo-agent.sh reload    push local app-agent/app.py into the cluster
  ./scripts/demo-agent.sh deploy    deploy v2 from scratch
  ./scripts/demo-agent.sh delete    remove v2 (leaves Vault and AWS untouched)

v1 runs on 8080, v2 on 8081. Running both at once is the clearest way to show the difference.
EOF
  ;;
esac
