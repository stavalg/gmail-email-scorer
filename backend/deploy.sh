#!/usr/bin/env bash
# Deploys the backend to Cloud Run. Run from the backend/ folder: ./deploy.sh
set -euo pipefail

SERVICE=email-scorer
REGION=us-central1
# Secrets from Secret Manager (filled in by Tasks 16-17). Empty = none.
SECRETS=""

args=(
  run deploy "$SERVICE"
  --source .
  --region "$REGION"
  --allow-unauthenticated   # the network door is open; app/auth.py checks every request
  --max-instances 2         # caps cost if someone floods the URL
  --memory 512Mi
  --env-vars-file env.yaml
)
if [[ -n "$SECRETS" ]]; then
  args+=(--set-secrets "$SECRETS")
fi
# On Windows (Git Bash) the gcloud bash launcher can't find Python; the .cmd launcher works.
GCLOUD=gcloud
if command -v gcloud.cmd >/dev/null 2>&1; then
  GCLOUD=gcloud.cmd
fi
"$GCLOUD" "${args[@]}"
