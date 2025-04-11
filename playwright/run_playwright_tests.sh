#!/usr/bin/env bash

set -euo pipefail

# Get the current datetime (e.g., 2025-04-10T12:34:56)
DATETIME=$(date +%Y-%m-%dT%H:%M:%S)

OVERRIDES=$(
  jq -n \
    --arg datetime "$DATETIME" \
    --arg bucket "$AUTOMATED_TEST_REPORTS_BUCKET_NAME" \
    --arg region "$AWS_REGION" \
    '{
    "containerOverrides": [
      {
        "name": "main",
        "environment": [
          { "name": "DATETIME", "value": $datetime },
          { "name": "AUTOMATED_TEST_REPORTS_BUCKET_NAME", "value": $bucket },
          { "name": "AWS_REGION", "value": $region }
        ],
        "command": [
          "sh",
          "-c",
          "echo \"Running Playwright Tests\" && cd /app/xfd/playwright && npx playwright test && echo \"Uploading to S3\" && aws s3 cp ./playwright-report/html s3://$AUTOMATED_TEST_REPORTS_BUCKET_NAME/playwright-reports/$DATETIME/html/ --recursive --region $AWS_REGION && aws s3 cp ./playwright-report/results.json s3://$AUTOMATED_TEST_REPORTS_BUCKET_NAME/playwright-reports/$DATETIME/results.json --region $AWS_REGION && echo \"Test results uploaded successfully to S3 at $DATETIME\""
        ]
      }
    ]
  }'
)

echo "Starting ECS task to run Playwright tests..."

TASK_ARN=$(aws ecs run-task \
  --cluster "$CLUSTER_NAME" \
  --task-definition "$TASK_DEFINITION" \
  --launch-type FARGATE \
  --network-configuration "{
    \"awsvpcConfiguration\":{
      \"subnets\": [\"${AWS_SUBNET}\"],
      \"securityGroups\": [\"${AWS_SECURITY_GROUP}\"],
      \"assignPublicIp\": \"ENABLED\"
    }
  }" \
  --region "${AWS_REGION}" \
  --overrides "$OVERRIDES" \
  --query 'tasks[0].taskArn' \
  --output text 2> /dev/null) || {
  echo "❌ Failed to run ECS task (aws command error)." >&2
  exit 1
}

# Sanity check: ensure the result isn't empty
if [[ -z "$TASK_ARN" || "$TASK_ARN" == "None" ]]; then
  echo "❌ Failed to run ECS task. No ARN returned." >&2
  exit 1
fi

echo "Started ECS Task with ARN: $TASK_ARN"

echo "Waiting for ECS task to complete..."
aws ecs wait tasks-stopped \
  --cluster "$CLUSTER_NAME" \
  --tasks "$TASK_ARN" \
  --region "${AWS_REGION}" || {
  echo "❌ Task did not complete successfully." >&2
  exit 1
}

echo "ECS task $TASK_ARN completed. Uploading test results to S3..."
