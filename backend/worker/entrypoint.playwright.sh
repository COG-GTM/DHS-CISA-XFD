#!/usr/bin/env bash

set -euo pipefail

echo "🔁 Running Playwright tests..."
npx playwright test

echo "📤 Uploading results to S3..."
aws s3 cp ./playwright-report/html "$S3_HTML_PATH" --recursive --region "$AWS_REGION"
aws s3 cp ./playwright-report/results.json "$S3_JSON_PATH" --region "$AWS_REGION"
aws s3 cp ./playwright-report/html "s3://$AUTOMATED_TEST_REPORTS_BUCKET_NAME/playwright-reports/latest/html/" --recursive --region "$AWS_REGION"
aws s3 cp ./playwright-report/results.json "s3://$AUTOMATED_TEST_REPORTS_BUCKET_NAME/playwright-reports/latest/results.json" --region "$AWS_REGION"

echo "✅ Tests completed and uploaded."
