#!/usr/bin/env bash

set -euo pipefail

echo "🔁 Cloning into Crossfeed..."
# Clone Playwright test repo and install dependencies
# Ensure a clean clone target
rm -rf /app/xfd
mkdir -p /app/xfd

git clone --branch "$GIT_BRANCH" https://github.com/cisagov/xfd.git /app/xfd
cd /app/xfd/playwright
npm ci
npx playwright install --with-deps

echo "🔁 Running Playwright tests..."
npx playwright test

echo "📤 Uploading results to S3..."

if [[ -d "./playwright-report/html" ]]; then
  aws s3 cp ./playwright-report/html "$S3_HTML_PATH" --recursive --region "$AWS_REGION"
  aws s3 cp ./playwright-report/html "s3://$AUTOMATED_TEST_REPORTS_BUCKET_NAME/$ENVIRONMENT/playwright-reports/latest/html/" --recursive --region "$AWS_REGION"
else
  echo "⚠️ No HTML report found at ./playwright-report/html"
fi

if [[ -f "./playwright-report/results.json" ]]; then
  aws s3 cp ./playwright-report/results.json "$S3_JSON_PATH" --region "$AWS_REGION"
  aws s3 cp ./playwright-report/results.json "s3://$AUTOMATED_TEST_REPORTS_BUCKET_NAME/$ENVIRONMENT/playwright-reports/latest/results.json" --region "$AWS_REGION"
else
  echo "⚠️ No results.json file found!"
fi

echo "✅ Tests completed and uploaded."
