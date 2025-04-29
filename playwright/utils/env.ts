// utils/env.ts
export function determineUrl(): string {
  const branch = process.env.GIT_BRANCH || '';
  const insideDocker = process.env.PW_DOCKER === 'true';
  const insideECS = process.env.PW_ECS;

  if (insideECS) {
    if (branch === 'integration') {
      return 'https://integration.crossfeed.cyber.dhs.gov';
    }
    return 'https://staging-cd.crossfeed.cyber.dhs.gov';
  }

  if (insideDocker) {
    return 'http://xfd-frontend-1:3000';
  }

  return 'http://localhost';
}

export function determineHeadless(): boolean {
  const insideDocker = process.env.PW_DOCKER === 'true';
  const insideECS = process.env.PW_ECS === 'true' || !!process.env.AWS_REGION;
  return insideDocker || insideECS;
}
