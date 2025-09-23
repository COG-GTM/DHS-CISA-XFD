// playwright/.auth/userRoles.ts

export const userRoles = [
  {
    role: 'global-admin',
    username: process.env.PW_GLOBAL_ADMIN_USERNAME!,
    password: process.env.PW_GLOBAL_ADMIN_PASSWORD!,
    totpSecret: process.env.PW_GLOBAL_ADMIN_2FA_SECRET!
  }
];
