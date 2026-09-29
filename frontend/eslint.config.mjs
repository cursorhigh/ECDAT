import nextVitals from "eslint-config-next/core-web-vitals";

/**
 * Build output is never source, and it must never be linted.
 *
 * The patterns are `**`-prefixed on purpose. A bare `.next/**` only matches the
 * top-level directory, so a stray nested build (a `next dev` started from the
 * wrong cwd leaves `frontend/frontend/.next`) slips past the ignore and lints as
 * if it were source. That produced 200+ phantom errors -- compiled `module`
 * assignments and references to rules that do not exist -- all pointing at
 * generated chunks rather than at anything worth fixing.
 */
const config = [
  ...nextVitals,
  {
    ignores: [
      "**/.next/**",
      "**/out/**",
      "**/build/**",
      "**/dist/**",
      "**/node_modules/**",
      "next-env.d.ts",
    ],
  },
];

export default config;
