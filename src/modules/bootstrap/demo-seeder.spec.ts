import { describe, expect, it } from 'vitest';

import { DEV_SEED_DEMO_PASSWORD } from '../../config.js';
import { demoSeedRefusal } from './demo-seeder.js';

describe('demoSeedRefusal (pnpm seed:demo guard)', () => {
  it('lets the seed run outside production', () => {
    for (const NODE_ENV of ['development', 'test']) {
      expect(
        demoSeedRefusal({
          NODE_ENV,
          SEED_DEMO_PASSWORD: DEV_SEED_DEMO_PASSWORD,
          SEED_DEMO_ALLOW_PRODUCTION: false,
        }),
      ).toBeUndefined();
    }
  });

  it('refuses production without the explicit opt-in', () => {
    expect(
      demoSeedRefusal({
        NODE_ENV: 'production',
        SEED_DEMO_PASSWORD: 'OwnSecret2026x',
        SEED_DEMO_ALLOW_PRODUCTION: false,
      }),
    ).toMatch(/SEED_DEMO_ALLOW_PRODUCTION=true/);
  });

  it('refuses production with the documented default password even when opted in', () => {
    expect(
      demoSeedRefusal({
        NODE_ENV: 'production',
        SEED_DEMO_PASSWORD: DEV_SEED_DEMO_PASSWORD,
        SEED_DEMO_ALLOW_PRODUCTION: true,
      }),
    ).toMatch(/default SEED_DEMO_PASSWORD/);
  });

  it('allows production with the opt-in and a password of its own', () => {
    expect(
      demoSeedRefusal({
        NODE_ENV: 'production',
        SEED_DEMO_PASSWORD: 'OwnSecret2026x',
        SEED_DEMO_ALLOW_PRODUCTION: true,
      }),
    ).toBeUndefined();
  });
});
