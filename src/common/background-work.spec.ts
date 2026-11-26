import type { Logger } from '@nestjs/common';
import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it, vi } from 'vitest';

import { BackgroundWork } from './background-work.js';

/** A Nest logger stub whose `error` calls land in `error`. */
function logger(error = vi.fn()): Logger {
  return { error } as unknown as Logger;
}

describe('BackgroundWork', () => {
  it('runs work without awaiting it and drains what is in flight', async () => {
    const work = new BackgroundWork(logger());
    let release: () => void = () => undefined;
    let finished = false;
    work.run('slow task', async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      finished = true;
    });
    await Promise.resolve();
    expect(work.size).toBe(1);

    const drained = work.drain();
    release();
    await drained;
    expect(finished).toBe(true);
    expect(work.size).toBe(0);
  });

  it('logs failures instead of rejecting, and waits for tasks started while draining', async () => {
    const error = vi.fn();
    const work = new BackgroundWork(logger(error));
    const order: string[] = [];
    work.run('first', async () => {
      await Promise.resolve();
      order.push('first');
      work.run('second', () => {
        order.push('second');
        return Promise.reject(new Error('boom'));
      });
    });
    await work.drain();
    expect(order).toEqual(['first', 'second']);
    expect(error).toHaveBeenCalledWith(
      { err: expect.any(Error) as Error },
      'second failed: boom',
    );
    expect(work.size).toBe(0);
  });

  it('logs a database failure without the values its statement bound', async () => {
    const error = vi.fn();
    const work = new BackgroundWork(logger(error));
    work.run('Password reset request', () =>
      Promise.reject(
        new DrizzleQueryError(
          'select "id" from "auth"."users" where lower("email") = lower($1)',
          ['victim@example.com'],
          Object.assign(
            new Error('canceling statement due to statement timeout'),
            { code: '57014', severity: 'ERROR' },
          ),
        ),
      ),
    );
    await work.drain();
    expect(error).toHaveBeenCalledWith(
      { err: expect.any(Error) as Error },
      'Password reset request failed: canceling statement due to statement timeout',
    );
    expect(JSON.stringify(error.mock.calls)).not.toContain(
      'victim@example.com',
    );
  });
});
