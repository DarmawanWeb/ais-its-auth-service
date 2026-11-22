import { RateLimitedError } from '@darmawanweb/ais-its-nest';
import {
  FixedWindowRateLimiter,
  guardAttempt,
  InjectRedis,
  type Redis,
  SlidingWindowRateLimiter,
} from '@darmawanweb/ais-its-nest/redis';
import { Injectable } from '@nestjs/common';

import { sha256Hex } from '../../domain/opaque-token.js';

const MINUTE_MS = 60_000;

/**
 * Throttling limits of the public auth endpoints (spec §8, §13.1). Login
 * limits are from the spec; the others follow the same model.
 *
 * @see docs/PLATFORM_SPEC.md §13.1 (Rules: 5 failures / 15 min per e-mail, 20 / 15 min per IP)
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#protect-against-automated-attacks
 */
export const THROTTLE_LIMITS = Object.freeze({
  /** Failed logins per e-mail. */
  loginPerEmail: { limit: 5, windowMs: 15 * MINUTE_MS },
  /** Failed logins and MFA codes per client IP. */
  loginPerIp: { limit: 20, windowMs: 15 * MINUTE_MS },
  /** Failed MFA codes per account. */
  mfaPerUser: { limit: 5, windowMs: 15 * MINUTE_MS },
  /** Wrong current passwords per account (`POST /auth/password/change`). */
  passwordChangePerUser: { limit: 5, windowMs: 15 * MINUTE_MS },
  /** Forgot-password requests per client IP (429 beyond). */
  forgotPerIp: { limit: 10, windowMs: 15 * MINUTE_MS },
  /** Reset e-mails per address (silently skipped beyond: the answer is always 202). */
  forgotPerEmail: { limit: 3, windowMs: 60 * MINUTE_MS },
  /** Failed password resets and invitation acceptances (bad links) per client IP. */
  resetPerIp: { limit: 10, windowMs: 15 * MINUTE_MS },
});

const THROTTLED_DETAIL = 'Too many failed attempts; try again later';

/**
 * Valkey-backed throttles (kit rate limiters, atomic Lua). Failed attempts
 * are reserved BEFORE the check with `guardAttempt` (no check-then-act
 * race) and refunded on success; a successful login also forgets the
 * e-mail's failures. Keys never contain e-mail addresses in clear (SHA-256).
 */
@Injectable()
export class AuthThrottle {
  private readonly loginEmail: FixedWindowRateLimiter;
  private readonly loginIp: FixedWindowRateLimiter;
  private readonly mfaUser: FixedWindowRateLimiter;
  private readonly passwordUser: FixedWindowRateLimiter;
  private readonly forgotIp: FixedWindowRateLimiter;
  private readonly forgotEmail: SlidingWindowRateLimiter;
  private readonly resetIp: FixedWindowRateLimiter;

  constructor(@InjectRedis() redis: Redis) {
    this.loginEmail = new FixedWindowRateLimiter(redis, {
      name: 'login-email',
      ...THROTTLE_LIMITS.loginPerEmail,
    });
    this.loginIp = new FixedWindowRateLimiter(redis, {
      name: 'login-ip',
      ...THROTTLE_LIMITS.loginPerIp,
    });
    this.mfaUser = new FixedWindowRateLimiter(redis, {
      name: 'mfa-user',
      ...THROTTLE_LIMITS.mfaPerUser,
    });
    this.passwordUser = new FixedWindowRateLimiter(redis, {
      name: 'password-change-user',
      ...THROTTLE_LIMITS.passwordChangePerUser,
    });
    this.forgotIp = new FixedWindowRateLimiter(redis, {
      name: 'forgot-ip',
      ...THROTTLE_LIMITS.forgotPerIp,
    });
    this.forgotEmail = new SlidingWindowRateLimiter(redis, {
      name: 'forgot-email',
      ...THROTTLE_LIMITS.forgotPerEmail,
    });
    this.resetIp = new FixedWindowRateLimiter(redis, {
      name: 'reset-ip',
      ...THROTTLE_LIMITS.resetPerIp,
    });
  }

  /**
   * Runs a password check under the per-IP and per-e-mail failure limits.
   *
   * @throws {RateLimitedError} `429 RATE_LIMITED` (with `Retry-After`) when a limit is exhausted.
   */
  guardLogin<T>(
    email: string,
    ip: string | null,
    attempt: () => Promise<T>,
  ): Promise<T> {
    return guardAttempt(
      this.loginIp,
      ipKey(ip),
      () =>
        guardAttempt(this.loginEmail, emailKey(email), attempt, {
          onSuccess: 'reset',
          detail: THROTTLED_DETAIL,
        }),
      { detail: THROTTLED_DETAIL },
    );
  }

  /** Runs an MFA code check under the per-IP and per-account failure limits. */
  guardMfa<T>(
    userId: string,
    ip: string | null,
    attempt: () => Promise<T>,
  ): Promise<T> {
    return guardAttempt(
      this.loginIp,
      ipKey(ip),
      () =>
        guardAttempt(this.mfaUser, userId, attempt, {
          onSuccess: 'reset',
          detail: THROTTLED_DETAIL,
        }),
      { detail: THROTTLED_DETAIL },
    );
  }

  /** Runs a current-password check of a signed-in user under the per-account limit. */
  guardPasswordChange<T>(
    userId: string,
    attempt: () => Promise<T>,
  ): Promise<T> {
    return guardAttempt(this.passwordUser, userId, attempt, {
      onSuccess: 'reset',
      detail: THROTTLED_DETAIL,
    });
  }

  /**
   * Counts a forgot-password request of a client IP.
   *
   * @throws {RateLimitedError} when the IP sent too many requests.
   */
  async consumeForgotPassword(ip: string | null): Promise<void> {
    const result = await this.forgotIp.consume(ipKey(ip));
    if (!result.allowed) {
      throw new RateLimitedError({
        retryAfterSeconds: result.retryAfterMs / 1000,
        detail: 'Too many password reset requests; try again later',
      });
    }
  }

  /**
   * Runs a password reset or invitation acceptance under the per-IP limit
   * of failed attempts (unknown, used or expired links, disabled accounts);
   * successful attempts are refunded.
   *
   * @throws {RateLimitedError} `429 RATE_LIMITED` (with `Retry-After`) when exhausted.
   */
  guardReset<T>(ip: string | null, attempt: () => Promise<T>): Promise<T> {
    return guardAttempt(this.resetIp, ipKey(ip), attempt, {
      detail: 'Too many invalid or expired links; try again later',
    });
  }

  /** `true` when another reset e-mail may be sent to this address now. */
  async allowResetEmail(email: string): Promise<boolean> {
    return (await this.forgotEmail.consume(emailKey(email))).allowed;
  }
}

function emailKey(email: string): string {
  return sha256Hex(email.toLowerCase()).slice(0, 32);
}

function ipKey(ip: string | null): string {
  return ip ?? 'unknown';
}
