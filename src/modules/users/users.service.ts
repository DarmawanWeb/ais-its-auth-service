import {
  type PageQuery,
  type Paginated,
  pageOffset,
  toPaginated,
} from '@darmawanweb/ais-its-contracts/api';
import {
  type AuditRequest,
  AuditService,
} from '@darmawanweb/ais-its-nest/audit';
import type { Principal } from '@darmawanweb/ais-its-nest/auth';
import { type Database, InjectDb } from '@darmawanweb/ais-its-nest/db';
import { Injectable } from '@nestjs/common';

import { AuthErrors } from '../../common/errors.js';
import { requireUser } from '../../common/principals.js';
import type { MembershipRow, UserRow } from '../../db/database.js';
import type * as schema from '../../db/schema.js';
import {
  type MembershipWithOrganization,
  MembershipsRepository,
} from '../accounts/memberships.repository.js';
import { SessionsRepository } from '../accounts/sessions.repository.js';
import {
  type UserFilter,
  UsersRepository,
} from '../accounts/users.repository.js';
import type { SETTABLE_USER_STATUSES } from './dto/user-input.dto.js';

/** The signed-in user's profile (`GET /me`). */
export interface Profile {
  readonly user: UserRow;
  readonly memberships: MembershipWithOrganization[];
}

/** A directory entry (`GET /users`). */
export interface DirectoryEntry {
  readonly user: UserRow;
  readonly memberships: MembershipRow[];
}

/**
 * Accounts: the user's own profile (`/me`) and the platform user directory
 * (`/users`, permission `org:manage`, i.e. super admins).
 */
@Injectable()
export class UsersService {
  constructor(
    @InjectDb() private readonly db: Database<typeof schema>,
    private readonly users: UsersRepository,
    private readonly memberships: MembershipsRepository,
    private readonly sessions: SessionsRepository,
    private readonly audit: AuditService,
  ) {}

  /** The signed-in user with their memberships. */
  async profile(principal: Principal): Promise<Profile> {
    const actor = requireUser(principal);
    const user = await this.users.findById(actor.id);
    if (user === undefined) throw AuthErrors.userNotFound(actor.id);
    return { user, memberships: await this.memberships.listOfUser(user.id) };
  }

  /** Changes the signed-in user's display name. */
  async rename(
    principal: Principal,
    name: string,
    request: AuditRequest,
  ): Promise<Profile> {
    const actor = requireUser(principal);
    const user = await this.users.setName(actor.id, name);
    if (user === undefined) throw AuthErrors.userNotFound(actor.id);
    await this.audit.record(
      {
        action: 'user.update',
        targetType: 'user',
        targetId: user.id,
        meta: { fields: ['name'] },
      },
      actor,
      request,
    );
    return { user, memberships: await this.memberships.listOfUser(user.id) };
  }

  /** One page of the directory with each user's memberships. */
  async list(
    filter: UserFilter,
    page: PageQuery,
  ): Promise<Paginated<DirectoryEntry>> {
    const { rows, total } = await this.users.list(filter, {
      offset: pageOffset(page),
      limit: page.pageSize,
    });
    const memberships = await this.memberships.listOfUsers(
      rows.map((user) => user.id),
    );
    return toPaginated(
      rows.map((user) => ({
        user,
        memberships: memberships.filter(
          (membership) => membership.userId === user.id,
        ),
      })),
      page,
      total,
    );
  }

  /**
   * Enables or disables an account. Disabling revokes every session at once
   * (access tokens expire within `ACCESS_TOKEN_TTL`); re-enabling needs a
   * password (an invited account accepts its invitation instead).
   */
  async setStatus(
    id: string,
    status: (typeof SETTABLE_USER_STATUSES)[number],
    principal: Principal,
    request: AuditRequest,
  ): Promise<DirectoryEntry> {
    const actor = requireUser(principal);
    if (actor.id === id) throw AuthErrors.ownStatus();
    const updated = await this.db.transaction(async (tx) => {
      // Row lock: a reset or invitation acceptance running at the same time
      // waits for this change (and then sees the new status) or precedes it.
      const user = await this.users.lockById(id, tx);
      if (user === undefined) throw AuthErrors.userNotFound(id);
      if (user.status === status) return { user, from: user.status };
      if (
        status === 'active' &&
        (user.status !== 'disabled' || user.passwordHash === null)
      ) {
        throw AuthErrors.statusTransition(user.status, status);
      }
      const changed = await this.users.setStatus(id, status, tx);
      if (changed === undefined) throw AuthErrors.userNotFound(id);
      if (status === 'disabled') await this.sessions.revokeOfUser(id, {}, tx);
      return { user: changed, from: user.status };
    });
    if (updated.from !== status) {
      await this.audit.record(
        {
          action: 'user.status.update',
          targetType: 'user',
          targetId: id,
          orgId: null,
          meta: { from: updated.from, to: status },
        },
        actor,
        request,
      );
    }
    return {
      user: updated.user,
      memberships: await this.memberships.listOfUsers([id]),
    };
  }
}
