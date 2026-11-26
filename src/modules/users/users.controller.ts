import type { Paginated } from '@darmawanweb/ais-its-contracts/api';
import {
  CurrentPrincipal,
  type Principal,
  RequirePermissions,
} from '@darmawanweb/ais-its-nest/auth';
import { ApiPageResponse, UuidParam } from '@darmawanweb/ais-its-nest/http';
import { Body, Controller, Get, Patch, Query, Req } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';

import { requireUser } from '../../common/principals.js';
import {
  ListUsersQuery,
  UpdateMeDto,
  UpdateUserStatusDto,
} from './dto/user-input.dto.js';
import { DirectoryUserDto, MeDto } from './dto/user.dto.js';
import { type Profile, UsersService } from './users.service.js';

/** The signed-in user: `/api/v2/me`. */
@ApiTags('me')
@Controller('me')
export class MeController {
  constructor(private readonly users: UsersService) {}

  @Get()
  @ApiOperation({
    summary:
      'The signed-in user, memberships, active organization, roles and permissions',
  })
  @ApiOkResponse({ type: MeDto })
  async me(@CurrentPrincipal() principal: Principal): Promise<MeDto> {
    return meDto(principal, await this.users.profile(principal));
  }

  @Patch()
  @ApiOperation({ summary: 'Change the own display name' })
  @ApiOkResponse({ type: MeDto })
  async update(
    @Body() body: UpdateMeDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<MeDto> {
    return meDto(
      principal,
      await this.users.rename(principal, body.name, request),
    );
  }
}

/** The platform user directory: `/api/v2/users` (`org:manage`). */
@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  @RequirePermissions('org:manage')
  @ApiOperation({
    summary: 'Search the users of the platform (super admins)',
    description:
      'Filters: search (e-mail or name), status, ids (batch lookup of up to 100 ids, e.g. the actors of a page of audit records), orgId (members of an organization).',
  })
  @ApiPageResponse(DirectoryUserDto)
  async list(
    @Query() query: ListUsersQuery,
  ): Promise<Paginated<DirectoryUserDto>> {
    const { page, pageSize, search, status, ids, orgId } = query;
    const result = await this.users.list(
      { search, status, ids, orgId },
      { page, pageSize },
    );
    return {
      data: result.data.map(
        (entry) => new DirectoryUserDto(entry.user, entry.memberships),
      ),
      meta: result.meta,
    };
  }

  @Patch(':id')
  @RequirePermissions('org:manage')
  @ApiOperation({
    summary: 'Enable or disable an account (disabling revokes its sessions)',
  })
  @ApiOkResponse({ type: DirectoryUserDto })
  async setStatus(
    @UuidParam() id: string,
    @Body() body: UpdateUserStatusDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<DirectoryUserDto> {
    const entry = await this.users.setStatus(
      id,
      body.status,
      principal,
      request,
    );
    return new DirectoryUserDto(entry.user, entry.memberships);
  }
}

function meDto(principal: Principal, profile: Profile): MeDto {
  const user = requireUser(principal);
  return new MeDto(profile.user, profile.memberships, {
    activeOrgId: user.orgId,
    roles: user.roles,
    permissions: user.permissions,
  });
}
