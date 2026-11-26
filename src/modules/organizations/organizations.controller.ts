import type { Paginated } from '@darmawanweb/ais-its-contracts/api';
import {
  CurrentPrincipal,
  type Principal,
  RequirePermissions,
} from '@darmawanweb/ais-its-nest/auth';
import {
  ApiPageResponse,
  PageQueryDto,
  UuidParam,
} from '@darmawanweb/ais-its-nest/http';
import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Patch,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import {
  ApiBody,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnprocessableEntityResponse,
} from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';

import {
  CreateOrganizationDto,
  InvitationDto,
  InviteMemberDto,
  ListOrganizationsQuery,
  MemberDto,
  OrganizationDto,
  OrganizationListItemDto,
  OrganizationStatsDto,
  OrganizationStatsQuery,
  ResendInvitationDto,
  SentInvitationDto,
  UpdateMemberDto,
  UpdateOrganizationDto,
} from './dto/organization.dto.js';
import { MembersService } from './members.service.js';
import { OrganizationsService } from './organizations.service.js';

/** The invitation e-mail budget (`AuthThrottle.consumeInvitationEmail`), as the routes that send one describe it. */
const INVITATION_EMAIL_LIMIT =
  'At most 4 invitation e-mails per address and organization and hour: the invitation and 3 more, whether resent, ' +
  'renewed by inviting the pending address again, or sent anew after a withdrawal (429 RATE_LIMITED with Retry-After beyond).';

/** Organizations (tenants): `/api/v2/organizations`. */
@ApiTags('organizations')
@Controller('organizations')
export class OrganizationsController {
  constructor(private readonly organizations: OrganizationsService) {}

  @Get()
  @RequirePermissions('org:manage')
  @ApiOperation({
    summary:
      'List organizations with their member and API key counts (super admins)',
  })
  @ApiPageResponse(OrganizationListItemDto)
  async list(
    @Query() query: ListOrganizationsQuery,
  ): Promise<Paginated<OrganizationListItemDto>> {
    const { page, pageSize, search, kind } = query;
    const result = await this.organizations.list(
      { search, kind },
      { page, pageSize },
    );
    return {
      data: result.data.map((row) => new OrganizationListItemDto(row)),
      meta: result.meta,
    };
  }

  @Get('stats')
  @RequirePermissions('org:manage')
  @ApiOperation({
    summary: 'Organizations per kind over every page (super admins)',
    description:
      'The counts of the GET /organizations header: total and per kind (every kind listed, 0 included), optionally of the organizations matching search.',
  })
  @ApiOkResponse({ type: OrganizationStatsDto })
  async stats(
    @Query() query: OrganizationStatsQuery,
  ): Promise<OrganizationStatsDto> {
    return new OrganizationStatsDto(
      await this.organizations.stats({ search: query.search }),
    );
  }

  @Post()
  @RequirePermissions('org:manage')
  @ApiOperation({ summary: 'Create an organization (super admins)' })
  @ApiCreatedResponse({ type: OrganizationDto })
  async create(
    @Body() body: CreateOrganizationDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<OrganizationDto> {
    return new OrganizationDto(
      await this.organizations.create(body, principal, request),
    );
  }

  /** No permission decorator: members read their own organization, the service checks. */
  @Get(':id')
  @ApiOperation({
    summary: 'Get an organization (super admins, or its members)',
  })
  @ApiOkResponse({ type: OrganizationDto })
  async get(
    @UuidParam() id: string,
    @CurrentPrincipal() principal: Principal,
  ): Promise<OrganizationDto> {
    return new OrganizationDto(await this.organizations.get(id, principal));
  }

  @Patch(':id')
  @RequirePermissions('org:manage')
  @ApiOperation({
    summary: 'Change the name, slug or kind of an organization (super admins)',
  })
  @ApiOkResponse({ type: OrganizationDto })
  async update(
    @UuidParam() id: string,
    @Body() body: UpdateOrganizationDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<OrganizationDto> {
    return new OrganizationDto(
      await this.organizations.update(id, body, principal, request),
    );
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermissions('org:manage')
  @ApiOperation({
    summary:
      'Delete an organization with its memberships and API keys (super admins)',
  })
  @ApiNoContentResponse()
  async remove(
    @UuidParam() id: string,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.organizations.remove(id, principal, request);
  }
}

/** Members of an organization: `/api/v2/organizations/:id/members` (`user:manage`). */
@ApiTags('organizations')
@Controller('organizations/:id/members')
export class MembersController {
  constructor(private readonly members: MembersService) {}

  @Get()
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'List the members of an organization' })
  @ApiPageResponse(MemberDto)
  async list(
    @UuidParam() orgId: string,
    @Query() query: PageQueryDto,
    @CurrentPrincipal() principal: Principal,
  ): Promise<Paginated<MemberDto>> {
    const result = await this.members.list(orgId, query, principal);
    return {
      data: result.data.map((record) => new MemberDto(record)),
      meta: result.meta,
    };
  }

  @Post()
  @RequirePermissions('user:manage')
  @ApiOperation({
    summary: 'Invite an address to the organization (it joins on acceptance)',
    description:
      'Creates an invited account for unknown addresses and e-mails an invitation link (accepted with POST /auth/password/reset). Existing accounts are never attached directly, and the answer is the same for new and existing addresses. Inviting a pending address again renews its link. ' +
      INVITATION_EMAIL_LIMIT,
  })
  @ApiCreatedResponse({ type: SentInvitationDto })
  @ApiConflictResponse({
    description: 'MEMBER_ALREADY_EXISTS, INVITATION_CONFLICT (retry)',
  })
  @ApiUnprocessableEntityResponse({ description: 'ROLE_NOT_GRANTABLE' })
  @ApiTooManyRequestsResponse({ description: 'RATE_LIMITED (Retry-After)' })
  async invite(
    @UuidParam() orgId: string,
    @Body() body: InviteMemberDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<SentInvitationDto> {
    const sent = await this.members.invite(orgId, body, principal, request);
    return new SentInvitationDto(sent.record, sent.invitationSent);
  }

  @Patch(':userId')
  @RequirePermissions('user:manage')
  @ApiOperation({
    summary: "Change a member's role (the last org_admin cannot be demoted)",
  })
  @ApiOkResponse({ type: MemberDto })
  async update(
    @UuidParam() orgId: string,
    @UuidParam('userId') userId: string,
    @Body() body: UpdateMemberDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<MemberDto> {
    return new MemberDto(
      await this.members.changeRole(
        orgId,
        userId,
        body.role,
        principal,
        request,
      ),
    );
  }

  @Delete(':userId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermissions('user:manage')
  @ApiOperation({
    summary:
      'Remove a member (not the last org_admin) and revoke their sessions in the organization',
  })
  @ApiNoContentResponse()
  async remove(
    @UuidParam() orgId: string,
    @UuidParam('userId') userId: string,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.members.remove(orgId, userId, principal, request);
  }
}

/** Pending invitations of an organization: `/api/v2/organizations/:id/invitations` (`user:manage`). */
@ApiTags('organizations')
@Controller('organizations/:id/invitations')
export class InvitationsController {
  constructor(private readonly members: MembersService) {}

  @Get()
  @RequirePermissions('user:manage')
  @ApiOperation({
    summary: 'List the pending invitations of an organization, newest first',
  })
  @ApiPageResponse(InvitationDto)
  async list(
    @UuidParam() orgId: string,
    @Query() query: PageQueryDto,
    @CurrentPrincipal() principal: Principal,
  ): Promise<Paginated<InvitationDto>> {
    const result = await this.members.listInvitations(orgId, query, principal);
    const now = new Date();
    return {
      data: result.data.map((record) => new InvitationDto(record, now)),
      meta: result.meta,
    };
  }

  @Post(':invitationId/resend')
  @HttpCode(HttpStatus.OK)
  @RequirePermissions('user:manage')
  @ApiOperation({
    summary: 'Send an invitation again with a new link',
    description:
      'Renews a pending or expired invitation: a new link valid INVITE_TTL_HOURS replaces the previous one (which stops ' +
      'working), role and name stay, the sender becomes the inviter. The role is checked again against the kind of the ' +
      'organization. The body may be omitted. ' +
      INVITATION_EMAIL_LIMIT,
  })
  // The body may be omitted (default locale): not `required` for generated clients.
  @ApiBody({ type: ResendInvitationDto, required: false })
  @ApiOkResponse({ type: SentInvitationDto })
  @ApiNotFoundResponse({
    description: 'INVITATION_NOT_FOUND (also once accepted or withdrawn)',
  })
  @ApiUnprocessableEntityResponse({ description: 'ROLE_NOT_GRANTABLE' })
  @ApiTooManyRequestsResponse({ description: 'RATE_LIMITED (Retry-After)' })
  async resend(
    @UuidParam() orgId: string,
    @UuidParam('invitationId') invitationId: string,
    @Body() body: ResendInvitationDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<SentInvitationDto> {
    const sent = await this.members.resendInvitation(
      orgId,
      invitationId,
      body.locale,
      principal,
      request,
    );
    return new SentInvitationDto(sent.record, sent.invitationSent);
  }

  @Delete(':invitationId')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermissions('user:manage')
  @ApiOperation({ summary: 'Withdraw an invitation (its link stops working)' })
  @ApiNoContentResponse()
  async cancel(
    @UuidParam() orgId: string,
    @UuidParam('invitationId') invitationId: string,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.members.cancelInvitation(
      orgId,
      invitationId,
      principal,
      request,
    );
  }
}
