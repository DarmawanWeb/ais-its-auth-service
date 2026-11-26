import type { Paginated } from '@darmawanweb/ais-its-contracts/api';
import type { ApiKeyIntrospectionResult } from '@darmawanweb/ais-its-contracts/auth';
import {
  CurrentPrincipal,
  Internal,
  type Principal,
  RequirePermissions,
} from '@darmawanweb/ais-its-nest/auth';
import { ApiPageResponse, UuidParam } from '@darmawanweb/ais-its-nest/http';
import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import {
  ApiBody,
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';

import { ApiKeysService } from './api-keys.service.js';
import {
  ApiKeyDto,
  ApiKeyIntrospectionDto,
  CreateApiKeyDto,
  CreatedApiKeyDto,
  IntrospectApiKeyDto,
  ListApiKeysQuery,
  RotateApiKeyDto,
} from './dto/api-key.dto.js';

/** API keys of the organization: `/api/v2/api-keys` (`api_key:manage`). */
@ApiTags('api-keys')
@Controller('api-keys')
export class ApiKeysController {
  constructor(private readonly keys: ApiKeysService) {}

  @Get()
  @RequirePermissions('api_key:manage')
  @ApiOperation({
    summary:
      'List the API keys of the active organization (super admins: all or ?orgId)',
  })
  @ApiPageResponse(ApiKeyDto)
  async list(
    @Query() query: ListApiKeysQuery,
    @CurrentPrincipal() principal: Principal,
  ): Promise<Paginated<ApiKeyDto>> {
    const { page, pageSize, orgId, includeRevoked } = query;
    const result = await this.keys.list(
      principal,
      { orgId, includeRevoked },
      { page, pageSize },
    );
    const now = new Date();
    return {
      data: result.data.map((row) => new ApiKeyDto(row, now)),
      meta: result.meta,
    };
  }

  @Post()
  @RequirePermissions('api_key:manage')
  @ApiOperation({
    summary: 'Create an API key (the key is returned once)',
    description:
      'org_admins create keys in their active organization with the scopes telemetry:ingest and ais:read; ais:ingest (the AIS feed shared by every tenant) is granted by super admins only. ' +
      'An optional expiresAt (in the future) ends the key: introspection treats it as inactive from then on (status expired).',
  })
  @ApiCreatedResponse({ type: CreatedApiKeyDto })
  @ApiForbiddenResponse({
    description:
      'SCOPE_NOT_GRANTABLE (ais:ingest requested by a non super admin), or another organization than the active one',
  })
  async create(
    @Body() body: CreateApiKeyDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<CreatedApiKeyDto> {
    const created = await this.keys.create(
      principal,
      {
        name: body.name,
        scopes: body.scopes,
        orgId: body.orgId,
        expiresAt:
          body.expiresAt === undefined ? undefined : new Date(body.expiresAt),
      },
      request,
    );
    return new CreatedApiKeyDto(created.row, created.key);
  }

  @Post(':id/rotate')
  @HttpCode(HttpStatus.OK)
  @RequirePermissions('api_key:manage')
  @ApiOperation({
    summary: 'Give an API key a new secret (returned once)',
    description:
      'The key keeps its id, prefix, name, scopes and expiry, so only the secret changes on the device. The replaced secret keeps ' +
      'working for gracePeriodMin minutes (default 1440 = 24 h, 0 = stops at once; previousKeyExpiresAt in the answer); rotating ' +
      'again during a grace period ends the older secret at once. Other services cache an active key for up to 60 s, so the ' +
      'replaced secret may still pass there for that long after its grace period. A key with a scope the caller could not grant ' +
      '(ais:ingest for org_admins) cannot be rotated by them.',
  })
  // The body may be omitted (default grace period): not `required` for generated clients.
  @ApiBody({ type: RotateApiKeyDto, required: false })
  @ApiOkResponse({ type: CreatedApiKeyDto })
  @ApiNotFoundResponse({ description: 'API_KEY_NOT_FOUND' })
  @ApiForbiddenResponse({ description: 'SCOPE_NOT_GRANTABLE' })
  @ApiConflictResponse({ description: 'API_KEY_INACTIVE (revoked or expired)' })
  async rotate(
    @UuidParam() id: string,
    @Body() body: RotateApiKeyDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<CreatedApiKeyDto> {
    const rotated = await this.keys.rotate(
      principal,
      id,
      { gracePeriodMin: body.gracePeriodMin },
      request,
    );
    return new CreatedApiKeyDto(rotated.row, rotated.key);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermissions('api_key:manage')
  @ApiOperation({ summary: 'Revoke an API key' })
  @ApiNoContentResponse()
  async revoke(
    @UuidParam() id: string,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.keys.revoke(principal, id, request);
  }
}

/** Service-to-service introspection: `/internal/api-keys` (`X-Internal-Token`, not routed by the gateway). */
@ApiTags('internal')
@ApiSecurity('internalToken')
@Controller('internal/api-keys')
export class InternalApiKeysController {
  constructor(private readonly keys: ApiKeysService) {}

  @Post('introspect')
  @Internal()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'Resolve an API key to its organization and scopes (services only)',
  })
  @ApiOkResponse({ type: ApiKeyIntrospectionDto })
  introspect(
    @Body() body: IntrospectApiKeyDto,
  ): Promise<ApiKeyIntrospectionResult> {
    return this.keys.introspect(body.key);
  }
}
