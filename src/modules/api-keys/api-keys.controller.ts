import type { Paginated } from '@darmawanweb/ais-its-contracts/api';
import type { ApiKeyIntrospectionResult } from '@darmawanweb/ais-its-contracts/auth';
import {
  CurrentPrincipal,
  Internal,
  type Principal,
  RequirePermissions,
} from '@darmawanweb/ais-its-nest/auth';
import { ApiPageResponse } from '@darmawanweb/ais-its-nest/http';
import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import {
  ApiCreatedResponse,
  ApiNoContentResponse,
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
    return {
      data: result.data.map((row) => new ApiKeyDto(row)),
      meta: result.meta,
    };
  }

  @Post()
  @RequirePermissions('api_key:manage')
  @ApiOperation({ summary: 'Create an API key (the key is returned once)' })
  @ApiCreatedResponse({ type: CreatedApiKeyDto })
  async create(
    @Body() body: CreateApiKeyDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<CreatedApiKeyDto> {
    const created = await this.keys.create(principal, body, request);
    return new CreatedApiKeyDto(created.row, created.key);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequirePermissions('api_key:manage')
  @ApiOperation({ summary: 'Revoke an API key' })
  @ApiNoContentResponse()
  async revoke(
    @Param('id', new ParseUUIDPipe()) id: string,
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
