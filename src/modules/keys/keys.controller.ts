import { JWKS_PATH } from '@darmawanweb/ais-its-contracts/auth';
import {
  CurrentPrincipal,
  type Principal,
  Public,
} from '@darmawanweb/ais-its-nest/auth';
import {
  Controller,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Post,
  Req,
} from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';

import { JwksDto, KeyRotationDto } from './dto/jwks.dto.js';
import { KeysService } from './keys.service.js';
import { SigningKeyStore } from './signing-key.store.js';

/** `GET /.well-known/jwks.json` (outside the `/api/v2` prefix, spec §5). */
@ApiTags('keys')
@Controller()
export class JwksController {
  constructor(private readonly keys: SigningKeyStore) {}

  @Get(JWKS_PATH.slice(1))
  @Public()
  @Header('Cache-Control', 'public, max-age=60')
  @ApiOperation({
    summary:
      'Public keys of the access token signer (active and retiring keys)',
  })
  @ApiOkResponse({ type: JwksDto })
  async jwks(): Promise<JwksDto> {
    return new JwksDto(await this.keys.jwks());
  }
}

/** Signing key administration: `/api/v2/auth/keys`. */
@ApiTags('keys')
@Controller('auth/keys')
export class KeysController {
  constructor(private readonly keys: KeysService) {}

  @Post('rotate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'Rotate the signing key (super_admin): the active key becomes retiring',
  })
  @ApiOkResponse({ type: KeyRotationDto })
  async rotate(
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<KeyRotationDto> {
    return new KeyRotationDto(await this.keys.rotate(principal, request));
  }
}
