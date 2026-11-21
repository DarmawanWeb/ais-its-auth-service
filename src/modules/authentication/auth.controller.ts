import { HTTP_HEADERS } from '@darmawanweb/ais-its-contracts/auth';
import type { Paginated } from '@darmawanweb/ais-its-contracts/api';
import {
  CurrentPrincipal,
  type Principal,
  Public,
} from '@darmawanweb/ais-its-nest/auth';
import { ApiPageResponse, PageQueryDto } from '@darmawanweb/ais-its-nest/http';
import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  ApiCookieAuth,
  ApiExtraModels,
  ApiForbiddenResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnauthorizedResponse,
  getSchemaPath,
} from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { REFRESH_COOKIE_NAME } from '../../domain/refresh-cookie.js';
import { MfaService } from '../mfa/mfa.service.js';
import { AccountSessionsService } from '../sessions/account-sessions.service.js';
import { SessionService } from '../sessions/session.service.js';
import {
  AuthenticationService,
  type SignedIn,
} from './authentication.service.js';
import { CookieOriginGuard } from './cookie-origin.guard.js';
import {
  AccessTokenDto,
  LoginDto,
  LoginResponseDto,
  MfaChallengeDto,
  MfaCodeDto,
  MfaSetupDto,
  MfaVerifyDto,
  SessionDto,
  SwitchOrganizationDto,
  SwitchOrganizationResponseDto,
  VerifiedTokenDto,
} from './dto/auth.dto.js';
import { ForwardAuthService } from './forward-auth.service.js';
import { RefreshCookieJar } from './refresh-cookie.js';

/**
 * Sign-in, sessions and tokens: `/api/v2/auth` (spec §13.1). The refresh
 * token travels only in the `aisits_rt` cookie (`Path=/api/v2/auth`).
 */
@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authentication: AuthenticationService,
    private readonly sessions: SessionService,
    private readonly cookies: RefreshCookieJar,
  ) {}

  @Post('login')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'Sign in with e-mail and password (sets the refresh cookie, or asks for the MFA code)',
  })
  @ApiExtraModels(LoginResponseDto, MfaChallengeDto)
  @ApiOkResponse({
    schema: {
      oneOf: [
        { $ref: getSchemaPath(LoginResponseDto) },
        { $ref: getSchemaPath(MfaChallengeDto) },
      ],
    },
  })
  @ApiUnauthorizedResponse({ description: 'INVALID_CREDENTIALS' })
  @ApiTooManyRequestsResponse({ description: 'RATE_LIMITED (Retry-After)' })
  async login(
    @Body() body: LoginDto,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<LoginResponseDto | MfaChallengeDto> {
    const result = await this.authentication.login(
      body.email,
      body.password,
      request,
    );
    if (result.kind === 'mfa_required')
      return new MfaChallengeDto(result.mfaToken);
    return this.signedIn(result, reply);
  }

  @Post('mfa/verify')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'Complete an MFA sign-in with the TOTP code (sets the refresh cookie)',
  })
  @ApiOkResponse({ type: LoginResponseDto })
  @ApiUnauthorizedResponse({
    description: 'INVALID_MFA_CODE or an invalid MFA token',
  })
  @ApiTooManyRequestsResponse({ description: 'RATE_LIMITED (Retry-After)' })
  async verifyMfa(
    @Body() body: MfaVerifyDto,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<LoginResponseDto> {
    return this.signedIn(
      await this.authentication.verifyMfa(body.mfaToken, body.code, request),
      reply,
    );
  }

  @Post('refresh')
  @Public()
  @UseGuards(CookieOriginGuard)
  @HttpCode(HttpStatus.OK)
  @ApiCookieAuth(REFRESH_COOKIE_NAME)
  @ApiOperation({
    summary: 'Rotate the refresh cookie and get a new access token',
  })
  @ApiOkResponse({ type: AccessTokenDto })
  @ApiUnauthorizedResponse({
    description:
      'INVALID_REFRESH_TOKEN or REFRESH_TOKEN_REUSED (session revoked)',
  })
  @ApiForbiddenResponse({ description: 'ORIGIN_NOT_ALLOWED, ACCOUNT_DISABLED' })
  async refresh(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<AccessTokenDto> {
    try {
      const refreshed = await this.sessions.refresh(
        this.cookies.read(request),
        request,
      );
      this.cookies.set(reply, refreshed.refresh.token);
      return new AccessTokenDto(refreshed.access);
    } catch (error) {
      this.cookies.clear(reply);
      throw error;
    }
  }

  @Post('logout')
  @Public()
  @UseGuards(CookieOriginGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiCookieAuth(REFRESH_COOKIE_NAME)
  @ApiOperation({
    summary: 'Sign out: revoke the session of the refresh cookie and clear it',
  })
  @ApiNoContentResponse()
  async logout(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    await this.sessions.logout(this.cookies.read(request), request);
    this.cookies.clear(reply);
  }

  private signedIn(result: SignedIn, reply: FastifyReply): LoginResponseDto {
    this.cookies.set(reply, result.opened.refresh.token);
    return new LoginResponseDto(result);
  }
}

/** Gateway `forwardAuth`: `GET /api/v2/auth/verify` (spec §12). */
@ApiTags('auth')
@Controller('auth/verify')
export class VerifyController {
  constructor(private readonly forwardAuth: ForwardAuthService) {}

  /** Public route: it validates the bearer token itself and answers 200 with identity headers or 401. */
  @Get()
  @Public()
  @Header('Cache-Control', 'no-store')
  @ApiOperation({
    summary:
      'Validate a bearer token for Traefik forwardAuth (X-User-Id, X-Org-Id, X-Roles)',
  })
  @ApiOkResponse({ type: VerifiedTokenDto })
  @ApiUnauthorizedResponse()
  async verify(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<VerifiedTokenDto> {
    const principal = await this.forwardAuth.verify(
      request.headers.authorization,
    );
    reply.header(HTTP_HEADERS.USER_ID, principal.id);
    reply.header(HTTP_HEADERS.ORG_ID, principal.orgId ?? '');
    reply.header(HTTP_HEADERS.ROLES, principal.roles.join(','));
    return new VerifiedTokenDto(principal);
  }
}

/** The signed-in user's sessions and active organization. */
@ApiTags('auth')
@Controller('auth')
export class SessionsController {
  constructor(private readonly sessions: AccountSessionsService) {}

  @Post('switch-org')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'Switch the active organization of the session (members, or super admins)',
  })
  @ApiOkResponse({ type: SwitchOrganizationResponseDto })
  async switchOrganization(
    @Body() body: SwitchOrganizationDto,
    @CurrentPrincipal() principal: Principal,
  ): Promise<SwitchOrganizationResponseDto> {
    return new SwitchOrganizationResponseDto(
      await this.sessions.switchOrganization(principal, body.orgId),
    );
  }

  @Get('sessions')
  @ApiOperation({ summary: 'List the own active sessions' })
  @ApiPageResponse(SessionDto)
  async list(
    @Query() query: PageQueryDto,
    @CurrentPrincipal() principal: Principal,
  ): Promise<Paginated<SessionDto>> {
    const result = await this.sessions.list(principal, query);
    return {
      data: result.data.map((view) => new SessionDto(view)),
      meta: result.meta,
    };
  }

  @Delete('sessions/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Revoke one of the own sessions (sign out a device)',
  })
  @ApiNoContentResponse()
  async revoke(
    @Param('id', new ParseUUIDPipe()) id: string,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.sessions.revoke(principal, id, request);
  }
}

/** TOTP enrollment of the signed-in user: `/api/v2/auth/mfa`. */
@ApiTags('auth')
@Controller('auth/mfa')
export class MfaController {
  constructor(private readonly mfa: MfaService) {}

  @Post('setup')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary:
      'Start the TOTP enrollment (returns the secret and the otpauth URI)',
  })
  @ApiOkResponse({ type: MfaSetupDto })
  async setup(@CurrentPrincipal() principal: Principal): Promise<MfaSetupDto> {
    return new MfaSetupDto(await this.mfa.setup(principal));
  }

  @Post('enable')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Enable MFA with the first code of the authenticator app',
  })
  @ApiNoContentResponse()
  async enable(
    @Body() body: MfaCodeDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.mfa.enable(principal, body.code, request);
  }

  @Post('disable')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Disable MFA with a current code' })
  @ApiNoContentResponse()
  async disable(
    @Body() body: MfaCodeDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.mfa.disable(principal, body.code, request);
  }
}
