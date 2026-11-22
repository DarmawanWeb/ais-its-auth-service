import {
  CurrentPrincipal,
  type Principal,
  Public,
} from '@darmawanweb/ais-its-nest/auth';
import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiBadRequestResponse,
  ApiForbiddenResponse,
  ApiNoContentResponse,
  ApiOperation,
  ApiTags,
  ApiTooManyRequestsResponse,
  ApiUnprocessableEntityResponse,
} from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';

import {
  ChangePasswordDto,
  ForgotPasswordDto,
  ResetPasswordDto,
} from './dto/password.dto.js';
import { PasswordService } from './password.service.js';

/** Password reset, invitation acceptance and password change: `/api/v2/auth/password`. */
@ApiTags('auth')
@Controller('auth/password')
export class PasswordsController {
  constructor(private readonly passwords: PasswordService) {}

  @Post('forgot')
  @Public()
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary:
      'Request a password reset link by e-mail (always 202; throttled per IP and address)',
  })
  @ApiAcceptedResponse({
    description: 'Accepted (whether or not the address exists)',
  })
  async forgot(
    @Body() body: ForgotPasswordDto,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.passwords.forgot(body.email, body.locale, request);
  }

  @Post('reset')
  @Public()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary:
      'Set a new password with a reset or invitation token (revokes every session)',
    description:
      'An invitation token also writes the membership of the invitation (and activates a new account). Failed attempts are throttled per client IP.',
  })
  @ApiNoContentResponse()
  @ApiBadRequestResponse({
    description: 'INVALID_TOKEN, VALIDATION_FAILED (password policy)',
  })
  @ApiForbiddenResponse({ description: 'ACCOUNT_DISABLED' })
  @ApiUnprocessableEntityResponse({
    description:
      'ROLE_NOT_GRANTABLE (the organization can no longer grant the invited role)',
  })
  @ApiTooManyRequestsResponse({ description: 'RATE_LIMITED (Retry-After)' })
  async reset(
    @Body() body: ResetPasswordDto,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.passwords.reset(body.token, body.password, request);
  }

  @Post('change')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Change the own password (revokes the other sessions)',
  })
  @ApiNoContentResponse()
  async change(
    @Body() body: ChangePasswordDto,
    @CurrentPrincipal() principal: Principal,
    @Req() request: FastifyRequest,
  ): Promise<void> {
    await this.passwords.change(
      principal,
      body.currentPassword,
      body.newPassword,
      request,
    );
  }
}
