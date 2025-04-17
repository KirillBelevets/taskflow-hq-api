/* eslint-disable
    @typescript-eslint/no-unsafe-assignment,
    @typescript-eslint/no-unsafe-member-access,
    @typescript-eslint/no-unsafe-call
*/

import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Req,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  ConflictException,
} from '@nestjs/common';
import { Request } from 'express';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '@/auth/jwt-auth.guard';
import { RolesGuard } from '@/common/guards/roles.guard';
import { Roles } from '@/common/decorators/roles.decorator';
import { RequestUser } from '@/common/types/request-user';
import { RegisterDto } from './dto/register.dto';

function isRequestUser(u: unknown): u is RequestUser {
  return (
    typeof u === 'object' &&
    u !== null &&
    typeof (u as any).username === 'string'
  );
}

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterDto) {
    const created = await this.usersService.createUser(
      dto.username,
      dto.password,
    );
    if (!created) {
      throw new ConflictException('User already exists');
    }
    return created;
  }

  @Roles('admin')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Get('admin-only')
  getAdminData(@Req() req: Request & { user?: unknown }) {
    if (!isRequestUser(req.user)) {
      throw new ForbiddenException('Invalid user payload');
    }

    return {
      message: 'Sensitive admin data',
      accessedBy: req.user.username,
    };
  }
}
