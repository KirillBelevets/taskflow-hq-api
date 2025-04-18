import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Request,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Request as ExpressRequest } from 'express';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenService } from './refresh-token.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

type RequestWithUser = ExpressRequest & {
  user: JwtPayload;
};

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly refreshService: RefreshTokenService,
  ) {}

  @Post('login')
  async login(@Body() dto: LoginDto) {
    try {
      return await this.authService.login(dto.username, dto.password);
    } catch (err) {
      console.error('🔥 AuthController.login error:', err);
      throw err;
    }
  }

  @Post('refresh')
  refresh(
    @Body('refreshToken') token: string,
  ): Promise<{ accessToken: string }> {
    return this.refreshService.refreshAccessToken(token);
  }

  @Post('logout')
  logout(@Body('refreshToken') token: string) {
    this.refreshService.invalidateRefreshToken(token);
    return { message: 'Logged out successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getProfile(@Request() req: RequestWithUser) {
    const user = req.user;

    return {
      id: user.sub,
      username: user.username,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      role: user.role,
    };
  }

  @UseGuards(JwtAuthGuard)
  @Post('change-password')
  async changePassword(
    @Request() req: RequestWithUser,
    @Body() dto: ChangePasswordDto,
  ) {
    await this.authService.changePassword(
      req.user.sub,
      dto.oldPassword,
      dto.newPassword,
    );
    return { message: 'Password changed successfully' };
  }

  @Post('forgot-password')
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    await this.authService.forgotPassword(dto.email);
    return { message: 'If that email exists, we sent a reset link' };
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    await this.authService.resetPassword(dto.token, dto.newPassword);
    return { message: 'Password has been reset successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  async logoutAll(@Request() req: RequestWithUser) {
    await this.authService.logoutFromAllDevices(req.user.sub);
    return { message: 'Logged out from all devices' };
  }
}
