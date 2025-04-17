import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenService } from './refresh-token.service';

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
}
