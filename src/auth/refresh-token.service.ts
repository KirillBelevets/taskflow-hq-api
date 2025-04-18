import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class RefreshTokenService {
  constructor(
    private readonly jwt: JwtService,
    private readonly users: UsersService,
    private readonly config: ConfigService,
  ) {}

  private readonly blacklist = new Set<string>();

  private getJwtSecret(): string {
    const secret = this.config.get<string>('JWT_SECRET');
    if (!secret) throw new Error('JWT_SECRET is not defined in config');
    return secret;
  }

  issueRefreshToken(payload: {
    sub: number;
    username: string;
    role: string;
  }): string {
    return this.jwt.sign(payload, {
      secret: this.getJwtSecret(),
      expiresIn: '7d',
    });
  }

  invalidateRefreshToken(token: string): void {
    if (!token || typeof token !== 'string' || token.trim() === '') {
      throw new BadRequestException('Refresh token is required');
    }

    this.blacklist.add(token);
  }

  isBlacklisted(token: string): boolean {
    return this.blacklist.has(token);
  }

  async refreshAccessToken(refreshToken: string): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    const payload = await this.jwt.verifyAsync<JwtPayload>(refreshToken, {
      secret: this.getJwtSecret(),
    });

    if (this.isBlacklisted(refreshToken)) {
      throw new UnauthorizedException('Refresh token has been invalidated');
    }

    const user = await this.users.findByUsername(payload.username);
    if (!user) {
      throw new UnauthorizedException('User no longer exists');
    }

    if (payload.tokenVersion !== user.tokenVersion) {
      throw new UnauthorizedException('Token no longer valid');
    }

    const newPayload: JwtPayload = {
      sub: user.id,
      username: user.username,
      role: user.role,
      tokenVersion: user.tokenVersion,
    };

    const newAccessToken = this.jwt.sign(newPayload, {
      secret: this.getJwtSecret(),
      expiresIn: '1h',
    });

    const newRefreshToken = this.jwt.sign(newPayload, {
      secret: this.getJwtSecret(),
      expiresIn: '7d',
    });

    this.invalidateRefreshToken(refreshToken);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  invalidateAllForUser(userId: number): void {
    console.log(
      `🔁 All refresh tokens for user ${userId} are now invalidated.`,
    );
  }
}
