import { Injectable, UnauthorizedException } from '@nestjs/common';
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

  refreshAccessToken(refreshToken: string): Promise<{ accessToken: string }> {
    return this.jwt
      .verifyAsync<JwtPayload>(refreshToken, {
        secret: this.getJwtSecret(),
      })
      .then(async (payload) => {
        const user = await this.users.findByUsername(payload.username);
        if (!user) throw new UnauthorizedException('User no longer exists');

        const newPayload = {
          sub: user.id,
          username: user.username,
          role: user.role,
        };

        const accessToken = this.jwt.sign(newPayload, {
          secret: this.getJwtSecret(),
          expiresIn: '1h',
        });

        return { accessToken };
      })
      .catch(() => {
        throw new UnauthorizedException('Invalid or expired refresh token');
      });
  }
}
