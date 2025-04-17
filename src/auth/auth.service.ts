/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { UsersService } from '@/users/users.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  private getJwtSecret(): string {
    const secret = this.config.get<string>('JWT_SECRET');
    if (!secret) throw new Error('JWT_SECRET is not defined');
    return secret;
  }

  private signToken(payload: JwtPayload, expiresIn: string): string {
    return this.jwt.sign(payload, {
      secret: this.getJwtSecret(),
      expiresIn,
    });
  }

  async login(
    username: string,
    password: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const user = await this.users.findByUsername(username);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const isMatch: boolean = await bcrypt.compare(password, user.password);
    if (!isMatch) throw new UnauthorizedException('Invalid credentials');

    const payload: JwtPayload = {
      sub: user.id,
      username: user.username,
      role: user.role,
    };

    const accessToken = this.signToken(payload, '1h');
    const refreshToken = this.signToken(payload, '7d');

    return { accessToken, refreshToken };
  }
}
