/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { v4 as uuidv4 } from 'uuid';
import { addMinutes } from 'date-fns';

import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { UsersService } from '@/users/users.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { UserRole } from '@/users/user.entity';
import { RefreshTokenService } from './refresh-token.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly refreshService: RefreshTokenService,
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
      role: user.role as UserRole,
      tokenVersion: user.tokenVersion,
    };

    const accessToken = this.signToken(payload, '1h');
    const refreshToken = this.signToken(payload, '7d');

    return { accessToken, refreshToken };
  }

  async changePassword(
    userId: number,
    oldPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException('User not found');

    const isValid = await bcrypt.compare(oldPassword, user.password);
    if (!isValid) throw new UnauthorizedException('Old password is incorrect');

    user.password = await bcrypt.hash(newPassword, 10);
    user.tokenVersion++;
    await this.users.save(user);

    this.refreshService.invalidateAllForUser(userId);
  }

  async forgotPassword(email: string): Promise<void> {
    const user = await this.users.findByEmail(email);
    if (!user) return; // email does not exist

    const token = uuidv4();
    const expires = addMinutes(new Date(), 15); // 15 minutes for refresh

    user.resetPasswordToken = token;
    user.resetPasswordExpires = expires;

    await this.users.save(user);

    // ⛔ TODO: just log, not email sending
    console.log(
      `📧 Reset link for ${user.username}: http://localhost:3000/reset-password?token=${token}`,
    );
  }

  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    const user = await this.users.findByResetToken(token);

    if (
      !user ||
      !user.resetPasswordExpires ||
      user.resetPasswordExpires.getTime() < Date.now()
    ) {
      throw new BadRequestException('Token is invalid or has expired');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;

    await this.users.save(user);

    return { message: 'Password has been reset successfully' };
  }

  async logoutFromAllDevices(userId: number): Promise<void> {
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException('User not found');

    user.tokenVersion++;
    await this.users.save(user);
  }
}
