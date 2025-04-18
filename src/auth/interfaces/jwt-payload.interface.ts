import { UserRole } from '@/users/user.entity';

export interface JwtPayload {
  sub: number;
  username: string;
  role: UserRole;
  tokenVersion: number;
}
