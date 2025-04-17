import { RequestUser } from '@/common/types/request-user';

declare global {
  namespace Express {
    interface Request {
      /**
       * Our authenticated user injected by JwtAuthGuard
       */
      user?: RequestUser;
    }
  }
}
