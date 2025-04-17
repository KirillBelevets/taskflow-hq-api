export interface RequestUser {
  userId: number;
  username: string;
  role: 'user' | 'admin';
}
