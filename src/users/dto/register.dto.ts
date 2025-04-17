import { IsString, Length, Matches } from 'class-validator';

export class RegisterDto {
  @IsString()
  @Length(3, 20)
  username: string;

  @IsString()
  @Length(6, 50)
  @Matches(/\d/, { message: 'Password must contain at least one number' })
  password: string;
}
