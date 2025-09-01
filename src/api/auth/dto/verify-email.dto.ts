import { IsEmail, IsString } from 'src/shared/decorators';

export class VerifyEmailDto {
  @IsEmail(false)
  email: string;

  @IsString(false)
  code: string;
}