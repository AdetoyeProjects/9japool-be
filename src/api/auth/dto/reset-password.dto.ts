import { IsEmail, IsString } from 'src/shared/decorators';

export class ResetPasswordDto {
  @IsEmail(false)
  email: string;

  @IsString(false)
  token: string;

  @IsString(false)
  password: string;
}
