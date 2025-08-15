import { IsEmail, IsString } from 'src/shared/decorators';

export class SignInDto {
   @IsEmail(true)
   email?: string;

   @IsString(true)
   userName?: string

   @IsString(false)
   password: string;
}
