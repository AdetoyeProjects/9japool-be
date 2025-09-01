import { IsEmail, IsString } from 'src/shared/decorators';

export class SignInDto {
   @IsEmail(false)
   email: string;

   @IsString(false)
   password: string;
}
