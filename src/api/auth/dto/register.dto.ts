import { MinLength } from 'class-validator';
import { IsEmail, IsString } from 'src/shared/decorators';

export class RegisterDto {
   @IsEmail(false)
   email: string;

   @IsString(false)
   @MinLength(6, { message: 'Password must be at least 6 characters long' })
   password: string;

   @IsString(true)
   referralCode: string
}
