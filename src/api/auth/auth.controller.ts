import {
   Body,
   Controller,
   HttpCode,
   HttpStatus,
   Post,
} from '@nestjs/common';
import { ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import {
   RegisterDto,
} from './dto/register.dto';
import { SignInDto } from './dto/sign-in.dto';
import { IsPublic } from 'src/shared/decorators/auth.decorators';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
   constructor(private readonly authService: AuthService) { }


   @Post('/signup')
   @IsPublic()
   @HttpCode(HttpStatus.CREATED)
   @ApiOperation({ summary: 'Create an account' })
   async onBoardPlayer(@Body() registerDto: RegisterDto) {
      const data = await this.authService.signUp(registerDto);

      return data;
   }


   @Post('/signin')
   @IsPublic()
   @HttpCode(HttpStatus.OK)
   @ApiOperation({ summary: 'Log in to an existing account' })
   async signIn(@Body() signInDto: SignInDto) {
      const data = await this.authService.signIn(signInDto);

      return data;
   }

   @Post('/verify-email')
   @IsPublic()
   @HttpCode(HttpStatus.OK)
   @ApiOperation({ summary: 'Verify email' })
   async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
      const data = await this.authService.verifyEmail(verifyEmailDto);

      return data;
   }

   @Post('/verify-email/request')
   @IsPublic()
   @HttpCode(HttpStatus.OK)
   @ApiBody({
      schema: { type: 'object', properties: { email: { type: 'string' } } },
   })
   @ApiOperation({ summary: 'Request email verification' })
   async requestVerificationEmail(@Body('email') email: string) {
      const data = await this.authService.requestEmailVerificationLink(email);

      return data;
   }

   @Post('/forgot-password')
   @IsPublic()
   @HttpCode(HttpStatus.OK)
   @ApiBody({
      schema: { type: 'object', properties: { email: { type: 'string' } } },
   })
   @ApiOperation({ summary: 'Request password reset' })
   async forgotPassword(@Body('email') email: string) {
      const data = await this.authService.forgotPassword(email);

      return data;
   }

   @Post('/reset-password')
   @HttpCode(HttpStatus.OK)
   @IsPublic()
   @ApiOperation({ summary: 'Reset password' })
   async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
      const data = await this.authService.resetPassword(resetPasswordDto);

      return data;
   }


   @Post('/session/refresh')
   @IsPublic()
   @HttpCode(HttpStatus.OK)
   @ApiBody({
      schema: {
         type: 'object',
         properties: { refreshToken: { type: 'string' } },
      },
   })
   @ApiOperation({ summary: 'Refresh Session' })
   async refreshSession(@Body('refreshToken') refreshToken: string) {
      const data = await this.authService.refreshSession(refreshToken);

      return data;
   }

}
