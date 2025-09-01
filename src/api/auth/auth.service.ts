import {
   BadRequestException,
   ForbiddenException,
   Injectable,
   NotFoundException,
   UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Jwt, JwtDocument } from './schema/jwt.schema';
import { Model } from 'mongoose';
import { UserService } from '../user/user.service';
import {
   RegisterDto,
} from './dto/register.dto';
import { UtilService } from 'src/shared/services/utils.service';
import { TokenService } from '../token/token.service';
import { TokenTypes } from '../token/enums';
import { MailService } from 'src/shared/mail/mail.service';
import { ConfigService } from '@nestjs/config';
import { SignInDto } from './dto/sign-in.dto';
import { UserDocument } from '../user/schema/user.schema';
import { JwtService } from '@nestjs/jwt';
import { JwtType } from './enums/jwt.enum';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';

@Injectable()
export class AuthService {
   constructor(
      @InjectModel(Jwt.name) private readonly _jwtModel: Model<JwtDocument>,
      private readonly userService: UserService,
      private readonly utilService: UtilService,
      private readonly tokenService: TokenService,
      private readonly mailService: MailService,
      private readonly configService: ConfigService,
      private readonly jwtService: JwtService,
   ) { }

   private async auth(user: UserDocument) {
      const ONE_HOUR = 1000 * 60 * 60;
      const accessToken = await this.jwtService.signAsync(user, {
         expiresIn: '1h',
      });
      const refreshToken = await this.jwtService.signAsync(user, {
         expiresIn: '7d',
      });

      await this._jwtModel.updateOne(
         { user: user._id, type: JwtType.access },
         { token: accessToken },
         { upsert: true },
      );
      await this._jwtModel.updateOne(
         { user: user._id, type: JwtType.refresh },
         { token: refreshToken },
         { upsert: true },
      );

      return {
         user,
         meta: {
            accessToken,
            refreshToken,
            lifeSpan: ONE_HOUR,
         },
      };
   }

   async signUp(signUpDto: RegisterDto) {
      const userExists = await this.userService.getUser({ email: signUpDto.email });

      if (userExists) {
         throw new BadRequestException(
            'Oops! A user with this email or username already exists',
         );
      }

      signUpDto.password = await this.utilService.hashPassword(
         signUpDto.password,
      );

      const user = await this.userService.createUser(signUpDto);

      const data = await this.utilService.excludePassword(user);

      const { value: code } = await this.tokenService.findOrCreateToken({
         email: user.email,
         value: this.utilService.generateOtpCode().toString(),
         type: TokenTypes.accountVerification,
      });


      await this.mailService.sendMail({
         to: user.email,
         subject: '9ja Pool: Account Verification',
         template: 'account-verification',
         context: {
            code,
         },
      });

      return {
         success: true,
         message: 'registration successful, account verification email sent',
         data
      };
   }

   async signIn(signInDto: SignInDto) {
      const user = await this.userService.getUser({ email: signInDto.email });

      if (!user) throw new UnauthorizedException('Invalid login credentials');

      const passwordMatch: boolean = await this.utilService.comparePassword(
         signInDto.password,
         user.password,
      );
      if (!passwordMatch)
         throw new UnauthorizedException('Invalid login credentials');
      if (!user.emailVerified)
         throw new BadRequestException('Email not verified');

      const data = await this.auth(this.utilService.excludePassword(user));

      return {
         success: true,
         message: 'sign in successful',
         data,
      };
   }

   async verifyEmail(verifyEmailDto: VerifyEmailDto) {
      const code = await this.tokenService.getToken({
         email: verifyEmailDto.email,
         value: verifyEmailDto.code,
         type: TokenTypes.accountVerification,
      });

      if (!code)
         throw new NotFoundException(
            'Code is invalid, try to request for a new verification code',
         );

      await this.userService.updateUser(
         { email: code.email },
         { emailVerified: true },
      );
      await code.deleteOne();

      return {
         success: true,
         message: 'Account Verified 😉',
      };
   }

   async requestEmailVerificationCode(email: string) {
      const user = await this.userService.getUser({ email });

      if (!user)
         throw new NotFoundException("User with this email doesn't exist");
      if (user.emailVerified)
         throw new NotFoundException('This account is already verified');

      const { value: code } = await this.tokenService.findOrCreateToken({
         email: user.email,
         value: this.utilService.generateOtpCode().toString(),
         type: TokenTypes.accountVerification,
      });

      await this.mailService.sendMail({
         to: user.email,
         subject: '9ja Pool: Account Verification',
         template: 'account-verification',
         context: {
            code,
         },
      });

      return {
         success: true,
         message: 'Verification Email Sent 🪁',
      };
   }

   async forgotPassword(email: string) {
      const user = await this.userService.getUser({ email });

      if (!user) {
         throw new NotFoundException("User with this email doesn't exist");
      }

      const { value: code } = await this.tokenService.findOrCreateToken({
         email,
         type: TokenTypes.passwordReset,
         value: this.utilService.generateOtpCode().toString(),
      });

      await this.mailService.sendMail({
         to: user.email,
         subject: '9ja Pool: Password Reset Request',
         template: 'forgot-password',
         context: {
            code,
         },
      });

      return {
         success: true,
         message: 'password reset code sent successfully',
      };
   }

   async resetPassword(resetPasswordDto: ResetPasswordDto) {
      const token = await this.tokenService.getToken({
         type: TokenTypes.passwordReset,
         value: resetPasswordDto.token,
         email: resetPasswordDto.email,
      });

      if (!token)
         throw new NotFoundException(
            'password reset link is invalid or has expired',
         );

      const hashedPassword = await this.utilService.hashPassword(
         resetPasswordDto.password,
      );

      await this.userService.updateUser(
         { email: token.email },
         { password: hashedPassword },
      );
      await token.deleteOne();

      return {
         success: true,
         message: 'password reset successful',
      };
   }

   async refreshSession(refreshToken: string) {
      const verifiedToken = await this.jwtService.verifyAsync(refreshToken);
      if (!verifiedToken) {
         throw new ForbiddenException('your session is invalid or has expired');
      }
      const jwtToken = await this._jwtModel.findOne({
         type: JwtType.refresh,
         token: refreshToken,
      });

      if (!jwtToken) {
         throw new ForbiddenException('your session is invalid or has expired');
      }

      const user = await this.userService.getUser({ _id: jwtToken.user });

      const accessToken = await this.jwtService.signAsync(
         this.utilService.excludePassword(user),
      );
      await this._jwtModel.updateOne(
         {
            type: JwtType.access,
            user: jwtToken.user,
         },
         { token: accessToken },
         { upsert: true },
      );

      return {
         success: true,
         message: 'session refreshed successfully',
         data: {
            accessToken,
            refreshToken,
         },
      };
   }
}
