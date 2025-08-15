import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Jwt, JwtSchema } from './schema/jwt.schema';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TokenModule } from '../token/token.module';
import { SharedModule } from 'src/shared/shared.module';
import { UserModule } from '../user/user.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from './guards/auth.guard';
// import { DoctorModule } from '../doctor/doctor.module';
// import { PatientModule } from '../patient/patient.module';

@Module({
   imports: [
      MongooseModule.forFeatureAsync([
         {
            name: Jwt.name,
            useFactory() {
               const schema = JwtSchema;

               return schema;
            },
         },
      ]),
      JwtModule.registerAsync({
         imports: [ConfigModule],
         inject: [ConfigService],
         useFactory(configService: ConfigService) {
            return {
               global: true,
               signOptions: { expiresIn: '1d' },
               secret: Buffer.from(
                  configService.get<string>('JWT_SECRET'),
                  'base64',
               ).toString('ascii'),
            };
         },
      }),
      TokenModule,
      SharedModule,
      UserModule,
      // DoctorModule,
      // PatientModule,
   ],
   providers: [AuthService, AuthGuard],
   controllers: [AuthController],
})
export class AuthModule {}
