import { Module } from '@nestjs/common';
import { DatabaseModule } from './database/database.module';
import { AuthModule } from './auth/auth.module';
import { TokenModule } from './token/token.module';
import { UserModule } from './user/user.module';

@Module({
   imports: [
      DatabaseModule,
      AuthModule,
      TokenModule,
      UserModule
   ]
})
export class ApiModule { }
