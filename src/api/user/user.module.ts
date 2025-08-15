import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schema/user.schema';
import { UserProvider } from './user.provider';
import { UserController } from './user.controller';
import { SharedModule } from 'src/shared/shared.module';

@Module({
   imports: [
      MongooseModule.forFeatureAsync([
         {
            name: User.name,
            useFactory() {
               const schema = UserSchema;
               return schema;
            },
         },
      ]),
      SharedModule,
   ],
   providers: [UserService, UserProvider],
   controllers: [UserController],
   exports: [UserService],
})
export class UserModule {}
