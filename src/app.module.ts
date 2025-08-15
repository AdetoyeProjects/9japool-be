import { Module } from '@nestjs/common';
import { ConfigModule, } from '@nestjs/config';
import { SharedModule } from 'src/shared/shared.module';
import { envSchema } from './shared/schemas/env.schema';
import { ApiModule } from './api/api.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';

@Module({
   imports: [
      ConfigModule.forRoot({
         isGlobal: true,
         envFilePath: '.env',
         validationSchema: envSchema,
      }),
      SharedModule,
      ApiModule,
   ],
   controllers: [AppController],
   providers: [AppService],
})
export class AppModule { }
