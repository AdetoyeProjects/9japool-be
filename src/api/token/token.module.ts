import { Module } from '@nestjs/common';
import { TokenService } from './token.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Token, TokenSchema } from './schema/token.schema';

@Module({
    imports: [
        MongooseModule.forFeatureAsync([
            {
                name: Token.name,
                useFactory() {
                    const schema = TokenSchema;

                    return schema;
                },
            },
        ]),
    ],
    providers: [TokenService],
    exports: [TokenService],
})
export class TokenModule {}
