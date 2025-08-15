import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Token, TokenDocument } from './schema/token.schema';
import { Model } from 'mongoose';
import { CreateTokenDto, GetTokenDto } from './dto/create-token.dto';

@Injectable()
export class TokenService {
    constructor(@InjectModel(Token.name) private readonly _tokenModel: Model<TokenDocument>) {}

    async findOrCreateToken(createTokenDto: CreateTokenDto) {
        const tokenExists = await this._tokenModel.findOne({
            email: createTokenDto.email,
            type: createTokenDto.type,
        });

        if (tokenExists) {
            tokenExists.value = createTokenDto.value;
            return await tokenExists.save();
        } else {
            return await this._tokenModel.create(createTokenDto);
        }
    }

    async getToken(getTokenDto: GetTokenDto) {
        const token = await this._tokenModel.findOne(getTokenDto);

        return token;
    }
}
