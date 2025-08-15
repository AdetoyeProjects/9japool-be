import { IsEnum, IsString } from 'src/shared/decorators';
import { TokenTypes } from '../enums';
import { PartialType } from '@nestjs/swagger';

export class CreateTokenDto {
    @IsString(false)
    email: string;

    @IsString(false)
    value: string;

    @IsEnum(TokenTypes, false)
    type: TokenTypes;
}

export class GetTokenDto extends PartialType(CreateTokenDto) {}
