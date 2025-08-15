import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { DbMixins, schemaOptions } from 'src/shared/constants/db.const';
import DEFAULT_MATCHERS from 'src/shared/constants/regex.const';
import { TokenTypes } from '../enums';
import { HydratedDocument } from 'mongoose';

@Schema(schemaOptions)
export class Token extends DbMixins {
    @Prop({ required: true, match: DEFAULT_MATCHERS.email })
    email: string;

    @Prop({ required: true })
    value: string;

    @Prop({ type: String, enum: Object.values(TokenTypes), required: true })
    type: TokenTypes;
}

export type TokenDocument = HydratedDocument<Token>;
export const TokenSchema = SchemaFactory.createForClass(Token);
