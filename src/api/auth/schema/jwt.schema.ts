import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';
import { User, UserDocument } from 'src/api/user/schema/user.schema';
import { Relations, schemaOptions } from 'src/shared/constants/db.const';
import { JwtType } from '../enums/jwt.enum';

@Schema(schemaOptions)
export class Jwt {
    @Prop({ required: true })
    token: string;

    @Prop({
        required: true,
        type: Types.ObjectId,
        ref: User.name,
    })
    user: Relations<UserDocument>;

    @Prop({
        type: String,
        enum: Object.values(JwtType),
        required: true,
    })
    type: JwtType;
}

export type JwtDocument = HydratedDocument<Jwt>;
export const JwtSchema = SchemaFactory.createForClass(Jwt);
