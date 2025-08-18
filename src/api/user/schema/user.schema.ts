import { Schema, SchemaFactory, Prop } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';
import { DbMixins, schemaOptions } from 'src/shared/constants/db.const';
import DEFAULT_MATCHERS from 'src/shared/constants/regex.const';
import { RoleNames } from '../enums';
import DEFAULT_IMAGES from 'src/shared/constants/images.const';

@Schema(schemaOptions)
export class User extends DbMixins {
   @Prop({
      required: true,
      unique: true,
      match: DEFAULT_MATCHERS.email,
      index: true
   })
   email: string;

   @Prop({ required: true, index: true })
   userName: string;

   @Prop({ required: true })
   name: string;

   @Prop({ select: false })
   password?: string;

   @Prop({ type: Boolean, default: false })
   emailVerified: boolean;

   @Prop({ type: String, default: DEFAULT_IMAGES.profilePicture })
   profilePicture: string;

   @Prop({ type: String, required: false })
   profilePictureId: string;

   @Prop({ type: String, required: true, enum: Object.values(RoleNames), default: RoleNames.PLAYER })
   role: RoleNames;

   @Prop({ type: Types.ObjectId, ref: User.name, default: null })
   referredBy: Types.ObjectId | UserDocument;
}

export type UserDocument = HydratedDocument<User>;
export const UserSchema = SchemaFactory.createForClass(User);
