import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from './schema/user.schema';
import {
   FilterQuery,
   Model,
   QueryOptions,
   UpdateQuery,
} from 'mongoose';

@Injectable()
export class UserService {
   constructor(
      @InjectModel(User.name) private readonly _userModel: Model<UserDocument>,
   ) { }

   async createUser<T>(data: T) {
      const user = await this._userModel.create(data);

      return user;
   }

   async getUser(filter: FilterQuery<UserDocument>) {
      const user = await this._userModel.findOne(filter).select('+password').populate('referredBy');

      return user;
   }

   async getUsers(filter: FilterQuery<UserDocument>) {
      const users = await this._userModel.find(filter).populate('referredBy');

      return users;
   }

   async updateUser(
      filter: FilterQuery<UserDocument>,
      update: UpdateQuery<UserDocument>,
      options?: QueryOptions<UserDocument>,
   ) {
      const user = await this._userModel.findOneAndUpdate(filter, update, {
         new: true,
         runValidators: true,
         ...options,
      });

      return user;
   }

   async deleteUser(
      filter: FilterQuery<UserDocument>,
      options?: QueryOptions<UserDocument>,
   ) {
      const user = await this._userModel.findOneAndDelete(filter, options);

      return user;
   }
}
