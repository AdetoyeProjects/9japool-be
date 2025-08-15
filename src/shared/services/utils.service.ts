import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { UserDocument } from 'src/api/user/schema/user.schema';
import { ResolvePaginationQuery } from '../interfaces/pagination.interface';

@Injectable()
export class UtilService {
   constructor(private readonly configService: ConfigService) {}

   async hashPassword(password: string) {
      const saltFactor = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash(password, saltFactor);

      return hashedPassword;
   }

   async comparePassword(password: string, hash: string) {
      return await bcrypt.compare(password, hash);
   }

   generateToken() {
      return crypto.randomBytes(32).toString('hex');
   }

   excludePassword(user: UserDocument) {
      delete user['_doc'].password;

      return user['_doc'];
   }

   setHourAndMin(hour: number, min: number) {
      const today = new Date();
      today.setUTCHours(hour);
      today.setUTCMinutes(min);
      return today;
   }

   resolvePaginationQuery(query: ResolvePaginationQuery) {
      const page = Number(query.page) || 1;
      let limit = query?.limit ?? 100000000000;
      const skip = (page - 1) * limit;
      console.log(query.count, limit);
      const totalPages = Math.ceil(query.count / limit);

      if (query?.limit === 0) limit = query.count;

      if (query?.limit === 0 && query.count === 0) limit++;

      return {
         skip,
         page,
         limit,
         totalPages,
         count: query.count,
      };
   }
}
