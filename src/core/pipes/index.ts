import {
   PipeTransform,
   ArgumentMetadata,
   BadRequestException,
} from '@nestjs/common';
import { Types } from 'mongoose';
import DEFAULT_MATCHERS from 'src/shared/constants/regex.const';

export class MongoIdPipe implements PipeTransform {
   transform(value: any, metadata: ArgumentMetadata) {
      const isValid = Types.ObjectId.isValid(value);

      if (!isValid) {
         throw new BadRequestException('invalid mongo id');
      }

      return value;
   }
}

export class Base64Pipe implements PipeTransform {
   transform(value: any, metadata: ArgumentMetadata) {
      const isValid = DEFAULT_MATCHERS.base64.test(value);

      if (!isValid) {
         throw new BadRequestException('parse a valid base64 string');
      }

      return value;
   }
}
