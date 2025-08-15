import { applyDecorators } from '@nestjs/common';
import {
   IsString as _IsString,
   IsNumber as _IsNumber,
   IsEmail as _IsEmail,
   IsBoolean as _IsBoolean,
   IsEnum as _IsEnum,
   IsUrl as _IsUrl,
   IsDate as _IsDate,
   IsBase64 as _IsBase64,
   IsOptional,
   IsDateString,
   IsNumberString,
} from 'class-validator';
import { ApiPropertyOptional, ApiProperty } from '@nestjs/swagger';

export const IsString = (isOptional: boolean) => {
   const decorators = [_IsString()];

   if (isOptional) {
      decorators.push(ApiPropertyOptional());
      decorators.push(IsOptional());
   } else {
      decorators.push(ApiProperty());
   }

   return applyDecorators(...decorators);
};

export const IsNumber = (isOptional: boolean) => {
   const decorators = [IsNumberString()];

   if (isOptional) {
      decorators.push(ApiPropertyOptional({ example: 0 }));
      decorators.push(IsOptional());
   } else {
      decorators.push(ApiProperty({ example: 0 }));
   }

   return applyDecorators(...decorators);
};

export const IsEmail = (isOptional: boolean) => {
   const decorators = [_IsEmail()];

   if (isOptional) {
      decorators.push(ApiPropertyOptional({ example: 'example@gmail.com' }));
      decorators.push(IsOptional());
   } else {
      decorators.push(ApiProperty({ example: 'example@gmail.com' }));
   }

   return applyDecorators(...decorators);
};

export const IsBoolean = (isOptional: boolean) => {
   const decorators = [_IsBoolean()];

   if (isOptional) {
      decorators.push(ApiPropertyOptional());
      decorators.push(IsOptional());
   } else {
      decorators.push(ApiProperty());
   }

   return applyDecorators(...decorators);
};

export const IsEnum = <T>(_enum: T, isOptional: boolean) => {
   const decorators = [_IsEnum(_enum as object)];

   if (isOptional) {
      decorators.push(ApiPropertyOptional({ enum: _enum }));
      decorators.push(IsOptional());
   } else {
      decorators.push(ApiProperty({ enum: _enum }));
   }

   return applyDecorators(...decorators);
};

export const IsDate = (isOptional: boolean) => {
   const decorators = [IsDateString()];

   if (isOptional) {
      decorators.push(ApiPropertyOptional());
      decorators.push(IsOptional());
   } else {
      decorators.push(ApiProperty());
   }

   return applyDecorators(...decorators);
};

export const IsUrl = (isOptional: boolean) => {
   const decorators = [_IsUrl()];

   if (isOptional) {
      decorators.push(ApiPropertyOptional());
      decorators.push(IsOptional());
   } else {
      decorators.push(ApiProperty());
   }

   return applyDecorators(...decorators);
};

export const IsBase64 = (isOptional: boolean) => {
   const decorators = [_IsString()];

   if (isOptional) {
      decorators.push(ApiPropertyOptional({ example: 'base64' }));
      decorators.push(IsOptional());
   } else {
      decorators.push(ApiProperty({ example: 'base64' }));
   }

   return applyDecorators(...decorators);
};
