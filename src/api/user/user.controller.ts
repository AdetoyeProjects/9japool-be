import { Body, Controller, Delete, Get, Post, Put } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiTags } from '@nestjs/swagger';
import { UserProvider } from './user.provider';
import { Auth, IsPublic } from 'src/shared/decorators/auth.decorators';
import { UserDocument } from './schema/user.schema';
import { Base64Pipe } from 'src/core/pipes';

@Controller('user')
@ApiTags('user')
@ApiBearerAuth()
export class UserController {
   constructor(private readonly userProvider: UserProvider) {}

   @Get()
   async getUser(@Auth() user: UserDocument) {
      const data = await this.userProvider.getUser(user);

      return data;
   }

   @Put('/profile-picture')
   @ApiBody({
      schema: { type: 'object', properties: { picture: { type: 'string' } } },
   })
   async updateProfilePicture(
      @Auth('_id') userId: string,
      @Body('picture', Base64Pipe) picture: string,
   ) {
      const data = await this.userProvider.updateProfilePicture(
         picture,
         userId,
      );

      return data;
   }

   @Delete('/profile-picture')
   async deleteProfilePicture(@Auth('_id') userId: string) {
      const data = await this.userProvider.removeProfilePicture(userId);

      return data;
   }

   @Delete('email')
   @ApiBody({
      schema: { type: 'object', properties: { email: { type: 'string' } } },
   })
   @IsPublic()
   async deleteByEmail(@Body('email') email: string) {
      const data = await this.userProvider.deleteByEmail(email);

      return data;
   }
}
