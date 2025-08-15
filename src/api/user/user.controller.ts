import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Post, Put } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { UserProvider } from './user.provider';
import { Auth, IsPublic } from 'src/shared/decorators/auth.decorators';
import { UserDocument } from './schema/user.schema';
import { Base64Pipe } from 'src/core/pipes';
import { ChangePasswordDto } from './dto/change-password.dto';

@Controller('user')
@ApiTags('user')
@ApiBearerAuth()
export class UserController {
   constructor(private readonly userProvider: UserProvider) { }

   @Get('/profile')
   @ApiOperation({ summary: 'Get User' })
   async getUser(@Auth() user: UserDocument) {
      const data = await this.userProvider.getUser(user);

      return data;
   }

   @Put('/change-password')
   @HttpCode(HttpStatus.OK)
   @ApiOperation({ summary: 'Change password' })
   async changePassword(
      @Auth('_id') userId: string,
      @Body() changePasswordDto: ChangePasswordDto,
   ) {
      const data = await this.userProvider.changePassword(
         changePasswordDto,
         userId,
      );

      return data;
   }

   @Put('/profile-picture')
   @ApiOperation({ summary: 'Update profile picture' })
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
   @ApiOperation({ summary: 'Delete profile picture' })
   async deleteProfilePicture(@Auth('_id') userId: string) {
      const data = await this.userProvider.removeProfilePicture(userId);

      return data;
   }

   @Delete('/account')
   @ApiOperation({
      summary: 'Delete account',
   })
   @ApiBody({
      schema: { type: 'object', properties: { email: { type: 'string' } } },
   })
   async deleteByEmail(@Body('email') email: string) {
      const data = await this.userProvider.deleteByEmail(email);

      return data;
   }
}
