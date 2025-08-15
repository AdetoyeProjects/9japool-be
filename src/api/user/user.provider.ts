import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { UserService } from './user.service';
import { UserDocument } from './schema/user.schema';
import { UtilService } from 'src/shared/services/utils.service';
import { FileService } from 'src/shared/file/file.service';
import DEFAULT_IMAGES from 'src/shared/constants/images.const';
import { ChangePasswordDto } from './dto/change-password.dto';

@Injectable()
export class UserProvider {
   constructor(
      private readonly userService: UserService,
      private readonly utilService: UtilService,
      private readonly fileService: FileService,
   ) { }

   async getUser(user: UserDocument) {
      const data = await this.userService.getUser({ _id: user._id });

      if (!data) throw new NotFoundException('Profile not found');

      return {
         success: true,
         message: 'user info fetched',
         data: this.utilService.excludePassword(data),
      };
   }

   async changePassword(changePasswordDto: ChangePasswordDto, userId: string) {
      const user = await this.userService.getUser({ _id: userId });

      const passwordMatch = await this.utilService.comparePassword(
         changePasswordDto.oldPassword,
         user.password,
      );

      if (!passwordMatch)
         throw new BadRequestException('Old password is incorrect');

      const hashedPassword = await this.utilService.hashPassword(
         changePasswordDto.newPassword,
      );
      user.password = hashedPassword;
      await user.save();

      return {
         success: true,
         message: 'password changed',
      };
   }

   async updateProfilePicture(picture: string, userId: string) {
      const user = await this.userService.getUser({ _id: userId });
      if (!user) throw new NotFoundException('User does not exist');

      const profilePictureId = user.profilePictureId;

      const { url, public_id } = await this.fileService.uploadResource(picture);

      user.profilePicture = url;
      user.profilePictureId = public_id;
      await user.save();

      if (profilePictureId) {
         await this.fileService.deleteResource(profilePictureId);
      }

      return {
         success: true,
         message: 'profile picture uploaded successfully',
      };
   }

   async deleteByEmail(email: string) {
      await this.userService.deleteUser({ email });

      return {
         success: true,
         message: 'deleted',
      };
   }

   async removeProfilePicture(userId: string) {
      let data = await this.userService.getUser({ _id: userId });

      if (!data) {
         throw new NotFoundException('User not found');
      }

      const previousId = data.profilePictureId;

      data.profilePicture = DEFAULT_IMAGES.profilePicture;
      data.profilePictureId = '';
      data = await data.save();

      if (previousId) {
         await this.fileService.deleteResource(previousId);
      }

      return {
         success: true,
         message: 'profile picture updated',
         data: this.utilService.excludePassword(data),
      };
   }
}
