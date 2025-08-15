import { IsString } from 'src/shared/decorators';

export class ChangePasswordDto {
  @IsString(false)
  oldPassword: string;

  @IsString(false)
  newPassword: string;
}
