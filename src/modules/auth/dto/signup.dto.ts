import { IsEmail, IsEnum, IsString, MinLength } from 'class-validator';
import { Role } from '../../../common/enums/role.enum';

export class SignupDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  password: string;

  @IsEnum(Role, { message: 'Role must be user, provider, or admin' })
  role: Role;
}
