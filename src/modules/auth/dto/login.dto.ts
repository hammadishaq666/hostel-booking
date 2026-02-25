import { IsEmail, IsEnum, IsOptional, IsString, MinLength } from 'class-validator';
import { Role } from '../../../common/enums/role.enum';

export class LoginDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(1, { message: 'Password is required' })
  password: string;

  /** Required when user has multiple roles (e.g. user + provider). Use "user" or "provider". */
  @IsOptional()
  @IsEnum(Role, { message: 'Role must be user, provider, or admin' })
  role?: Role;
}
