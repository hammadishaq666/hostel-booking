import { IsEmail, IsEnum, IsString, MinLength, MaxLength, Matches } from 'class-validator';
import { Role } from '../../../common/enums/role.enum';

export class SignupDto {
  @IsString()
  @MinLength(1, { message: 'Name is required' })
  @MaxLength(255)
  name: string;

  @IsString()
  @Matches(/^[+]?[\d\s-]{10,20}$/, {
    message: 'Contact number must be 10–20 digits (may include +, spaces, or hyphens)',
  })
  contactNumber: string;

  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  password: string;

  @IsEnum(Role, { message: 'Role must be user, provider, or admin' })
  role: Role;
}
