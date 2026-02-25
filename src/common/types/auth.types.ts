import { Role } from '../enums/role.enum';

export interface TokenPayload {
  sub: string;
  email: string;
  role: Role;
  type: 'access' | 'refresh';
}
