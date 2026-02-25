import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { Role } from '../../../common/enums/role.enum';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';

/** Serialize Role[] to comma-separated string for DB (e.g. "user,provider"). */
function rolesTransformer(roles: Role[]): string {
  return roles?.length ? roles.join(',') : '';
}
function rolesFromDB(value: string | null): Role[] {
  if (!value || typeof value !== 'string') return [Role.USER];
  return value.split(',').filter(Boolean) as Role[];
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ length: 255 })
  name: string;

  @Column({ name: 'contact_number', length: 20 })
  contactNumber: string;

  @Column({ unique: true, length: 255 })
  email: string;

  @Column({ name: 'password_hash', length: 255 })
  passwordHash: string;

  /** One email can have multiple roles (e.g. user + provider). Stored as "user,provider". */
  @Column({
    name: 'roles',
    type: 'varchar',
    length: 64,
    default: 'user',
    transformer: {
      to: rolesTransformer,
      from: rolesFromDB,
    },
  })
  roles: Role[] = [Role.USER];

  @Column({ name: 'email_verified', default: false })
  emailVerified: boolean;

  @Column({ type: 'varchar', length: 6, nullable: true })
  otp: string | null;

  @Column({ name: 'otp_expires_at', type: 'timestamptz', nullable: true })
  otpExpiresAt: Date | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;

  @OneToMany(() => RefreshToken, (rt) => rt.user)
  refreshTokens: RefreshToken[];
}
