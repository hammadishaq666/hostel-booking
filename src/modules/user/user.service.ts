import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';

export interface CreateUserData {
  name: string;
  contactNumber: string;
  email: string;
  passwordHash: string;
  role: User['role'];
  emailVerified?: boolean;
  otp?: string | null;
  otpExpiresAt?: Date | null;
}

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { email: email.toLowerCase() } });
  }

  async findById(id: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { id } });
  }

  async save(user: User): Promise<User> {
    return this.userRepo.save(user);
  }

  async create(data: CreateUserData): Promise<User> {
    const user = this.userRepo.create({
      ...data,
      email: data.email.toLowerCase(),
    });
    return this.userRepo.save(user);
  }
}
