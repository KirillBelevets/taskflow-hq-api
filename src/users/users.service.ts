/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly repo: Repository<User>,
  ) {}

  /**
   * Find a user entity by username in the database.
   * @param username - the username to search for
   * @returns a Promise resolving to the User or null if not found
   */
  // src/users/users.service.ts
  findByUsername(username: string): Promise<User | undefined> {
    return this.repo
      .findOne({ where: { username } })
      .then((user) => user ?? undefined);
  }

  /**
   * Create a new user with a hashed password.
   * @param username - the new user's username
   * @param password - the new user's plaintext password
   * @returns the new User object without the password field
   */
  async createUser(
    username: string,
    password: string,
  ): Promise<Omit<User, 'password'> | null> {
    const hashed = await bcrypt.hash(password, 10);
    const userEntity = this.repo.create({ username, password: hashed });
    const saved = await this.repo.save(userEntity);

    const { password: _, ...rest } = saved;
    return rest;
  }

  /**
   * Validate a user's credentials during login.
   * @param username - the username provided
   * @param pass - the plaintext password provided
   * @returns the user object without password if valid; otherwise null
   */
  async validateUser(
    username: string,
    pass: string,
  ): Promise<Omit<User, 'password'> | null> {
    const user = await this.findByUsername(username);
    if (!user) return null;

    const isMatch: boolean = await bcrypt.compare(pass, user.password);
    if (!isMatch) return null;

    const { password: _, ...rest } = user;
    return rest;
  }
}
