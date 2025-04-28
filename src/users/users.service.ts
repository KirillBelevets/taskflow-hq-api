/* eslint-disable @typescript-eslint/no-unused-vars */

import { v4 as uuidv4 } from 'uuid';

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
    const confirmationToken: string = uuidv4();

    const hashed = await bcrypt.hash(password, 10);
    const userEntity = this.repo.create({
      username,
      password: hashed,
      emailConfirmed: false,
      emailConfirmationToken: confirmationToken,
    });
    const saved = await this.repo.save(userEntity);

    console.log(
      `📧 Confirm email: http://localhost:3000/auth/confirm-email?token=${confirmationToken}`,
    );

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

  findById(id: number): Promise<User | undefined> {
    return this.repo
      .findOne({ where: { id } })
      .then((user) => user ?? undefined);
  }

  findByEmail(email: string): Promise<User | undefined> {
    return this.repo
      .findOne({ where: { username: email } })
      .then((user) => user ?? undefined);
  }

  findByResetToken(token: string): Promise<User | undefined> {
    return this.repo
      .findOne({ where: { resetPasswordToken: token } })
      .then((user) => user ?? undefined);
  }

  findByConfirmationToken(token: string): Promise<User | undefined> {
    return this.repo
      .findOne({ where: { emailConfirmationToken: token } })
      .then((user) => user ?? undefined);
  }

  findByEmailToken(token: string): Promise<User | undefined> {
    return this.repo
      .findOne({ where: { emailConfirmationToken: token } })
      .then((user) => user ?? undefined);
  }

  save(user: User): Promise<User> {
    return this.repo.save(user);
  }
}
