import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersRequestDTO } from './dto';
import * as bcrypt from 'bcrypt';
import { UserRepository } from './users.repository';

@Injectable()
export class UsersService {
  constructor(private readonly userRepository: UserRepository) {}

  async login(body: UsersRequestDTO) {
    const { email, password } = body;
    const user = await this.userRepository.findByEmail(email);

    if (!user) {
      throw new UnauthorizedException('존재하지 않는 이메일입니다.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('비밀번호가 일치하지 않습니다.');
    }

    return user.readOnlyData;
  }

  async signUp(body: UsersRequestDTO) {
    const { email, password } = body;
    const isUserExist = await this.userRepository.existsByEmail(email);

    if (isUserExist) {
      throw new UnauthorizedException('이미 존재하는 이메일입니다.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.userRepository.create({
      email,
      password: hashedPassword,
    });

    return user.readOnlyData;
  }
}
