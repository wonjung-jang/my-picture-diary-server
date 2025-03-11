import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { LoginUserDto } from 'src/user/dto/login-user.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  parseBasicToken(rawToken: string) {
    const basicSplit = rawToken.split(' ');

    if (basicSplit.length !== 2) {
      throw new BadRequestException('잘못된 토큰값입니다.');
    }

    const [_, token] = basicSplit;

    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    const tokenSplit = decoded.split(':');

    if (tokenSplit.length !== 2) {
      throw new BadRequestException('잘못된 토큰값입니다.');
    }

    const [userId, password] = tokenSplit;

    return { userId, password };
  }

  async signup(createUserDto: CreateUserDto) {
    const { userId, name, password } = createUserDto;

    await this.isDuplicateId(userId);

    const hash = await bcrypt.hash(
      password,
      this.configService.get<number>('HASH_ROUNDS') as number,
    );

    await this.userRepository.save({ userId, name, password: hash });

    return this.userRepository.findOne({ where: { userId } });
  }

  async login(loginUserDto: LoginUserDto) {
    const { userId, password } = loginUserDto;

    const user = await this.userRepository.findOne({ where: { userId } });
    if (!user) {
      throw new BadRequestException('잘못된 사용자 정보입니다.');
    }

    const passOk = await bcrypt.compare(password, user.password);
    if (!passOk) {
      throw new BadRequestException('잘못된 사용자 정보입니다.');
    }

    const refreshTokenSecret = this.configService.get<string>(
      'REFRESH_TOKEN_SECRET',
    );
    const accessTokenSecret = this.configService.get<string>(
      'ACCESS_TOKEN_SECRET',
    );

    const tokens = {
      refreshToken: await this.jwtService.signAsync(
        {
          sub: user.id,
          role: user.role,
          type: 'refresh',
        },
        {
          secret: refreshTokenSecret,
          expiresIn: '24h',
        },
      ),
      accessToken: await this.jwtService.signAsync(
        {
          sub: user.id,
          role: user.role,
          type: 'access',
        },
        {
          secret: accessTokenSecret,
          expiresIn: 300,
        },
      ),
    };

    return tokens;
  }

  async isDuplicateId(userId: string) {
    const user = await this.userRepository.findOne({ where: { userId } });
    if (user) {
      throw new BadRequestException('이미 등록된 아이디입니다.');
    }
    return userId;
  }
}
