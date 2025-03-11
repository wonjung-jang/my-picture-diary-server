import { Controller, Post, Body, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { LoginUserDto } from 'src/user/dto/login-user.dto';
import { Response } from 'express';
import { ConfigService } from '@nestjs/config';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {}

  @Post('signup')
  signupUser(@Body() createUserDto: CreateUserDto) {
    return this.authService.signup(createUserDto);
  }

  @Post('login')
  async login(
    @Body() loginUserDto: LoginUserDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const { refreshToken, accessToken } =
      await this.authService.login(loginUserDto);

    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('ENV') === 'prod',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
    });

    return { accessToken };
  }

  @Post('/send/code')
  async sendCode(@Body() { userId }: { userId: string }) {
    return await this.authService.isDuplicateId(userId);
  }
}
