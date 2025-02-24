import { Body, Controller, Post } from '@nestjs/common';
import { UsersRequestDTO, ReadOnlyUserDTO } from './dto';
import { UsersService } from './users.service';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: '로그인' })
  @ApiResponse({
    status: 200,
    description: '로그인 성공',
    type: ReadOnlyUserDTO,
  })
  @ApiResponse({
    status: 401,
    description: '로그인 실패',
  })
  @Post('login')
  async login(@Body() body: UsersRequestDTO) {
    const user = await this.usersService.login(body);
    return user;
  }

  @ApiOperation({ summary: '회원가입' })
  @ApiResponse({
    status: 200,
    description: '회원가입 성공',
    type: ReadOnlyUserDTO,
  })
  @ApiResponse({
    status: 400,
    description: '회원가입 실패',
  })
  @Post('signup')
  async signUp(@Body() body: UsersRequestDTO) {
    const user = await this.usersService.signUp(body);
    return user;
  }
}
