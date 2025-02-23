import { Body, Controller, Post } from '@nestjs/common';
import { UsersRequestDTO } from './dto/users.request.dto';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('login')
  async login(@Body() body: UsersRequestDTO) {
    const user = await this.usersService.login(body);
    return user;
  }

  @Post('signup')
  async signUp(@Body() body: UsersRequestDTO) {
    const user = await this.usersService.signUp(body);
    return user;
  }
}
