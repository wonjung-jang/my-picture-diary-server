import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class UsersRequestDTO {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
