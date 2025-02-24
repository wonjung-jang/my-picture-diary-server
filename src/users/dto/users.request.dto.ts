import { User } from '../users.schema';
import { PickType } from '@nestjs/swagger';

export class UsersRequestDTO extends PickType(User, [
  'email',
  'password',
] as const) {}
