import { User } from '../users.scheme';
import { PickType } from '@nestjs/swagger';

export class UsersRequestDTO extends PickType(User, [
  'email',
  'password',
] as const) {}
