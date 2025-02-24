import { ApiProperty, PickType } from '@nestjs/swagger';
import { User } from '../users.scheme';

export class ReadOnlyUserDTO extends PickType(User, ['email'] as const) {
  @ApiProperty({
    description: 'id',
    example: '67bb62e6c721d143922df417',
    required: true,
  })
  id: string;
}
