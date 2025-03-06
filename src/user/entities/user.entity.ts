import { Exclude } from 'class-transformer';
import { BaseTable } from 'src/common/entites/base-table.entity';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

export enum ROLE {
  admin,
  user,
}

@Entity()
export class User extends BaseTable {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  @Exclude({
    toPlainOnly: true,
  })
  password: string;

  @Column()
  name: string;

  @Column({
    enum: ROLE,
    default: ROLE.user,
  })
  role: ROLE;
}
