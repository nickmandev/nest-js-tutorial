import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import { hashSync, compareSync } from 'bcrypt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    const hashedPassword = hashSync(dto.password, 10);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash: hashedPassword,
        },
      });

      delete user.hash;

      return user;
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        console.log(err.code);
        if (err.code === 'P2002') {
          throw new ForbiddenException('Credentials taken!');
        }
      }
      throw err;
    }
  }

  async signin(dto: AuthDto) {
    // find the user
    // if not exist ForbiddenException

    // compare password
    // if not correct ForbiddenException

    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email as string,
      },
    });
    if (!user) {
      throw new ForbiddenException('Credentials incorect');
    }

    const pwMastchess = compareSync(dto.password, user.hash);
    if (!pwMastchess) {
      throw new ForbiddenException('Credentials incorect');
    }

    delete user.hash;
    return user;
  }
}
