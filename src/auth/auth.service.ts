import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './dto';
import { hashSync, compareSync } from 'bcrypt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    const hashedPassword = hashSync(dto.password, 10);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash: hashedPassword,
        },
      });

      return this.signToken(user.id, user.email);
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

    return this.signToken(user.id, user.email);
  }

  async signToken(userId: number, email: string): Promise<string> {
    const payload = { sub: userId, email };
    const secret = this.config.get('JWT_SECRET');
    return this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret,
    });
  }
}
