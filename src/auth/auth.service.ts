import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { AuthDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}
  async signin(dto: AuthDto): Promise<{ access_token: string }> {
    // check if the user is already existed
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) {
      throw new ForbiddenException('email is not exist');
    }
    // check ifa the password is correct
    const comparedPassword = await argon.verify(user.hash, dto.password);
    if (!comparedPassword) {
      throw new BadRequestException('email or password is incorrect');
    }
    // send token
    return this.signinToken(user.id, user.email);
  }
  async signup(dto: AuthDto): Promise<{ access_token: string }> {
    try {
      // hash the password
      const hashedPassword = await argon.hash(dto.password);
      // create user
      const user = await this.prisma.user.create({
        data: {
          hash: hashedPassword,
          email: dto.email,
        },
      });
      return this.signinToken(user.id, user.email);
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('email is already existed');
        }
      }
      console.log(err);
      throw err;
    }
  }
  async signinToken(userId: number, email: string) {
    const payload = {
      sub: userId,
      email,
    };
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET'),
    });
    return {
      access_token: token,
    };
  }
}
