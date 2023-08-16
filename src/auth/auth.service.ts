import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { Profile } from 'passport-google-oauth20';
@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'secret-at',
          expiresIn: 60 * 15,
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'secret-rt',
          expiresIn: 60 * 15,
        },
      ),
    ]);
    return {
      access_token: at,
      refresh_token: rt,
    };
  }
  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    const newUser = await this.prismaService.user.create({
      data: {
        provider: 'local',
        email: dto.email,
        hash,
      },
    });
    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prismaService.user.findUnique({
      where: { email: dto.email },
    });
    if (!user) {
      throw new UnauthorizedException();
    }
    const isPasswordValid = bcrypt.compare(dto.password, user.hash);
    if (!isPasswordValid) {
      throw new UnauthorizedException();
    }
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }
  async logout(userId: number) {
    await this.prismaService.user.updateMany({
      where: {
        id: userId,
        hashRt: {
          not: null,
        },
      },
      data: {
        hashRt: null,
      },
    });
  }
  async refreshTokens(userId: number, rt: string) {
    const user = await this.prismaService.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.hashRt) {
      throw new UnauthorizedException();
    }
    const isRtValid = await bcrypt.compare(rt, user.hashRt);
    if (!isRtValid) {
      throw new UnauthorizedException();
    }
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashRt: hash,
      },
    });
  }

  async signInSignUpWithGoogle(profile: Profile) {
    const isUserExists = await this.prismaService.user.findUnique({
      where: {
        email: profile.emails[0].value,
      },
    });
    if (isUserExists) {
      const tokens = await this.getTokens(isUserExists.id, isUserExists.email);
      await this.updateRtHash(isUserExists.id, tokens.refresh_token);
      return tokens;
    }
    const newUser = await this.prismaService.user.create({
      data: {
        provider: 'google',
        email: profile.emails[0].value,
        data: profile._raw,
        googleId: profile.id,
        hash: await this.hashData(profile.id),
      },
    });
    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }
}
