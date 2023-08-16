import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AtStrategy, GoogleStrategy, RtStrategy } from './strategies';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports: [JwtModule.register({}), PassportModule],
  controllers: [AuthController],
  providers: [AuthService, AtStrategy, RtStrategy, GoogleStrategy],
})
export class AuthModule {}
