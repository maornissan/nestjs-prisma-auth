import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { AtGuard, GoogleGuard, RtGuard } from 'src/common/guards';
import { GetCurrentUser, GetCurrentUserId } from 'src/common/decorators';
import { Profile } from 'passport-google-oauth20';
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('/local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() dto: AuthDto) {
    return this.authService.signupLocal(dto);
  }

  @Post('/local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() dto: AuthDto) {
    return this.authService.signinLocal(dto);
  }

  @UseGuards(AtGuard)
  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUser('sub') userId: number) {
    return this.authService.logout(userId);
  }

  @UseGuards(RtGuard)
  @Post('/refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.refreshTokens(userId, refreshToken);
  }

  @UseGuards(GoogleGuard)
  @Get('/google/signin')
  signinGoogle() {
    return { message: 'Redirecting to Google...' };
  }

  @UseGuards(GoogleGuard)
  @Get('/google/redirect')
  signinGoogleCallback(@Req() req) {
    const profile: Profile = req.user.profile;
    console.log(profile);
    return this.authService.signInSignUpWithGoogle(profile);
  }
}
