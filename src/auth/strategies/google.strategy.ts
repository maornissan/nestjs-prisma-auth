import * as config from 'dotenv';
import { Injectable } from '@nestjs/common';
import { Profile, Strategy } from 'passport-google-oauth20';
import { PassportStrategy } from '@nestjs/passport';

config.config();
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor() {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: ['email', 'profile'],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: Profile) {
    return { refreshToken, profile };
  }
}
