import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import { JwtPayloadWithRt } from 'src/auth/types/jwtPayloadWithRt.type';

export const GetCurrentUser = createParamDecorator(
  (data: undefined | keyof JwtPayloadWithRt, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    if (!data) return request.user;
    return request.user[data];
  },
);
