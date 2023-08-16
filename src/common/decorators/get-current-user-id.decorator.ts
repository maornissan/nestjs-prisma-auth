import { ExecutionContext, createParamDecorator } from '@nestjs/common';

export const GetCurrentUserId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    if (!data) return request.user.sub;
    return request.user.data.sub;
  },
);
