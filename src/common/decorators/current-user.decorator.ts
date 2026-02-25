import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { TokenPayload } from '../types/auth.types';

export const CurrentUser = createParamDecorator(
  (data: keyof TokenPayload | undefined, ctx: ExecutionContext): TokenPayload | unknown => {
    const request = ctx.switchToHttp().getRequest<{ user: TokenPayload }>();
    const user = request.user;
    return data ? user?.[data] : user;
  },
);
