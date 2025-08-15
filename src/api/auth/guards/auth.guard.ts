import {
   CanActivate,
   ExecutionContext,
   ForbiddenException,
   Injectable,
   UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Request } from 'express';
import { Jwt, JwtDocument } from '../schema/jwt.schema';
import { Model } from 'mongoose';
import { UserDocument } from 'src/api/user/schema/user.schema';
import { JwtType } from '../enums/jwt.enum';
import { Reflector } from '@nestjs/core';
import { IsPublic, Roles } from 'src/shared/decorators/auth.decorators';
import { RoleNames } from 'src/api/user/enums';

@Injectable()
export class AuthGuard implements CanActivate {
   constructor(
      private readonly reflector: Reflector,
      private readonly jwtService: JwtService,
      @InjectModel(Jwt.name) private readonly _jwtModel: Model<JwtDocument>,
   ) { }

   async canActivate(context: ExecutionContext) {
      const ctx = context.switchToHttp();
      const req = ctx.getRequest<Request>();

      const publicRoute = this.reflector.get(IsPublic, context.getHandler());
      if (publicRoute) return true;

      const user = await this.validateToken(req);
      req['user'] = user;

      const roles: RoleNames[] = this.reflector.get(
         Roles,
         context.getHandler(),
      );

      if (roles && roles.length > 0) {
         if (!roles.includes(user.role)) {
            throw new UnauthorizedException(
               `Only ${roles.join(',')} have access`,
            );
         }
      }

      return true;
   }

   private async validateToken(req: Request) {
      try {
         const authHeader = req.headers['authorization'];

         if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new UnauthorizedException('Unauthorized!');
         }

         const token = authHeader.split(' ')[1];
         if (!token) {
            throw new UnauthorizedException('Unauthorized!');
         }

         const jwtToken = await this._jwtModel.find({
            token,
            type: JwtType.access,
         });

         if (!jwtToken) {
            throw new ForbiddenException('Session is invalid or has expired');
         }

         const payload = await this.jwtService.verifyAsync<UserDocument>(token);

         if (!payload) {
            throw new ForbiddenException('Session is invalid or has expired');
         }

         return payload as UserDocument;
      } catch (error) {
         throw new ForbiddenException('Session is invalid or has expired');
      }
   }
}
