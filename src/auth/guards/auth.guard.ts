import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private jwtService: JwtService,
    private authService: AuthService,
  ) {}

  async canActivate( context: ExecutionContext ): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('capo, no tenes token!!');
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token,{secret: process.env.JWT_SEED}
      );
      
      const user = await this.authService.findUserById(payload.id);
      if (!user) {
        throw new UnauthorizedException('este usuario no existe!')
      }
      if (user.isActive === false) {
        throw new UnauthorizedException('este usuario no esta activo mi rey!')
      }
      request['user'] = user;

    } catch(error){
      throw new UnauthorizedException('Tu token es trucho sinverguenza!!!')
    }
     
    return true;
  
  }
  
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
