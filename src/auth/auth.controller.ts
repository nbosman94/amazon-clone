import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { ExisitingUserDTO } from 'src/user/dto/existing-user.dto';
import { NewUserDTO } from 'src/user/dto/new-user.dto';
import { UserDetails } from 'src/user/user.interface';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService){}

    @Post('register')
    register(@Body() user: NewUserDTO) : Promise<UserDetails | null> {
        return this.authService.register(user);
    }

    @Post('login')
    @HttpCode(HttpStatus.OK)
    login(@Body() user: ExisitingUserDTO) : Promise<{token:string}| null> {
        return this.authService.login(user);
    }

    @Post('verify-jwt')
    @HttpCode(HttpStatus.OK)
    verifyJwt(@Body() payload: {jwt: string}) : Promise<{exp:number}| null > {
        return this.authService.verifyJwt(payload.jwt);
    }


}
