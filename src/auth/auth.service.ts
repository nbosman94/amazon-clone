import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { ExisitingUserDTO } from 'src/user/dto/existing-user.dto';
import { NewUserDTO } from 'src/user/dto/new-user.dto';
import { UserDetails } from 'src/user/user.interface';
import { UserService } from 'src/user/user.service';

@Injectable()
export class AuthService {
    constructor(private userService: UserService, private jwtService: JwtService){}

    async hashPassword(password: string): Promise<string>{
        return bcrypt.hash(password, 12);
    }

    async register(user: Readonly<NewUserDTO>): Promise<UserDetails | any >{
        const {name, email, password} = user;

        const exisitingUser =  await this.userService.findByEmail(email);
        if(exisitingUser) throw new HttpException('Account already exists', HttpStatus.CONFLICT);

        const hashedPassword = await this.hashPassword(password);

        const newUser = await this.userService.create(name, email, hashedPassword);

        return this.userService._getUserDetails(newUser);

    }

    async doesPasswordMatch(password: string, hashedPassword: string): Promise<boolean> {
        return bcrypt.compare(password, hashedPassword);

    }

    async validateUser(email: string, password: string): Promise<UserDetails | null>{
        const user = await this.userService.findByEmail(email);
        const doesUserExisit = !!user;
        if(!doesUserExisit) return null;

        const doesPasswordMatch = await this.doesPasswordMatch(password, user.password);

        if(!doesPasswordMatch) return null;

        return this.userService._getUserDetails(user);

    }

    async login(exisitingUser: ExisitingUserDTO): Promise<{token: string}> {
        const {email, password} = exisitingUser;
        const user = await this.validateUser(email, password);

        if(!user) throw new HttpException("Credentials are not valid", HttpStatus.UNAUTHORIZED)

        const jwt = await this.jwtService.signAsync({ user });
        return { token : jwt};
    }

    async verifyJwt(jwt: string): Promise<{exp: number}> {
        try {
            const { exp } = await this.jwtService.verifyAsync(jwt)
            return { exp }
        } catch (error) {
            throw new HttpException('Invalid JWT', HttpStatus.UNAUTHORIZED);
        }
    }
}
