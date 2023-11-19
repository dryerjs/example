import { Request } from 'express';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Module,
  UnauthorizedException,
  UseGuards,
  ValidationPipe,
  createParamDecorator,
} from '@nestjs/common';
import {
  Args,
  Field,
  GqlExecutionContext,
  GraphQLModule,
  Mutation,
  PickType,
  Query,
  Resolver,
  registerEnumType,
  ObjectType,
  InputType,
} from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { MongooseModule } from '@nestjs/mongoose';
import {
  BelongsTo,
  CreateInputType,
  Definition,
  DryerModule,
  GraphQLObjectId,
  Id,
  ObjectId,
  OutputType,
  Property,
  Skip,
} from 'dryerjs';
import { BaseService, InjectBaseService } from 'dryerjs/dist/base.service';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { plainToInstance } from 'class-transformer';
import { ApolloServerPluginLandingPageLocalDefault } from '@apollo/server/plugin/landingPage/default';

enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
}

registerEnumType(UserRole, { name: 'UserRole' });

@Definition({ allowedApis: ['findOne', 'paginate', 'remove', 'update'] })
export class User {
  @Id()
  id: ObjectId;

  @Property()
  email: string;

  @Property({ db: { type: String, enum: UserRole } })
  role: UserRole;

  @Property()
  name: string;

  @Property({ update: Skip, output: Skip })
  password: string;
}

@Definition()
export class Post {
  @Id()
  id: string;

  @Property()
  content: string;

  @Property({ nullable: true, create: { defaultValue: true } })
  isPublic: boolean;

  @BelongsTo(() => User, { from: 'userId' })
  user: User;

  @Property({ type: () => GraphQLObjectId })
  userId: ObjectId;
}

type Context = null | Pick<User, 'email' | 'id' | 'name' | 'role'>;

const SYSTEM: Context = {
  id: new ObjectId('000000000000000000000000'),
  role: UserRole.ADMIN,
  email: 'system@dryerjs.com',
  name: 'system',
};

const pipe = new ValidationPipe({
  transform: true,
  expectedType: CreateInputType(User),
});

export const Ctx = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const { req } = GqlExecutionContext.create(ctx).getContext();
    if (req.user) return req.user as Context;
    return null;
  },
);

const getCtxFromReq = async (
  req: Request,
  jwtService: JwtService,
): Promise<Context> => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return null;
  try {
    return jwtService.verify(token);
  } catch (error) {
    return null;
  }
};

@Injectable()
export class AdminOnly implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(executionContext: ExecutionContext): Promise<boolean> {
    const { req } = GqlExecutionContext.create(executionContext).getContext();
    const ctx = await getCtxFromReq(req, this.jwtService);
    if (ctx?.role !== UserRole.ADMIN) {
      throw new UnauthorizedException('AdminOnly');
    }
    req.ctx = ctx;
    return true;
  }
}

@Injectable()
export class UserOnly implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(executionContext: ExecutionContext): Promise<boolean> {
    const { req } = GqlExecutionContext.create(executionContext).getContext();
    const ctx = await getCtxFromReq(req, this.jwtService);
    if (![UserRole.ADMIN, UserRole.USER].includes(ctx?.role)) {
      throw new UnauthorizedException('AdminOnly');
    }
    req.ctx = ctx;
    return true;
  }
}

@Injectable()
export class PublicAccessWithContext implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(executionContext: ExecutionContext): Promise<boolean> {
    const { req } = GqlExecutionContext.create(executionContext).getContext();
    const ctx = await getCtxFromReq(req, this.jwtService);
    req.ctx = ctx;
    return true;
  }
}

@ObjectType()
class AccessTokenResponse {
  @Field()
  token: string;
}

@InputType()
class SignInInput extends PickType(CreateInputType(User), [
  'email',
  'password',
]) {
  @Field({ nullable: true })
  remember: boolean;
}

@Resolver()
export class AuthResolver {
  constructor(
    @InjectBaseService(User) public userService: BaseService<User, Context>,
    private readonly jwtService: JwtService,
  ) {}

  @Mutation(() => OutputType(User))
  async signUp(
    @Args('input', { type: () => CreateInputType(User) }, pipe)
    input: Omit<User, 'id'>,
  ) {
    const user = await this.userService.create(SYSTEM, input);
    return plainToInstance(User, user['toObject']());
  }

  @Mutation(() => AccessTokenResponse)
  async signIn(
    @Args('input', {
      type: () => SignInInput,
    })
    input: Pick<User, 'email' | 'password'>,
  ) {
    const user = await this.userService.findOne(SYSTEM, {
      email: input.email,
    });
    if (user.password === input.password) {
      throw new UnauthorizedException('Invalid email or password');
    }
    const accessToken = await this.jwtService.signAsync({
      id: user.id.toString(),
      role: user.role,
      email: user.email,
      name: user.name,
    });
    return { accessToken };
  }

  @UseGuards(UserOnly)
  @Query(() => OutputType(User))
  async whoAmI(@Ctx() ctx: Context) {
    const user = await this.userService.findOne(ctx, { _id: ctx.id });
    if (user === null) {
      throw new UnauthorizedException();
    }
    return user;
  }
}

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true,
      playground: false,
      plugins: [ApolloServerPluginLandingPageLocalDefault()],
    }),
    MongooseModule.forRoot('mongodb://127.0.0.1:27017/test'),
    DryerModule.register({ definitions: [User, Post], contextDecorator: Ctx }),
    JwtModule.register({
      secret: 'DO_NOT_TELL_ANYONE',
      signOptions: { expiresIn: '7d' },
    }),
  ],
  providers: [AuthResolver],
})
export class AppModule {}
