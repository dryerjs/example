import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  Module,
  OnModuleInit,
  UnauthorizedException,
  UseGuards,
  applyDecorators,
  createParamDecorator,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
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
  BaseService,
  InjectBaseService,
  BeforeUpdateHook,
  BeforeReadFilterHook,
  BeforeWriteFilterHook,
  BeforeUpdateHookInput,
  BeforeWriteFilterHookInput,
  BeforeReadFilterHookInput,
} from 'dryerjs';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { ApolloServerPluginLandingPageLocalDefault } from '@apollo/server/plugin/landingPage/default';

enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
}

registerEnumType(UserRole, { name: 'UserRole' });

export const Role = Reflector.createDecorator<UserRole>();

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private reflector: Reflector,
  ) {}

  async canActivate(executionContext: ExecutionContext): Promise<boolean> {
    const { req } = GqlExecutionContext.create(executionContext).getContext();

    const ctx = await this.jwtService
      .verifyAsync(req.header('Authorization')?.split(' ')?.[1])
      .catch(() => null);

    if (ctx?.id) {
      ctx.id = new ObjectId(ctx.id);
    }

    req.ctx = ctx;

    const role = this.reflector.get(Role, executionContext.getHandler());
    if (!role) return true;
    if (role === UserRole.ADMIN && ctx?.role !== UserRole.ADMIN) {
      throw new UnauthorizedException('AdminOnly');
    }
    if (
      role === UserRole.USER &&
      ![UserRole.ADMIN, UserRole.USER].includes(ctx?.role)
    ) {
      throw new UnauthorizedException('UserOnly');
    }

    return true;
  }
}

const UserOnly = () => {
  return applyDecorators(Role(UserRole.USER), UseGuards(RoleGuard));
};

const AdminOnly = () => {
  return applyDecorators(Role(UserRole.ADMIN), UseGuards(RoleGuard));
};

const PublicAccessWithRole = () => applyDecorators(UseGuards(RoleGuard));

@Definition()
export class User {
  @Id()
  id: ObjectId;

  @Property()
  email: string;

  @Property({ db: { type: String, enum: UserRole } })
  role: UserRole;

  @Property()
  name: string;

  @Property({ output: Skip })
  password: string;
}

@Definition()
export class Post {
  @Id()
  id: ObjectId;

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

@Injectable()
class UserHook {
  @BeforeUpdateHook(() => User)
  async beforeUpdate({
    ctx,
    input,
  }: BeforeUpdateHookInput<User, Context>): Promise<void> {
    if (ctx.role === UserRole.USER && input.role === UserRole.ADMIN) {
      throw new UnauthorizedException('Cannot update role');
    }
    if (
      ctx.role === UserRole.USER &&
      input.id.toString() !== ctx.id.toString()
    ) {
      throw new UnauthorizedException('Cannot update other user');
    }
  }
}

@Injectable()
class PostHook {
  @BeforeWriteFilterHook(() => Post)
  async ensureNormalUserCanOnlyWriteToHimself({
    ctx,
    filter,
  }: BeforeWriteFilterHookInput<Post, Context>): Promise<void> {
    if (ctx?.role === UserRole.USER) {
      filter.userId = ctx.id;
    }
    // guest cannot write post so we don't need to handle it
  }

  @BeforeReadFilterHook(() => Post)
  async ensureGuestOrNormalUserCannotReadPrivatePostsOfOthers({
    ctx,
    filter,
  }: BeforeReadFilterHookInput<Post, Context>): Promise<void> {
    if (ctx === null) filter.isPublic = true;
    if (ctx?.role === UserRole.USER) {
      filter['$and'] = [
        {
          $or: [
            { userId: ctx.id },
            { userId: { $ne: ctx.id }, isPublic: true },
          ],
        },
      ];
    }
  }
}

export const Ctx = createParamDecorator(
  (_data: unknown, executionContext: ExecutionContext) => {
    const { req } = GqlExecutionContext.create(executionContext).getContext();
    if (req.ctx) return req.ctx as Context;
    return null;
  },
);

@ObjectType()
class AccessTokenResponse {
  @Field()
  accessToken: string;
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

  @Mutation(() => AccessTokenResponse)
  async signIn(
    @Args('input', {
      type: () => SignInInput,
    })
    input: Pick<User, 'email' | 'password'>,
  ) {
    const user = await this.userService.model.findOne({ email: input.email });
    if (user?.password !== input.password) {
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

  @UserOnly()
  @Query(() => OutputType(User))
  async whoAmI(@Ctx() ctx: Context) {
    const user = await this.userService.findOne(ctx, { _id: ctx.id });
    if (user === null) {
      throw new UnauthorizedException();
    }
    return user;
  }
}

@Injectable()
export class SeederService implements OnModuleInit {
  constructor(
    @InjectBaseService(User) public userService: BaseService<User, Context>,
    @InjectBaseService(Post) public postService: BaseService<Post, Context>,
  ) {}

  async onModuleInit() {
    if ((await this.userService.model.countDocuments({})) !== 0) return;
    if (process.env.NODE_ENV !== 'test') {
      Logger.log('Run seeding...', SeederService.name);
    }
    const adminUserId = new ObjectId('000000000000000000000000');
    const normalUserId = new ObjectId('000000000000000000000001');
    const secondNormalUserId = new ObjectId('000000000000000000000002');
    const users = [
      {
        _id: adminUserId,
        email: 'admin@dryerjs.com',
        password: 'password',
        name: 'Admin@DryerJS',
        role: UserRole.ADMIN,
      },
      {
        _id: normalUserId,
        email: 'user@dryerjs.com',
        password: 'password',
        name: 'User@DryerJS',
        role: UserRole.USER,
      },
      {
        _id: secondNormalUserId,
        email: 'secondUser@dryerjs.com',
        password: 'password',
        name: 'SecondUser@DryerJS',
        role: UserRole.USER,
      },
    ];

    const posts = [
      {
        _id: new ObjectId('000000000000000000000003'),
        content: 'Admin public announcement',
        isPublic: true,
        userId: adminUserId,
      },
      {
        _id: new ObjectId('000000000000000000000004'),
        content: 'Admin private note',
        isPublic: false,
        userId: adminUserId,
      },
      {
        _id: new ObjectId('000000000000000000000005'),
        content: 'User public note',
        isPublic: true,
        userId: normalUserId,
      },
      {
        _id: new ObjectId('000000000000000000000006'),
        content: 'User private note',
        isPublic: false,
        userId: normalUserId,
      },
      {
        _id: new ObjectId('000000000000000000000007'),
        content: 'Second user public note',
        isPublic: true,
        userId: secondNormalUserId,
      },
      {
        _id: new ObjectId('000000000000000000000008'),
        content: 'Second user private note',
        isPublic: false,
        userId: secondNormalUserId,
      },
    ];
    await this.userService.model.create(users);
    await this.postService.model.create(posts);
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
    MongooseModule.forRoot(
      process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/dryerjs-example',
    ),
    DryerModule.register({
      contextDecorator: Ctx,
      providers: [UserHook, PostHook],
      definitions: [
        {
          definition: User,
          allowedApis: ['findOne', 'paginate', 'remove', 'update'],
          decorators: {
            update: [UserOnly()],
            remove: [AdminOnly()],
          },
        },
        {
          definition: Post,
          decorators: {
            write: [UserOnly()],
            read: [PublicAccessWithRole()],
          },
        },
      ],
    }),
    JwtModule.register({
      global: true,
      secret: 'DO_NOT_TELL_ANYONE',
      signOptions: { expiresIn: '7d' },
    }),
  ],
  providers: [AuthResolver, SeederService, RoleGuard],
})
export class AppModule {}
