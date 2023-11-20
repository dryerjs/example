import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Module,
  NotFoundException,
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
import { InjectModel, MongooseModule } from '@nestjs/mongoose';
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
  Hook,
  BeforeUpdateHookInput,
  BeforeFindOneHookInput,
  AfterFindOneHookInput,
  BeforeRemoveHookInput,
  BeforeFindManyHookInput,
} from 'dryerjs';
import { PaginateModel } from 'mongoose';
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

@Definition({
  allowedApis: ['findOne', 'paginate', 'remove', 'update'],
  resolverDecorators: {
    update: [UserOnly()],
    remove: [AdminOnly()],
  },
})
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

@Definition({
  allowedApis: 'essentials',
  resolverDecorators: {
    write: [UserOnly()],
    read: [PublicAccessWithRole()],
  },
})
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
  id: new ObjectId('999999999999999999999999'),
  role: UserRole.ADMIN,
  email: 'system@dryerjs.com',
  name: 'system',
};

@Hook(() => User)
class UserHook implements Hook<User, Context> {
  async beforeUpdate({
    ctx,
    input,
  }: BeforeUpdateHookInput<User, Context>): Promise<void> {
    if (ctx.role === UserRole.USER && input.role === UserRole.ADMIN) {
      throw new UnauthorizedException('YOU_WERE_CAUGHT');
    }
  }
}

@Hook(() => Post)
class PostHook implements Hook<Post, Context> {
  async beforeUpdate({
    ctx,
    beforeUpdated,
  }: BeforeUpdateHookInput<Post, Context>): Promise<void> {
    if (
      ctx?.role === UserRole.USER &&
      beforeUpdated.id.toString() !== ctx.id.toString()
    ) {
      throw new UnauthorizedException('YOU_WERE_CAUGHT');
    }
  }

  async beforeRemove({
    ctx,
    beforeRemoved,
  }: BeforeRemoveHookInput<Post, Context>): Promise<void> {
    if (
      ctx?.role === UserRole.USER &&
      beforeRemoved.id.toString() !== ctx.id.toString()
    ) {
      throw new UnauthorizedException('YOU_WERE_CAUGHT');
    }
  }

  async beforeFindOne({
    ctx,
    filter,
  }: BeforeFindOneHookInput<Post, Context>): Promise<void> {
    if (ctx === null) filter.isPublic = true;
  }

  async afterFindOne({
    ctx,
    result,
  }: AfterFindOneHookInput<Post, Context>): Promise<void> {
    if (result.isPublic) return;
    if (ctx?.role === UserRole.ADMIN) return;
    if (result.userId.toString() !== ctx.id.toString()) {
      throw new NotFoundException();
    }
  }

  async beforeFindMany({
    ctx,
    filter,
  }: BeforeFindManyHookInput<Post, Context>): Promise<void> {
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
    const user = await this.userService.findOne(SYSTEM, {
      email: input.email,
    });
    if (user.password !== input.password) {
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
    @InjectModel('User') readonly User: PaginateModel<User>,
    @InjectModel('Post') readonly Post: PaginateModel<User>,
  ) {}

  async onModuleInit() {
    if ((await this.User.countDocuments({})) !== 0) return;
    console.log('Seeding...');
    const adminUserId = new ObjectId('000000000000000000000000');
    const normalUserId = new ObjectId('000000000000000000000001');
    const users = [
      {
        _id: adminUserId,
        email: 'admin@dryerjs.com',
        password: 'password',
        name: 'Admin@DryerJS',
        role: UserRole.ADMIN,
      },
      {
        _id: new ObjectId('000000000000000000000001'),
        email: 'user@dryerjs.com',
        password: 'password',
        name: 'User@DryerJS',
        role: UserRole.USER,
      },
    ];
    const posts = [
      {
        _id: new ObjectId('000000000000000000000002'),
        content: 'Admin public announcement',
        isPublic: true,
        userId: adminUserId,
      },
      {
        _id: new ObjectId('000000000000000000000003'),
        content: 'Admin private note',
        isPublic: false,
        userId: adminUserId,
      },
      {
        _id: new ObjectId('000000000000000000000004'),
        content: 'User public note',
        isPublic: true,
        userId: normalUserId,
      },
      {
        _id: new ObjectId('000000000000000000000005'),
        content: 'User private note',
        isPublic: false,
        userId: normalUserId,
      },
    ];
    for (const user of users) await this.User.create(user);
    for (const post of posts) await this.Post.create(post);
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
    MongooseModule.forRoot('mongodb://127.0.0.1:27017/dryerjs-jwt'),
    DryerModule.register({
      definitions: [User, Post],
      contextDecorator: Ctx,
      hooks: [UserHook, PostHook],
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
