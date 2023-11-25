import { Module } from '@nestjs/common';
import { GraphQLISODateTime, GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { MongooseModule } from '@nestjs/mongoose';
import {
  Definition,
  DryerModule,
  Embedded,
  Id,
  ObjectId,
  Property,
  Skip,
} from 'dryerjs';
import { ApolloServerPluginLandingPageLocalDefault } from '@apollo/server/plugin/landingPage/default';

export const AutoTimestamp = () => {
  return Property({
    output: { type: () => GraphQLISODateTime },
    create: Skip,
    update: Skip,
  });
};

class Base {
  @Id()
  id: ObjectId;

  @AutoTimestamp()
  createdAt: Date;

  @AutoTimestamp()
  updatedAt: Date;
}

@Definition({ timestamps: true })
export class User extends Base {
  @Property()
  name: string;
}

@Definition()
class Brand {
  @Id()
  id: ObjectId;

  @Property()
  name: string;
}

@Definition()
export class Car {
  @Id()
  id: ObjectId;

  @Property()
  name: string;

  @Embedded(() => Brand, {
    overridePropertyOptions: {
      create: { nullable: false },
      output: { nullable: false },
      db: { required: true },
    },
  })
  brand: Brand;
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
      definitions: [User, Car],
    }),
  ],
})
export class AppModule {}
