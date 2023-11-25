import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ApolloServerPluginLandingPageLocalDefault } from '@apollo/server/plugin/landingPage/default';
import { User } from './user';
import { DryerModule } from 'dryerjs';

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
      definitions: [User],
    }),
    JwtModule.register({
      global: true,
      secret: 'DO_NOT_TELL_ANYONE',
      signOptions: { expiresIn: '7d' },
    }),
  ],
})
export class AppModule {}
