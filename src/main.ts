import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use('/', (req, res, next) => {
    if (req.path !== '/') return next();
    res.redirect('/graphql');
  });
  await app.listen(3000);
}

bootstrap();
