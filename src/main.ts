import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { ApiAcceptedResponse, DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
 
  app.setGlobalPrefix('api');
  app.enableVersioning({
   type:VersioningType.URI,
   defaultVersion: '1',
  });

  // Enable CORS with specific options
  app.enableCors({
    origin: [
      'http://localhost:3000',
      'http://localhost:3001',
      'https://yourdomain.com',
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Accept',
      'Origin',
      'Access-Control-Allow-Headers',
      'Access-Control-Request-Method',
      'Access-Control-Request-Headers',
    ],
    credentials: true,
    preflightContinue: false,
    optionsSuccessStatus: 204,
  });

  app.set('trust proxy', 1);

  app.useGlobalPipes(new ValidationPipe());

  // --- SWAGGER CONFIG ---
  const config = new DocumentBuilder()
    .setTitle('Auth System API')
    .setDescription(
      'Industrial grade Authentication with Access/Refresh tokens, RBAC, and OTP',
    )
    .setVersion('1.0')
    .addBearerAuth() // Enables the "Authorize" button for JWTs
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document); // Swagger available at /api
  // ----------------------

  await app.listen(process.env.PORT || 8080);
}
bootstrap();
