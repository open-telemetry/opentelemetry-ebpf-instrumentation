// Example NestJS bootstrap using the Fastify adapter
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import cors from '@fastify/cors';
import multipart from '@fastify/multipart';
import { AppModule } from './app.module';

async function bootstrap() {
  const adapter = new FastifyAdapter();
  const app = await NestFactory.create<NestFastifyApplication>(AppModule, adapter, {
    bufferLogs: true,
  });
  await app.register(cors, { origin: true });
  await app.register(multipart, { limits: { fileSize: 1048576 } });
  await app.listen(8080, '0.0.0.0');
}
bootstrap();
