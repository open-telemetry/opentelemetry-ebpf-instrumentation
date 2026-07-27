// Example NestJS controller with a bare method decorator: the route is the
// controller prefix itself. The handler reads the raw Fastify request.
import type { FastifyRequest } from 'fastify';
import { Controller, HttpCode, Post, Req } from '@nestjs/common';

@Controller('callbacks/acme')
export class AcmeCallbackController {
  @Post()
  @Public()
  @HttpCode(200)
  ingest(@Req() request: FastifyRequest) {
    return this.handler.ingestRaw(request.body, request.headers);
  }
}
