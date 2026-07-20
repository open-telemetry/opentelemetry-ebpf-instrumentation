"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@nestjs/core");
const platform_fastify_1 = require("@nestjs/platform-fastify");
const cors_1 = require("@fastify/cors");
const app_module_1 = require("./app.module");
async function bootstrap() {
    const adapter = new platform_fastify_1.FastifyAdapter();
    const app = await core_1.NestFactory.create(app_module_1.AppModule, adapter, {
        bufferLogs: true,
    });
    await app.register(cors_1.default, { origin: true });
    await app.listen(8080, '0.0.0.0');
}
bootstrap();
