// Example Fastify application
const fastify = require("fastify")({ logger: true });

fastify.route({
  method: "POST",
  url: "/api/v2/items",
  handler: async (request, reply) => {
    return { created: true };
  },
});

// Simple routes
fastify.get("/", async (request, reply) => {
  return { hello: "world" };
});

fastify.post("/users", async (request, reply) => {
  return { id: 123, ...request.body };
});

// Routes with parameters
fastify.get("/users/:id", async (request, reply) => {
  return { userId: request.params.id };
});

fastify.put("/posts/:postId/comments/:commentId", async (request, reply) => {
  return { updated: true };
});

// Route object syntax
fastify.route({
  method: "GET",
  url: "/search",
  handler: async (request, reply) => {
    return { results: [] };
  },
});

fastify.route({
  method: "DELETE",
  url: "/api/v2/items/:id",
  schema: {
    params: {
      type: "object",
      properties: {
        id: { type: "string" },
      },
    },
  },
  handler: async (request, reply) => {
    reply.code(204).send();
  },
});

// Multiple methods
fastify.patch("/settings/:key", async (request, reply) => {
  return { key: request.params.key, updated: true };
});

fastify.delete("/cache", async (request, reply) => {
  return { cleared: true };
});

const start = async () => {
  try {
    await fastify.listen({ port: 3001, host: "0.0.0.0" });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
