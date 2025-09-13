import Fastify from "fastify";
import cors from "@fastify/cors";
import cookie from "@fastify/cookie";
import swagger from "@fastify/swagger";
import swaggerUI from "@fastify/swagger-ui";
import { ZodTypeProvider, serializerCompiler, validatorCompiler, jsonSchemaTransform } from "fastify-type-provider-zod";
import { env } from "../src/config/env";
import authRoutes from "../src/routes/auth.routes";
import collegeRoutes from "../src/routes/college.routes";
import backendAdminRoutes from "../src/routes/backendAdmin.routes";
import headAdminRoutes from "../src/routes/headAdmin.routes";
import { getJWKS } from "../src/utils/jwt";

let app: any = null;

async function buildServer() {
  if (app) return app;
  
  const fastify = Fastify({ 
    logger: process.env.NODE_ENV === 'development',
    trustProxy: true 
  }).withTypeProvider<ZodTypeProvider>();

  // Enable Zod validation/serialization
  fastify.setValidatorCompiler(validatorCompiler);
  fastify.setSerializerCompiler(serializerCompiler);

  await fastify.register(cors, {
    origin: [
      "http://localhost:3000", 
      "http://127.0.0.1:3000", 
      "https://nexus-frontend-pi-ten.vercel.app",
      /\.vercel\.app$/
    ],
    credentials: true,
    allowedHeaders: ["Authorization", "Content-Type"],
  });

  await fastify.register(cookie);

  await fastify.register(swagger, {
    openapi: {
      info: { title: "Nexus Auth Service", version: "0.1.0" },
      servers: [
        { url: `https://nexus-auth-service.vercel.app` },
        { url: `http://localhost:${env.PORT || 4001}` }
      ],
      components: {},
      tags: [
        { name: "auth", description: "Authentication endpoints" },
        { name: "colleges", description: "College management endpoints" },
        { name: "backend-admin", description: "Backend admin endpoints" },
        { name: "head-admin", description: "Head admin endpoints" },
      ],
    },
    transform: jsonSchemaTransform,
  });
  
  await fastify.register(swaggerUI, { routePrefix: "/docs" });
  
  fastify.get("/", async () => ({ message: "Welcome To NexUs 🤝" }));
  fastify.get("/health", async () => ({ status: "ok", timestamp: new Date().toISOString() }));
  fastify.get("/.well-known/jwks.json", async () => await getJWKS());

  await fastify.register(authRoutes);
  await fastify.register(collegeRoutes);
  await fastify.register(backendAdminRoutes);
  await fastify.register(headAdminRoutes);

  app = fastify;
  return fastify;
}

export default async function handler(request: Request): Promise<Response> {
  try {
    const server = await buildServer();
    await server.ready();
    
    const url = new URL(request.url);
    const method = request.method;
    const headers = Object.fromEntries(request.headers.entries());
    
    // Get the full path for routing
    let path = url.pathname;
    
    // Handle request body properly
    let payload: string | undefined;
    if (request.body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      payload = await request.text();
    }

    // Use Fastify's inject method for serverless compatibility
    const response = await server.inject({
      method: method as any,
      url: path + url.search,
      headers,
      payload,
    });

    return new Response(response.payload, {
      status: response.statusCode,
      headers: response.headers as any,
    });
  } catch (error) {
    console.error('Auth service error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error',
      message: process.env.NODE_ENV === 'development' ? (error as Error).message : 'Something went wrong'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
