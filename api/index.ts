// Types for Vercel serverless functions
interface VercelRequest {
  method?: string;
  url?: string;
  headers: any;
  body?: any;
}

interface VercelResponse {
  status: (code: number) => VercelResponse;
  setHeader: (key: string, value: string) => void;
  send: (data: any) => void;
}
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
  const fastify = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();

  // Enable Zod validation/serialization
  fastify.setValidatorCompiler(validatorCompiler);
  fastify.setSerializerCompiler(serializerCompiler);

  await fastify.register(cors, {
    origin: true,
    credentials: true,
    allowedHeaders: ["Authorization", "Content-Type"],
  });

  await fastify.register(cookie);

  await fastify.register(swagger, {
    openapi: {
      info: { title: "Nexus Auth Service", version: "0.1.0" },
      servers: [{ url: `https://your-vercel-domain.vercel.app` }],
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
  
  fastify.get("/", async () => ({ message: "Welcome To Nexus Auth Service 🤝" }));
  fastify.get("/health", async () => ({ status: "ok" }));
  fastify.get("/.well-known/jwks.json", async () => await getJWKS());

  await fastify.register(authRoutes);
  await fastify.register(collegeRoutes);
  await fastify.register(backendAdminRoutes);
  await fastify.register(headAdminRoutes);

  return fastify;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (!app) {
    app = await buildServer();
    await app.ready();
  }

  const response = await app.inject({
    method: req.method,
    url: req.url,
    headers: req.headers,
    payload: req.body,
  });

  res.status(response.statusCode);
  
  Object.keys(response.headers).forEach(key => {
    res.setHeader(key, response.headers[key]);
  });

  res.send(response.payload);
}
