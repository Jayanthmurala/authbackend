import type { FastifyInstance } from "fastify";
import { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import crypto from "node:crypto";
import { prisma } from "../db";
import { env } from "../config/env";
import { hashPassword, verifyPassword, hashSecret, verifySecret } from "../utils/crypto";
import { signAccessToken, verifyAccessToken } from "../utils/jwt";
import { authSuccessResponseSchema, loginBodySchema, errorResponseSchema, oauthExchangeBodySchema, forgotPasswordBodySchema, resetPasswordBodySchema, verifyEmailBodySchema, resendVerificationBodySchema, messageResponseSchema, registerBodySchema, superAdminRegisterBodySchema } from "../schemas/auth.schemas";
import { ProfileInitializationService } from "../services/ProfileInitializationService";

const usersQuerySchema = z.object({
  limit: z.string().optional(),
  offset: z.string().optional(),
  q: z.string().optional(),
  role: z.enum(["STUDENT", "FACULTY", "DEPT_ADMIN", "PLACEMENTS_ADMIN", "HEAD_ADMIN"]).optional(),
});
import { sendPasswordResetEmail, sendVerificationEmail } from "../emails/mailer";

const REFRESH_COOKIE = "rt";

function parseExpiryToMs(input: string): number {
  const m = input.trim().match(/^(\d+)([smhd])$/i);
  if (!m) return 0;
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  switch (unit) {
    case "s": return n * 1000;
    case "m": return n * 60 * 1000;
    case "h": return n * 60 * 60 * 1000;
    case "d": return n * 24 * 60 * 60 * 1000;
    default: return 0;
  }
}

function buildCookieOptions(expiresAt: Date) {
  const secure = env.NODE_ENV === "production";
  const opts: any = {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
    expires: expiresAt,
  };
  if (env.COOKIE_DOMAIN) {
    opts.domain = env.COOKIE_DOMAIN;
  }
  return opts;
}

async function issueRefreshTokenCookie(userId: string, reply: any) {
  const secret = crypto.randomBytes(32).toString("base64url");
  const expiresInMs = parseExpiryToMs(env.AUTH_JWT_REFRESH_EXPIRES_IN);
  const expiresAt = new Date(Date.now() + (expiresInMs || 30 * 24 * 60 * 60 * 1000));

  const token = await prisma.securityToken.create({
    data: {
      userId,
      tokenHash: await hashSecret(secret),
      type: "REFRESH_TOKEN",
      expiresAt,
    },
  });

  const cookieVal = `${token.id}.${secret}`;
  reply.setCookie(REFRESH_COOKIE, cookieVal, buildCookieOptions(expiresAt));
}

async function rotateRefreshToken(oldCookie: string | undefined, reply: any) {
  if (!oldCookie) return null;
  const [id, secret] = oldCookie.split(".");
  if (!id || !secret) return null;

  const record = await prisma.securityToken.findUnique({ where: { id } });
  if (!record || record.type !== "REFRESH_TOKEN") return null;
  if (record.usedAt || record.expiresAt < new Date()) return null;

  const ok = await verifySecret(record.tokenHash, secret);
  if (!ok) return null;

  // mark old token used and create a new one (rotation)
  await prisma.securityToken.update({ where: { id: record.id }, data: { usedAt: new Date() } });
  await issueRefreshTokenCookie(record.userId, reply);
  return record.userId;
}

// Fetch minimal profile from OAuth providers
async function initializeUserProfile(userId: string, accessToken: string) {
  const profileServiceUrl = process.env.PROFILE_SERVICE_URL || "http://localhost:4002";
  
  try {
    const response = await fetch(`${profileServiceUrl}/v1/profiles/me`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${accessToken}`,
      },
      body: JSON.stringify({}), // Empty profile data to initialize
    });

    if (!response.ok) {
      throw new Error(`Profile initialization failed: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("Profile initialization error:", error);
    throw error;
  }
}

async function getGoogleProfile(accessToken: string) {
  const resp = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!resp.ok) return null;
  const j: any = await resp.json();
  return {
    providerId: j.sub as string,
    email: j.email as string | null,
    emailVerified: Boolean(j.email_verified),
    name: (j.name as string) || null,
    avatarUrl: (j.picture as string) || null,
  };
}

async function getGithubProfile(accessToken: string) {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    "User-Agent": "nexus-auth-service",
    Accept: "application/vnd.github+json",
  } as any;
  const uResp = await fetch("https://api.github.com/user", { headers });
  if (!uResp.ok) return null;
  const u: any = await uResp.json();
  let email: string | null = u.email ?? null;
  if (!email) {
    const eResp = await fetch("https://api.github.com/user/emails", { headers });
    if (eResp.ok) {
      const emails: any[] = await eResp.json();
      const primary = Array.isArray(emails)
        ? emails.find((e: any) => e.primary && e.verified) || emails.find((e: any) => e.verified) || emails[0]
        : null;
      email = primary?.email ?? null;
    }
  }
  return {
    providerId: String(u.id),
    email,
    emailVerified: true,
    name: (u.name as string) || (u.login as string) || null,
    avatarUrl: (u.avatar_url as string) || null,
  };
}

async function authRoutes(app: FastifyInstance) {
  const f = app.withTypeProvider<ZodTypeProvider>();

  // GET /v1/auth/me - Get current user profile
  f.get("/v1/auth/me", {
    schema: {
      tags: ["auth"],
      security: [{ bearerAuth: [] }],
      response: {
        200: z.object({
          id: z.string(),
          email: z.string(),
          name: z.string(),
          roles: z.array(z.string()),
          collegeId: z.string().optional(),
          collegeMemberId: z.string().optional(),
          isEmailVerified: z.boolean(),
          createdAt: z.date(),
          updatedAt: z.date()
        }),
        401: errorResponseSchema
      }
    }
  }, async (req, reply) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return reply.code(401).send({ message: 'Unauthorized' });
    }
    
    try {
      const token = authHeader.slice('Bearer '.length);
      const payload = await verifyAccessToken(token);
      
      const user = await prisma.user.findUnique({
        where: { id: payload.sub },
        select: {
          id: true,
          email: true,
          displayName: true,
          roles: true,
          collegeId: true,
          collegeMemberId: true,
          emailVerifiedAt: true,
          createdAt: true,
          updatedAt: true
        }
      });
      
      if (!user) {
        return reply.code(401).send({ message: 'User not found' });
      }
      
      return reply.send({
        id: user.id,
        email: user.email,
        name: user.displayName,
        roles: user.roles,
        collegeId: user.collegeId || undefined,
        collegeMemberId: user.collegeMemberId || undefined,
        isEmailVerified: !!user.emailVerifiedAt,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      });
    } catch (error) {
      return reply.code(401).send({ message: 'Invalid token' });
    }
  });

  f.post("/v1/auth/register", {
    schema: {
      tags: ["auth"],
      body: registerBodySchema,
      response: { 201: authSuccessResponseSchema, 400: errorResponseSchema, 409: errorResponseSchema },
    },
  }, async (req, reply) => {
    const { displayName, email, password, role, collegeId, department, collegeMemberId, year } = req.body as z.infer<typeof registerBodySchema>;
    
    try {

      // Check if email already exists
      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        return reply.code(409).send({ 
          message: `Registration failed: The email address '${email}' is already registered. Please use a different email or try logging in.` 
        });
      }

      // Validate college exists and is active
      const college = await prisma.college.findUnique({ where: { id: collegeId } });
      if (!college) {
        return reply.code(400).send({ 
          message: `Registration failed: College with ID '${collegeId}' not found. Please contact your administrator or verify the college ID.` 
        });
      }
      if (!college.isActive) {
        return reply.code(400).send({ 
          message: `Registration failed: College '${college.name}' is currently inactive. Please contact your administrator.` 
        });
      }

      // Validate department exists in college
      if (!college.departments.includes(department)) {
        return reply.code(400).send({ 
          message: `Registration failed: Department '${department}' is not available in '${college.name}'. Available departments: ${college.departments.join(', ')}.` 
        });
      }

      // Check if collegeMemberId is unique within the college (if provided)
      if (collegeMemberId) {
        const existingMember = await prisma.user.findFirst({
          where: {
            collegeId,
            collegeMemberId,
          },
        });
        if (existingMember) {
          return reply.code(409).send({ 
            message: `Registration failed: College member ID '${collegeMemberId}' already exists in '${college.name}'. Please use a different member ID.` 
          });
        }
      }

      // Validate year is provided for students
      if (role === "STUDENT" && !year) {
        return reply.code(400).send({ 
          message: "Registration failed: Year is required for student registration. Please provide your academic year (1-6)." 
        });
      }
    } catch (validationError: any) {
      // Handle Zod validation errors with clear field-specific messages
      if (validationError.issues) {
        const fieldErrors = validationError.issues.map((issue: any) => {
          const field = issue.path.join('.');
          switch (field) {
            case 'email':
              return `Email: ${issue.message.toLowerCase()}. Please provide a valid email address.`;
            case 'password':
              return `Password: Must be at least 8 characters long.`;
            case 'displayName':
              return `Display Name: ${issue.message.toLowerCase()}. Please provide your full name.`;
            case 'collegeId':
              return `College: This field is required. Please select your college.`;
            case 'department':
              return `Department: This field is required. Please select your department.`;
            case 'role':
              return `Role: Invalid role selected. Available roles: STUDENT, FACULTY, DEPT_ADMIN, PLACEMENTS_ADMIN, HEAD_ADMIN.`;
            case 'year':
              return `Year: Must be a number between 1 and 6.`;
            default:
              return `${field}: ${issue.message}`;
          }
        });
        
        return reply.code(400).send({ 
          message: `Registration failed due to validation errors:\n• ${fieldErrors.join('\n• ')}` 
        });
      }
      
      return reply.code(400).send({ 
        message: "Registration failed: Invalid request data. Please check all required fields and try again." 
      });
    }

    const user = await prisma.user.create({
      data: {
        email,
        passwordHash: await hashPassword(password),
        displayName,
        roles: [role],
        status: "ACTIVE",
        collegeId,
        department,
        year: role === "STUDENT" ? year : undefined,
        collegeMemberId,
        preferences: { create: {} },
      },
    });

    const accessToken = await signAccessToken(user.id, {
      email: user.email,
      roles: user.roles,
      displayName: user.displayName,
      collegeId: user.collegeId,
    });

    await issueRefreshTokenCookie(user.id, reply);

    // Initialize user profile asynchronously for new registration
    ProfileInitializationService.initializeUserProfileAsync({
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      roles: user.roles,
      avatarUrl: user.avatarUrl,
      collegeId: user.collegeId,
      department: user.department,
      year: user.year,
      collegeMemberId: user.collegeMemberId,
    });

    return reply.code(201).send({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        roles: user.roles,
        avatarUrl: user.avatarUrl ?? null,
        collegeId: user.collegeId,
        department: user.department,
        year: user.year,
        collegeMemberId: user.collegeMemberId,
      },
    });
  });

  // OAuth exchange: client sends provider accessToken; we return backend-issued tokens
  f.post("/v1/auth/oauth/exchange", {
    schema: {
      tags: ["auth"],
      body: oauthExchangeBodySchema,
      response: { 200: authSuccessResponseSchema, 400: errorResponseSchema },
    },
  }, async (req, reply) => {
    const { provider, accessToken: providerToken } = req.body as z.infer<typeof oauthExchangeBodySchema>;
    let profile: any = null;
    try {
      profile = provider === "google" ? await getGoogleProfile(providerToken) : await getGithubProfile(providerToken);
    } catch {
      profile = null;
    }
    if (!profile || !profile.email) {
      return reply.code(400).send({ message: "Invalid provider token or email not available" });
    }

    // Find or create user by email
    let user = await prisma.user.findUnique({ where: { email: profile.email } });
    if (!user) {
      user = await prisma.user.create({
        data: {
          email: profile.email,
          passwordHash: null,
          displayName: profile.name || profile.email.split("@")[0],
          avatarUrl: profile.avatarUrl ?? null,
          roles: ["STUDENT"],
          status: "ACTIVE",
          preferences: { create: {} },
        },
      });
    }

    // Upsert OAuthAccount link
    await prisma.oAuthAccount.upsert({
      where: { provider_providerAccountId: { provider, providerAccountId: profile.providerId } },
      update: { userId: user.id, accessToken: providerToken },
      create: { userId: user.id, provider, providerAccountId: profile.providerId, accessToken: providerToken },
    });

    const accessToken = await signAccessToken(user.id, {
      email: user.email,
      roles: user.roles,
      displayName: user.displayName,
      tokenVersion: user.tokenVersion,
      // profile: {
      //   collegeId: user.collegeId,
      //   department: user.department,
      //   year: user.year,
      // },
      profile: {
        collegeId: user.collegeId,
        department: user.department,
        year: user.year,
      },
    });

    await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
    await issueRefreshTokenCookie(user.id, reply);

    return reply.send({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        roles: user.roles,
        avatarUrl: user.avatarUrl ?? null,
      },
    });
  });

  // Token refresh endpoint
  f.post("/v1/auth/refresh", {
    schema: {
      tags: ["auth"],
      response: { 200: authSuccessResponseSchema, 401: errorResponseSchema },
    },
  }, async (req, reply) => {
    const oldCookie = req.cookies[REFRESH_COOKIE];
    const userId = await rotateRefreshToken(oldCookie, reply);
    
    if (!userId) {
      return reply.code(401).send({ message: "Invalid or expired refresh token" });
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return reply.code(401).send({ message: "User not found" });
    }

    const accessToken = await signAccessToken(user.id, {
      email: user.email,
      roles: user.roles,
      displayName: user.displayName,
      collegeId: user.collegeId,
    });

    return reply.send({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        roles: user.roles,
        avatarUrl: user.avatarUrl ?? null,
      },
    });
  });

  // Logout endpoint
  f.post("/v1/auth/logout", {
    schema: {
      tags: ["auth"],
      response: { 200: z.object({ success: z.boolean() }) },
    },
  }, async (req, reply) => {
    // Best-effort: mark current refresh token used
    const raw = req.cookies[REFRESH_COOKIE];
    if (raw) {
      const id = raw.split(".")[0];
      await prisma.securityToken.updateMany({ where: { id }, data: { usedAt: new Date() } });
    }
    
    // Clear the refresh token cookie
    const cookieOptions = {
      httpOnly: true,
      secure: env.NODE_ENV === "production",
      sameSite: "lax" as const,
      path: "/",
    };
    
    if (env.COOKIE_DOMAIN) {
      (cookieOptions as any).domain = env.COOKIE_DOMAIN;
    }
    
    reply.clearCookie(REFRESH_COOKIE, cookieOptions);
    reply.send({ success: true });
  });

  // ...

  f.post("/v1/auth/login", {
    schema: {
      tags: ["auth"],
      body: loginBodySchema,
      response: { 200: authSuccessResponseSchema, 400: errorResponseSchema, 401: errorResponseSchema },
    },
  }, async (req, reply) => {
    const { email, password } = req.body as z.infer<typeof loginBodySchema>;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash) {
      return reply.code(401).send({ message: "Invalid email or password" });
    }

    const valid = await verifyPassword(user.passwordHash, password);
    if (!valid) {
      return reply.code(401).send({ message: "Invalid email or password" });
    }

    await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
    await issueRefreshTokenCookie(user.id, reply);

    // Initialize user profile asynchronously (doesn't block login)
    ProfileInitializationService.initializeUserProfileAsync({
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      roles: user.roles,
      avatarUrl: user.avatarUrl,
      collegeId: user.collegeId,
      department: user.department,
      year: user.year,
      collegeMemberId: user.collegeMemberId,
    });

    const accessToken = await signAccessToken(user.id, {
      email: user.email,
      roles: user.roles,
      displayName: user.displayName,
      collegeId: user.collegeId,
    });

    return reply.send({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        roles: user.roles,
        avatarUrl: user.avatarUrl ?? null,
        collegeId: user.collegeId,
        department: user.department,
        year: user.year,
        collegeMemberId: user.collegeMemberId,
      },
    });
  });

  // Public: List users directory with optional filters
  f.get("/v1/users", {
    schema: {
      tags: ["users"],
      querystring: usersQuerySchema,
      response: { 200: z.any() },
    },
  }, async (req, reply) => {
    const { limit = "20", offset = "0", q, role } = req.query as z.infer<typeof usersQuerySchema>;
    
    const where: any = {};
    if (q) {
      where.OR = [
        { displayName: { contains: q, mode: "insensitive" } },
        { email: { contains: q, mode: "insensitive" } },
      ];
    }
    if (role) {
      where.roles = { has: role };
    }

    const users = await prisma.user.findMany({
      where,
      orderBy: { displayName: "asc" },
      take: parseInt(limit),
      skip: parseInt(offset),
    });

    // Transform the response to only include safe fields
    const safeUsers = users.map(user => ({
      id: user.id,
      displayName: user.displayName,
      email: user.email,
      avatarUrl: user.avatarUrl,
      roles: user.roles,
      collegeId: (user as any).collegeId,
      department: (user as any).department,
      year: (user as any).year,
      createdAt: user.createdAt,
    }));

    return reply.send({ users: safeUsers });
  });

  // Protected: Get user by ID (for inter-service communication)
  f.get("/v1/users/:userId", {
    schema: {
      tags: ["users"],
      params: z.object({ userId: z.string().cuid() }),
      response: { 200: z.any(), 404: errorResponseSchema },
    },
  }, async (req, reply) => {
    const { userId } = req.params as { userId: string };
    
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        displayName: true,
        email: true,
        avatarUrl: true,
        roles: true,
        collegeId: true,
        department: true,
        year: true,
        collegeMemberId: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      return reply.code(404).send({ message: "User not found" });
    }

    return reply.send({ user });
  });

  // Protected: Update user displayName (for inter-service communication)
  f.put("/v1/users/:userId", {
    schema: {
      tags: ["users"],
      params: z.object({ userId: z.string().cuid() }),
      body: z.object({ 
        displayName: z.string().min(1).max(100).optional(),
        avatarUrl: z.string().url().optional(),
        collegeId: z.string().cuid().optional(),
        department: z.string().min(1).max(100).optional(),
        year: z.number().int().min(1).max(6).optional()
      }),
      response: { 200: z.any(), 404: errorResponseSchema },
    },
  }, async (req, reply) => {
    const { userId } = req.params as { userId: string };
    const { displayName, avatarUrl, collegeId, department, year } = req.body as { 
      displayName?: string; 
      avatarUrl?: string; 
      collegeId?: string; 
      department?: string; 
      year?: number; 
    };
    
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return reply.code(404).send({ message: "User not found" });
    }

    // Validate college if provided
    if (collegeId) {
      const college = await prisma.college.findUnique({ where: { id: collegeId } });
      if (!college || !college.isActive) {
        return reply.code(400).send({ message: "Invalid or inactive college" });
      }
      
      // Validate department exists in college
      if (department && !college.departments.includes(department)) {
        return reply.code(400).send({ 
          message: `Department '${department}' not available in '${college.name}'. Available: ${college.departments.join(', ')}` 
        });
      }
    }

    // Build update data object
    const updateData: any = {};
    if (displayName !== undefined) updateData.displayName = displayName;
    if (avatarUrl !== undefined) updateData.avatarUrl = avatarUrl;
    if (collegeId !== undefined) updateData.collegeId = collegeId;
    if (department !== undefined) updateData.department = department;
    if (year !== undefined) updateData.year = year;

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: updateData,
      select: {
        id: true,
        displayName: true,
        email: true,
        avatarUrl: true,
        roles: true,
        collegeId: true,
        department: true,
        year: true,
        collegeMemberId: true,
        updatedAt: true,
      },
    });

    return reply.send({ user: updatedUser });
  });

  // Complete user profile (for users with incomplete college affiliation)
  f.put("/v1/auth/complete-profile", {
    schema: {
      tags: ["auth"],
      body: z.object({
        collegeId: z.string().cuid(),
        department: z.string().min(1).max(100),
        year: z.number().int().min(1).max(6).optional(),
        collegeMemberId: z.string().min(1).max(50).optional()
      }),
      response: { 200: z.any(), 400: errorResponseSchema, 401: errorResponseSchema },
    },
  }, async (req, reply) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return reply.code(401).send({ message: "Missing or invalid authorization header" });
    }

    try {
      const token = authHeader.substring(7);
      const payload = await verifyAccessToken(token);
      const userId = payload.sub;

      const { collegeId, department, year, collegeMemberId } = req.body as {
        collegeId: string;
        department: string;
        year?: number;
        collegeMemberId?: string;
      };

      // Validate college exists and is active
      const college = await prisma.college.findUnique({ where: { id: collegeId } });
      if (!college || !college.isActive) {
        return reply.code(400).send({ 
          message: `College not found or inactive. Please contact your administrator.` 
        });
      }

      // Validate department exists in college
      if (!college.departments.includes(department)) {
        return reply.code(400).send({ 
          message: `Department '${department}' not available in '${college.name}'. Available: ${college.departments.join(', ')}` 
        });
      }

      // Check if collegeMemberId is unique within the college (if provided)
      if (collegeMemberId) {
        const existingMember = await prisma.user.findFirst({
          where: {
            collegeId,
            collegeMemberId,
            id: { not: userId }, // Exclude current user
          },
        });
        if (existingMember) {
          return reply.code(400).send({ 
            message: `College member ID '${collegeMemberId}' already exists in '${college.name}'. Please use a different member ID.` 
          });
        }
      }

      // Update user profile
      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: {
          collegeId,
          department,
          year,
          collegeMemberId,
        },
        select: {
          id: true,
          displayName: true,
          email: true,
          avatarUrl: true,
          roles: true,
          collegeId: true,
          department: true,
          year: true,
          collegeMemberId: true,
          updatedAt: true,
        },
      });

      return reply.send({ 
        message: "Profile completed successfully",
        user: updatedUser 
      });

    } catch (error) {
      console.error("Profile completion error:", error);
      return reply.code(401).send({ message: "Invalid or expired token" });
    }
  });

  // Cron job endpoint to retry failed profile initializations
  f.post("/v1/auth/retry-profile-inits", {
    schema: {
      tags: ["auth"],
      response: { 200: messageResponseSchema, 401: errorResponseSchema },
    },
  }, async (req, reply) => {
    // Simple auth check - could be enhanced with API key
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${process.env.CRON_SECRET || 'cron-secret'}`) {
      return reply.code(401).send({ message: "Unauthorized - Invalid cron secret" });
    }

    try {
      await ProfileInitializationService.retryPendingProfileInits();
      return reply.send({ message: "Profile initialization retry completed" });
    } catch (error) {
      console.error("Profile retry cron job failed:", error);
      return reply.code(500).send({ message: "Profile retry failed" });
    }
  });
}

export default authRoutes;
