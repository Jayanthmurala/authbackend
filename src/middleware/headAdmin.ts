import { FastifyRequest, FastifyReply } from 'fastify';
import { verifyAccessToken } from '../utils/jwt';
import { prisma } from '../db';
import { Role } from '@prisma/client';

export interface AuthenticatedRequest extends FastifyRequest {
  user: {
    id: string;
    email: string;
    roles: Role[];
    collegeId: string;
    department?: string;
    displayName: string;
  };
}

/**
 * Middleware to verify JWT token and extract user information
 */
export async function requireAuth(request: FastifyRequest, reply: FastifyReply) {
  try {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.status(401).send({
        error: 'UNAUTHORIZED',
        message: 'Missing or invalid authorization header'
      });
    }

    const token = authHeader.substring(7);
    const payload = await verifyAccessToken(token);

    if (!payload.sub) {
      return reply.status(401).send({
        error: 'UNAUTHORIZED',
        message: 'Invalid token payload'
      });
    }

    // Fetch user details from database
    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        roles: true,
        collegeId: true,
        department: true,
        displayName: true,
        status: true
      }
    });

    if (!user || user.status !== 'ACTIVE') {
      return reply.status(401).send({
        error: 'UNAUTHORIZED',
        message: 'User not found or inactive'
      });
    }

    if (!user.collegeId) {
      return reply.status(401).send({
        error: 'UNAUTHORIZED',
        message: 'User must be associated with a college'
      });
    }

    // Attach user to request
    (request as AuthenticatedRequest).user = {
      ...user,
      collegeId: user.collegeId, // Now guaranteed to be non-null
      department: user.department || undefined,
    };
  } catch (error) {
    request.log.error({ error }, 'Auth middleware error');
    return reply.status(401).send({
      error: 'UNAUTHORIZED',
      message: 'Invalid or expired token'
    });
  }
}

/**
 * Middleware to ensure user has HEAD_ADMIN or SUPER_ADMIN role
 */
export async function requireHeadAdmin(request: FastifyRequest, reply: FastifyReply) {
  const authRequest = request as AuthenticatedRequest;
  
  if (!authRequest.user) {
    return reply.status(401).send({
      error: 'UNAUTHORIZED',
      message: 'Authentication required'
    });
  }

  const hasRequiredRole = authRequest.user.roles.some(role => 
    ['HEAD_ADMIN', 'SUPER_ADMIN'].includes(role)
  );

  if (!hasRequiredRole) {
    return reply.status(403).send({
      error: 'FORBIDDEN',
      message: 'HEAD_ADMIN or SUPER_ADMIN role required'
    });
  }
}

/**
 * Middleware to ensure user has DEPT_ADMIN, HEAD_ADMIN, or SUPER_ADMIN role
 */
export async function requireAdminRole(request: FastifyRequest, reply: FastifyReply) {
  const authRequest = request as AuthenticatedRequest;
  
  if (!authRequest.user) {
    return reply.status(401).send({
      error: 'UNAUTHORIZED',
      message: 'Authentication required'
    });
  }

  const hasAdminRole = authRequest.user.roles.some(role => 
    ['HEAD_ADMIN', 'DEPT_ADMIN', 'SUPER_ADMIN'].includes(role)
  );

  if (!hasAdminRole) {
    return reply.status(403).send({
      error: 'FORBIDDEN',
      message: 'Admin role required (HEAD_ADMIN, DEPT_ADMIN, or SUPER_ADMIN)'
    });
  }
}

/**
 * Helper function to get college-scoped where clause
 */
export function getCollegeScopedWhere(request: FastifyRequest, additionalWhere: any = {}) {
  const authRequest = request as AuthenticatedRequest;
  return {
    ...additionalWhere,
    collegeId: authRequest.user.collegeId
  };
}

/**
 * Helper function to check if user can access resource in their college
 */
export async function canAccessCollegeResource(
  request: FastifyRequest, 
  resourceCollegeId: string
): Promise<boolean> {
  const authRequest = request as AuthenticatedRequest;
  return authRequest.user.collegeId === resourceCollegeId;
}
