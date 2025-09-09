import type { FastifyInstance } from "fastify";
import { prisma } from "../db";
import { requireAuth, requireHeadAdmin, getCollegeScopedWhere, AuthenticatedRequest } from "../middleware/headAdmin";
import { hashPassword } from "../utils/crypto";

export default async function headAdminRoutes(fastify: FastifyInstance) {
  
  // List all users in HEAD_ADMIN's college
  fastify.get('/v1/head-admin/users', {
    preHandler: [requireAuth, requireHeadAdmin]
  }, async (request, reply) => {
    const authRequest = request as AuthenticatedRequest;
    const query = request.query as any;
    
    const limit = parseInt(query.limit) || 50;
    const offset = parseInt(query.offset) || 0;
    const search = query.search;
    const role = query.role;
    const department = query.department;
    const status = query.status;
    const year = query.year;

    let whereClause = getCollegeScopedWhere(request);

    // Add filters
    if (search) {
      whereClause = {
        ...whereClause,
        OR: [
          { displayName: { contains: search, mode: 'insensitive' } },
          { email: { contains: search, mode: 'insensitive' } },
          { collegeMemberId: { contains: search, mode: 'insensitive' } },
        ],
      };
    }

    if (role) {
      whereClause.roles = { has: role };
    }

    if (department) {
      whereClause.department = department;
    }

    if (status) {
      whereClause.status = status;
    }

    if (year) {
      whereClause.year = parseInt(year);
    }

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where: whereClause,
        select: {
          id: true,
          displayName: true,
          email: true,
          roles: true,
          department: true,
          year: true,
          collegeMemberId: true,
          status: true,
          avatarUrl: true,
          createdAt: true,
          lastLoginAt: true,
        },
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
      }),
      prisma.user.count({ where: whereClause }),
    ]);

    return {
      users,
      total,
      limit,
      offset,
    };
  });

  // Create new user in HEAD_ADMIN's college
  fastify.post('/v1/head-admin/users', {
    preHandler: [requireAuth, requireHeadAdmin]
  }, async (request, reply) => {
    const authRequest = request as AuthenticatedRequest;
    const userData = request.body as any;

    // Check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: userData.email },
    });

    if (existingUser) {
      return reply.status(409).send({
        error: 'CONFLICT',
        message: 'User with this email already exists',
      });
    }

    // Generate password if not provided
    const password = userData.password || Math.random().toString(36).slice(-12);
    const passwordHash = await hashPassword(password);

    const newUser = await prisma.user.create({
      data: {
        displayName: userData.displayName,
        email: userData.email,
        passwordHash,
        roles: userData.roles,
        collegeId: authRequest.user.collegeId,
        department: userData.department,
        year: userData.year,
        collegeMemberId: userData.collegeMemberId,
        status: userData.status || 'ACTIVE',
        emailVerifiedAt: userData.status === 'ACTIVE' ? new Date() : null,
      },
      select: {
        id: true,
        displayName: true,
        email: true,
        roles: true,
        department: true,
        year: true,
        collegeMemberId: true,
        status: true,
        avatarUrl: true,
        createdAt: true,
        lastLoginAt: true,
      },
    });

    reply.status(201);
    return newUser;
  });

  // Bulk create users in HEAD_ADMIN's college
  fastify.post('/v1/head-admin/users/bulk', {
    preHandler: [requireAuth, requireHeadAdmin]
  }, async (request, reply) => {
    const authRequest = request as AuthenticatedRequest;
    const { users, defaultPassword } = request.body as {
      users: any[];
      defaultPassword?: string;
    };

    if (!users || !Array.isArray(users) || users.length === 0) {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Users array is required and must not be empty'
      });
    }

    if (users.length > 1000) {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Maximum 1000 users allowed per bulk operation'
      });
    }

    const results = {
      created: [] as any[],
      failed: [] as any[],
      summary: {
        total: users.length,
        successful: 0,
        failed: 0
      }
    };

    // Process users sequentially to avoid database conflicts
    for (const userData of users) {
      try {
        // Validate required fields
        if (!userData.email || !userData.displayName || !userData.roles) {
          results.failed.push({
            email: userData.email || 'unknown',
            error: 'Missing required fields: email, displayName, roles'
          });
          results.summary.failed++;
          continue;
        }

        // Validate collegeId - must match HEAD_ADMIN's college
        if (userData.collegeId && userData.collegeId !== authRequest.user.collegeId) {
          results.failed.push({
            email: userData.email,
            error: `College ID mismatch. HEAD_ADMIN can only create users in their own college (${authRequest.user.collegeId})`
          });
          results.summary.failed++;
          continue;
        }

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({
          where: { email: userData.email }
        });

        if (existingUser) {
          results.failed.push({
            email: userData.email,
            error: 'User with this email already exists'
          });
          results.summary.failed++;
          continue;
        }

        // Generate password if not provided
        const password = userData.password || defaultPassword || Math.random().toString(36).slice(-12);
        const passwordHash = await hashPassword(password);

        // Create user - use provided collegeId or default to HEAD_ADMIN's college
        const newUser = await prisma.user.create({
          data: {
            displayName: userData.displayName,
            email: userData.email,
            passwordHash,
            roles: userData.roles,
            collegeId: userData.collegeId || authRequest.user.collegeId,
            department: userData.department,
            year: userData.year,
            collegeMemberId: userData.collegeMemberId,
            status: userData.status || 'ACTIVE',
            emailVerifiedAt: (userData.status || 'ACTIVE') === 'ACTIVE' ? new Date() : null,
          },
          select: {
            id: true,
            displayName: true,
            email: true,
            roles: true,
            department: true,
            year: true,
            collegeMemberId: true,
            status: true,
            createdAt: true,
          }
        });

        results.created.push(newUser);
        results.summary.successful++;

      } catch (error) {
        results.failed.push({
          email: userData.email || 'unknown',
          error: (error as Error).message
        });
        results.summary.failed++;
      }
    }

    return results;
  });

  // Update user in HEAD_ADMIN's college
  fastify.put('/v1/head-admin/users/:userId', {
    preHandler: [requireAuth, requireHeadAdmin]
  }, async (request, reply) => {
    const authRequest = request as AuthenticatedRequest;
    const userData = request.body as any;
    const params = request.params as any;
    const userId = params.userId;

    // Check if user exists and belongs to same college
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, collegeId: true, roles: true, email: true },
    });

    if (!user) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: 'User not found',
      });
    }

    if (user.collegeId !== authRequest.user.collegeId) {
      return reply.status(403).send({
        error: 'FORBIDDEN',
        message: 'Cannot update user from different college',
      });
    }

    // Prevent HEAD_ADMIN from updating other HEAD_ADMINs or SUPER_ADMINs
    if (user.roles.includes('HEAD_ADMIN') || user.roles.includes('SUPER_ADMIN')) {
      return reply.status(403).send({
        error: 'FORBIDDEN',
        message: 'Cannot update HEAD_ADMIN or SUPER_ADMIN users',
      });
    }

    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: {
        displayName: userData.displayName,
        email: userData.email,
        roles: userData.roles,
        department: userData.department,
        year: userData.year,
        collegeMemberId: userData.collegeMemberId,
        status: userData.status,
      },
      select: {
        id: true,
        displayName: true,
        email: true,
        roles: true,
        department: true,
        year: true,
        collegeMemberId: true,
        status: true,
        avatarUrl: true,
        createdAt: true,
        lastLoginAt: true,
      },
    });

    return updatedUser;
  });

  // Reset user password in HEAD_ADMIN's college
  fastify.post('/v1/head-admin/users/:userId/reset-password', {
    preHandler: [requireAuth, requireHeadAdmin]
  }, async (request, reply) => {
    const authRequest = request as AuthenticatedRequest;
    const params = request.params as any;
    const body = request.body as any;
    
    const userId = params.userId;
    const newPassword = body.newPassword;
    const forceChange = body.forceChange;

    // Check if user exists and belongs to same college
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, collegeId: true, roles: true, email: true },
    });

    if (!user) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: 'User not found',
      });
    }

    if (user.collegeId !== authRequest.user.collegeId) {
      return reply.status(403).send({
        error: 'FORBIDDEN',
        message: 'Cannot reset password for user from different college',
      });
    }

    // Prevent HEAD_ADMIN from resetting other HEAD_ADMINs or SUPER_ADMINs passwords
    if (user.roles.includes('HEAD_ADMIN') || user.roles.includes('SUPER_ADMIN')) {
      return reply.status(403).send({
        error: 'FORBIDDEN',
        message: 'Cannot reset password for HEAD_ADMIN or SUPER_ADMIN users',
      });
    }

    const passwordHash = await hashPassword(newPassword);

    await prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash,
        tokenVersion: { increment: 1 }, // Invalidate existing tokens
      },
    });

    return {
      message: 'Password reset successfully',
      ...(forceChange && { temporaryPassword: newPassword }),
    };
  });

  // Get HEAD_ADMIN's college information
  fastify.get('/v1/head-admin/college', {
    preHandler: [requireAuth, requireHeadAdmin]
  }, async (request, reply) => {
    const authRequest = request as AuthenticatedRequest;

    const college = await prisma.college.findUnique({
      where: { id: authRequest.user.collegeId },
      select: {
        id: true,
        name: true,
        code: true,
        location: true,
        website: true,
        departments: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!college) {
      return reply.status(404).send({
        error: 'NOT_FOUND',
        message: 'College not found',
      });
    }

    return college;
  });

  // Get college statistics for HEAD_ADMIN
  fastify.get('/v1/head-admin/stats', {
    preHandler: [requireAuth, requireHeadAdmin]
  }, async (request, reply) => {
    const authRequest = request as AuthenticatedRequest;
    const collegeId = authRequest.user.collegeId;

    // Get total users
    const totalUsers = await prisma.user.count({
      where: { collegeId },
    });

    // Get users by role
    const usersByRole = await prisma.user.groupBy({
      by: ['roles'],
      where: { collegeId },
      _count: true,
    });

    // Get users by status
    const usersByStatus = await prisma.user.groupBy({
      by: ['status'],
      where: { collegeId },
      _count: true,
    });

    // Get users by department
    const usersByDepartment = await prisma.user.groupBy({
      by: ['department'],
      where: { 
        collegeId,
        department: { not: null },
      },
      _count: true,
    });

    // Get recent registrations (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const recentRegistrations = await prisma.user.count({
      where: {
        collegeId,
        createdAt: { gte: thirtyDaysAgo },
      },
    });

    return {
      totalUsers,
      usersByRole: usersByRole.reduce((acc, item) => {
        item.roles.forEach(role => {
          acc[role] = (acc[role] || 0) + item._count;
        });
        return acc;
      }, {} as Record<string, number>),
      usersByStatus: usersByStatus.reduce((acc, item) => {
        acc[item.status] = item._count;
        return acc;
      }, {} as Record<string, number>),
      usersByDepartment: usersByDepartment.reduce((acc, item) => {
        if (item.department) {
          acc[item.department] = item._count;
        }
        return acc;
      }, {} as Record<string, number>),
      recentRegistrations,
    };
  });
}
