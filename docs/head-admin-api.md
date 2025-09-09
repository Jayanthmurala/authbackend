# HEAD_ADMIN API Documentation

## Overview
HEAD_ADMIN routes provide college-scoped administrative functionality for managing users, college information, and viewing statistics within their specific college.

## Authentication
All HEAD_ADMIN endpoints require:
- Valid JWT token with HEAD_ADMIN role
- User must be associated with a college
- All operations are scoped to the HEAD_ADMIN's college

## Endpoints

### User Management

#### GET /v1/head-admin/users
Get all users in HEAD_ADMIN's college with filtering and pagination.

**Query Parameters:**
- `limit` (optional): Number of users per page (default: 50)
- `offset` (optional): Pagination offset (default: 0)
- `search` (optional): Search by name, email, or college member ID
- `role` (optional): Filter by role (STUDENT, FACULTY, DEPT_ADMIN)
- `department` (optional): Filter by department
- `status` (optional): Filter by status (PENDING_VERIFICATION, ACTIVE, SUSPENDED)
- `year` (optional): Filter by academic year

**Response:**
```json
{
  "users": [
    {
      "id": "string",
      "displayName": "string",
      "email": "string",
      "roles": ["string"],
      "department": "string",
      "year": number,
      "collegeMemberId": "string",
      "status": "string",
      "avatarUrl": "string",
      "createdAt": "date",
      "lastLoginAt": "date"
    }
  ],
  "total": number,
  "limit": number,
  "offset": number
}
```

#### POST /v1/head-admin/users
Create new user in HEAD_ADMIN's college.

**Request Body:**
```json
{
  "displayName": "string",
  "email": "string",
  "password": "string", // optional
  "roles": ["STUDENT" | "FACULTY" | "DEPT_ADMIN"],
  "department": "string",
  "year": number, // optional
  "collegeMemberId": "string", // optional
  "status": "PENDING_VERIFICATION" | "ACTIVE" // optional, default: ACTIVE
}
```

**Response:** User object (201 Created)

#### POST /v1/head-admin/users/:userId/reset-password
Reset user password in HEAD_ADMIN's college.

**Request Body:**
```json
{
  "newPassword": "string",
  "forceChange": boolean // optional, default: true
}
```

**Response:**
```json
{
  "message": "string",
  "temporaryPassword": "string" // if forceChange is true
}
```

### College Management

#### GET /v1/head-admin/college
Get HEAD_ADMIN's college information.

**Response:**
```json
{
  "id": "string",
  "name": "string",
  "code": "string",
  "location": "string",
  "website": "string",
  "departments": ["string"],
  "isActive": boolean,
  "createdAt": "date",
  "updatedAt": "date"
}
```

### Statistics

#### GET /v1/head-admin/stats
Get college statistics for HEAD_ADMIN.

**Response:**
```json
{
  "totalUsers": number,
  "usersByRole": {
    "STUDENT": number,
    "FACULTY": number,
    "DEPT_ADMIN": number
  },
  "usersByStatus": {
    "ACTIVE": number,
    "PENDING_VERIFICATION": number,
    "SUSPENDED": number
  },
  "usersByDepartment": {
    "department_name": number
  },
  "recentRegistrations": number // last 30 days
}
```

## Security Features

### College Scoping
- All operations are automatically scoped to the HEAD_ADMIN's college
- HEAD_ADMINs cannot access or modify users from other colleges
- College ID is extracted from the authenticated user's JWT token

### Role Restrictions
- HEAD_ADMINs cannot create, update, or manage other HEAD_ADMINs or SUPER_ADMINs
- HEAD_ADMINs can only manage STUDENT, FACULTY, and DEPT_ADMIN roles
- Password resets are restricted to users within the same college

### Audit Trail
- All administrative actions should be logged for audit purposes
- User token versions are incremented on password resets to invalidate existing sessions

## Error Responses

### 401 Unauthorized
- Missing or invalid JWT token
- User not associated with a college

### 403 Forbidden
- User doesn't have HEAD_ADMIN role
- Attempting to manage users from different college
- Attempting to manage HEAD_ADMIN or SUPER_ADMIN users

### 404 Not Found
- User or college not found

### 409 Conflict
- Email already exists when creating users

## Usage Examples

### Create a new student
```bash
POST /v1/head-admin/users
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "displayName": "John Doe",
  "email": "john.doe@college.edu",
  "roles": ["STUDENT"],
  "department": "Computer Science",
  "year": 2,
  "collegeMemberId": "CS2024001"
}
```

### Get college statistics
```bash
GET /v1/head-admin/stats
Authorization: Bearer <jwt_token>
```

### Reset user password
```bash
POST /v1/head-admin/users/user123/reset-password
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "newPassword": "newSecurePassword123",
  "forceChange": true
}
```
