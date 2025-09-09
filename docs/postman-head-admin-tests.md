# Postman Collection for HEAD_ADMIN API Testing

This document provides a comprehensive Postman collection for testing all HEAD_ADMIN endpoints in the auth-service.

## Prerequisites

1. **Environment Variables Setup**
   - `base_url`: `http://localhost:3001` (or your auth service URL)
   - `jwt_token`: Valid JWT token with HEAD_ADMIN role
   - `college_id`: Your HEAD_ADMIN's college ID
   - `user_id`: A test user ID for operations

2. **Authentication**
   - All requests require `Authorization: Bearer {{jwt_token}}` header
   - Ensure your JWT token has HEAD_ADMIN role and valid college association

## Test Collection

### 1. Get College Users

**GET** `{{base_url}}/v1/head-admin/users`

**Headers:**
```
Authorization: Bearer {{jwt_token}}
Content-Type: application/json
```

**Query Parameters:**
```
limit: 10
offset: 0
search: john
role: STUDENT
department: Computer Science
status: ACTIVE
year: 2
```

**Expected Response (200):**
```json
{
  "users": [
    {
      "id": "user123",
      "displayName": "John Doe",
      "email": "john.doe@college.edu",
      "roles": ["STUDENT"],
      "department": "Computer Science",
      "year": 2,
      "collegeMemberId": "CS2024001",
      "status": "ACTIVE",
      "avatarUrl": null,
      "createdAt": "2024-01-01T00:00:00.000Z",
      "lastLoginAt": "2024-01-15T10:30:00.000Z"
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}
```

### 2. Create New User

**POST** `{{base_url}}/v1/head-admin/users`

**Headers:**
```
Authorization: Bearer {{jwt_token}}
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "displayName": "Jane Smith",
  "email": "jane.smith@college.edu",
  "password": "SecurePassword123!",
  "roles": ["STUDENT"],
  "department": "Computer Science",
  "year": 1,
  "collegeMemberId": "CS2024002",
  "status": "ACTIVE"
}
```

**Expected Response (201):**
```json
{
  "id": "user456",
  "displayName": "Jane Smith",
  "email": "jane.smith@college.edu",
  "roles": ["STUDENT"],
  "department": "Computer Science",
  "year": 1,
  "collegeMemberId": "CS2024002",
  "status": "ACTIVE",
  "avatarUrl": null,
  "createdAt": "2024-01-20T00:00:00.000Z",
  "lastLoginAt": null
}
```

### 3. Update User

**PUT** `{{base_url}}/v1/head-admin/users/{{user_id}}`

**Headers:**
```
Authorization: Bearer {{jwt_token}}
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "displayName": "Jane Smith Updated",
  "email": "jane.smith.updated@college.edu",
  "roles": ["FACULTY"],
  "department": "Computer Science",
  "year": null,
  "collegeMemberId": "FAC2024001",
  "status": "ACTIVE"
}
```

**Expected Response (200):**
```json
{
  "id": "user456",
  "displayName": "Jane Smith Updated",
  "email": "jane.smith.updated@college.edu",
  "roles": ["FACULTY"],
  "department": "Computer Science",
  "year": null,
  "collegeMemberId": "FAC2024001",
  "status": "ACTIVE",
  "avatarUrl": null,
  "createdAt": "2024-01-20T00:00:00.000Z",
  "lastLoginAt": null
}
```

### 4. Reset User Password

**POST** `{{base_url}}/v1/head-admin/users/{{user_id}}/reset-password`

**Headers:**
```
Authorization: Bearer {{jwt_token}}
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "newPassword": "NewSecurePassword123!",
  "forceChange": true
}
```

**Expected Response (200):**
```json
{
  "message": "Password reset successfully",
  "temporaryPassword": "NewSecurePassword123!"
}
```

### 5. Update User Status (Suspend/Activate)

**PATCH** `{{base_url}}/v1/head-admin/users/{{user_id}}/status`

**Headers:**
```
Authorization: Bearer {{jwt_token}}
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "status": "SUSPENDED",
  "reason": "Violation of college policies"
}
```

**Expected Response (200):**
```json
{
  "message": "User status updated successfully",
  "user": {
    "id": "user456",
    "status": "SUSPENDED",
    "updatedAt": "2024-01-21T00:00:00.000Z"
  }
}
```

### 6. Get College Information

**GET** `{{base_url}}/v1/head-admin/college`

**Headers:**
```
Authorization: Bearer {{jwt_token}}
Content-Type: application/json
```

**Expected Response (200):**
```json
{
  "id": "college123",
  "name": "Tech University",
  "code": "TECH",
  "location": "Silicon Valley, CA",
  "website": "https://techuniversity.edu",
  "departments": [
    "Computer Science",
    "Electrical Engineering",
    "Mechanical Engineering"
  ],
  "isActive": true,
  "createdAt": "2023-01-01T00:00:00.000Z",
  "updatedAt": "2024-01-01T00:00:00.000Z"
}
```

### 7. Update College Information

**PUT** `{{base_url}}/v1/head-admin/college`

**Headers:**
```
Authorization: Bearer {{jwt_token}}
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "name": "Tech University Updated",
  "location": "San Francisco, CA",
  "website": "https://techuniversity.edu",
  "departments": [
    "Computer Science",
    "Electrical Engineering",
    "Mechanical Engineering",
    "Data Science"
  ]
}
```

**Expected Response (200):**
```json
{
  "id": "college123",
  "name": "Tech University Updated",
  "code": "TECH",
  "location": "San Francisco, CA",
  "website": "https://techuniversity.edu",
  "departments": [
    "Computer Science",
    "Electrical Engineering",
    "Mechanical Engineering",
    "Data Science"
  ],
  "isActive": true,
  "createdAt": "2023-01-01T00:00:00.000Z",
  "updatedAt": "2024-01-21T00:00:00.000Z"
}
```

### 8. Get College Statistics

**GET** `{{base_url}}/v1/head-admin/stats`

**Headers:**
```
Authorization: Bearer {{jwt_token}}
Content-Type: application/json
```

**Expected Response (200):**
```json
{
  "totalUsers": 1250,
  "usersByRole": {
    "STUDENT": 1000,
    "FACULTY": 200,
    "DEPT_ADMIN": 50
  },
  "usersByStatus": {
    "ACTIVE": 1200,
    "PENDING_VERIFICATION": 30,
    "SUSPENDED": 20
  },
  "usersByDepartment": {
    "Computer Science": 400,
    "Electrical Engineering": 350,
    "Mechanical Engineering": 300,
    "Data Science": 200
  },
  "recentRegistrations": 45
}
```

### 9. Bulk Create Users

**POST** `{{base_url}}/v1/head-admin/users/bulk`

**Headers:**
```
Authorization: Bearer {{jwt_token}}
Content-Type: application/json
```

**Body (JSON):**
```json
{
  "users": [
    {
      "displayName": "Student One",
      "email": "student1@college.edu",
      "roles": ["STUDENT"],
      "department": "Computer Science",
      "year": 1,
      "collegeMemberId": "CS2024003"
    },
    {
      "displayName": "Student Two",
      "email": "student2@college.edu",
      "roles": ["STUDENT"],
      "department": "Computer Science",
      "year": 2,
      "collegeMemberId": "CS2024004"
    }
  ],
  "defaultPassword": "TempPassword123!",
  "sendWelcomeEmail": true
}
```

**Expected Response (200):**
```json
{
  "created": [
    {
      "id": "user789",
      "displayName": "Student One",
      "email": "student1@college.edu",
      "roles": ["STUDENT"],
      "department": "Computer Science",
      "year": 1,
      "collegeMemberId": "CS2024003",
      "status": "ACTIVE"
    }
  ],
  "failed": [
    {
      "email": "student2@college.edu",
      "error": "Email already exists"
    }
  ],
  "summary": {
    "total": 2,
    "successful": 1,
    "failed": 1
  }
}
```

## Error Response Examples

### 401 Unauthorized
```json
{
  "error": "UNAUTHORIZED",
  "message": "Missing or invalid authorization header"
}
```

### 403 Forbidden
```json
{
  "error": "FORBIDDEN",
  "message": "HEAD_ADMIN role required"
}
```

### 404 Not Found
```json
{
  "error": "NOT_FOUND",
  "message": "User not found"
}
```

### 409 Conflict
```json
{
  "error": "CONFLICT",
  "message": "User with this email already exists"
}
```

## Test Scenarios

### Positive Test Cases
1. **Authentication Flow**: Test with valid HEAD_ADMIN JWT token
2. **User Management**: Create, read, update users within college scope
3. **Password Management**: Reset passwords with different options
4. **College Management**: View and update college information
5. **Statistics**: Retrieve comprehensive college analytics
6. **Bulk Operations**: Create multiple users efficiently

### Negative Test Cases
1. **Invalid Authentication**: Test with missing/invalid JWT tokens
2. **Role Restrictions**: Test with non-HEAD_ADMIN tokens
3. **College Scoping**: Attempt to access users from different colleges
4. **Permission Boundaries**: Try to manage HEAD_ADMIN/SUPER_ADMIN users
5. **Data Validation**: Send invalid data formats and required fields
6. **Duplicate Prevention**: Attempt to create users with existing emails

### Edge Cases
1. **Large Datasets**: Test pagination with large user lists
2. **Special Characters**: Test with names/emails containing special characters
3. **Concurrent Operations**: Test simultaneous user creation/updates
4. **Rate Limiting**: Test API rate limits if implemented

## Postman Collection Import

To import this collection into Postman:

1. Create a new collection named "HEAD_ADMIN API Tests"
2. Set up environment variables as mentioned in prerequisites
3. Create requests for each endpoint above
4. Add tests for response validation:

```javascript
// Example test script for user creation
pm.test("Status code is 201", function () {
    pm.response.to.have.status(201);
});

pm.test("Response has user data", function () {
    var jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property('id');
    pm.expect(jsonData).to.have.property('email');
    pm.expect(jsonData.roles).to.include('STUDENT');
});

pm.test("User belongs to correct college", function () {
    var jsonData = pm.response.json();
    pm.expect(jsonData.collegeId).to.eql(pm.environment.get("college_id"));
});
```

## Running Tests

1. **Sequential Testing**: Run requests in order for dependent operations
2. **Data Cleanup**: Reset test data between test runs
3. **Environment Switching**: Test against different environments (dev, staging)
4. **Automated Testing**: Set up Newman for CI/CD pipeline integration

This comprehensive test suite ensures all HEAD_ADMIN functionality works correctly with proper security and scoping.
