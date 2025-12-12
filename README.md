# Auth Service - Spring Boot Microservice

A comprehensive Spring Boot microservice for user authentication and authorization with JWT tokens, role-based access control, and API logging.

## Features

1. **User Registration & Login**
    - Secure password encryption using BCrypt
    - JWT token generation
    - Email and username validation

2. **JWT Authentication Filter**
    - Validates access tokens on each request
    - Extracts user information from token
    - Sets Spring Security context

3. **Security Configuration**
    - Public endpoints configured via `application.yml`
    - `/api/auth/login` and `/api/auth/register` are public by default
    - All other endpoints require authentication

4. **Role-Based Access Control**
    - Support for multiple roles per user
    - `ROLE_USER` and `ROLE_ADMIN` predefined
    - Method-level security with `@PreAuthorize`

5. **API Logging with AOP**
    - Automatic logging of all REST API calls
    - Captures request/response body, status code, execution time
    - Stores logs in database with user information
    - Masks sensitive data (passwords, tokens)

## Project Structure

```
src/main/java/com/example/authservice/
├── aspect/
│   └── ApiLoggingAspect.java
├── config/
│   ├── DataInitializer.java
│   └── SecurityConfig.java
├── controller/
│   └── AuthController.java
├── dto/
│   ├── ApiResponse.java
│   ├── AuthResponse.java
│   ├── LoginRequest.java
│   └── RegisterRequest.java
├── entity/
│   ├── ApiLog.java
│   ├── Role.java
│   └── User.java
├── exception/
│   └── GlobalExceptionHandler.java
├── filter/
│   └── JwtAuthenticationFilter.java
├── repository/
│   ├── ApiLogRepository.java
│   ├── RoleRepository.java
│   └── UserRepository.java
├── service/
│   ├── AuthService.java
│   └── CustomUserDetailsService.java
├── util/
│   └── JwtUtil.java
└── AuthServiceApplication.java
```

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven 3.6+
- MySQL (optional, H2 is configured by default)

### Installation

1. Clone the repository
2. Navigate to project directory
3. Build the project:
   ```bash
   mvn clean install
   ```

4. Run the application:
   ```bash
   mvn spring-boot:run
   ```

The service will start on `http://localhost:8080`

## Configuration

### Application Properties (`application.yml`)

```yaml
jwt:
  secret: your-secret-key
  expiration: 86400000  # 24 hours

security:
  public-endpoints:
    - /api/auth/login
    - /api/auth/register
    - /h2-console/**
```

### Default Users

The application creates default users on startup:

| Username | Password | Roles |
|----------|----------|-------|
| admin | admin123 | ROLE_ADMIN, ROLE_USER |
| user | user123 | ROLE_USER |

## API Endpoints

### Public Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "password123",
  "firstName": "John",
  "lastName": "Doe",
  "roles": ["ROLE_USER"]
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "johndoe",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "type": "Bearer",
    "username": "johndoe",
    "email": "john@example.com",
    "roles": ["ROLE_USER"]
  }
}
```

### Protected Endpoints

All protected endpoints require `Authorization` header:
```
Authorization: Bearer <your-jwt-token>
```

#### Get Profile
```http
GET /api/auth/profile
Authorization: Bearer <token>
```

#### User Endpoint (USER or ADMIN role)
```http
GET /api/auth/user
Authorization: Bearer <token>
```

#### Admin Endpoint (ADMIN role only)
```http
GET /api/auth/admin
Authorization: Bearer <token>
```

## Security Features

### JWT Token Filter
- Validates JWT tokens in `Authorization` header
- Extracts user details and authorities
- Sets Spring Security context for authenticated requests

### Password Encryption
- Uses BCrypt with strength 10
- Passwords are never stored in plain text

### Role-Based Authorization
```java
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<?> adminEndpoint() {
    // Only users with ROLE_ADMIN can access
}

@PreAuthorize("hasAnyRole('USER', 'ADMIN')")
public ResponseEntity<?> userEndpoint() {
    // Users with either role can access
}
```

## API Logging

The `ApiLoggingAspect` automatically logs all REST controller methods:

**Logged Information:**
- Endpoint URL
- HTTP method
- Request body (with password masking)
- Response body (with token masking)
- HTTP status code
- Execution time
- Username (if authenticated)
- IP address

**Example Log Entry:**
```
API Call: POST /api/auth/login - Status: 200 - Time: 145ms - User: anonymousUser
```

Logs are stored in the `api_logs` table for audit purposes.

## Database Schema

### Users Table
- id, username, email, password
- first_name, last_name, is_active
- created_at, updated_at

### Roles Table
- id, name, description

### User_Roles Table (Join Table)
- user_id, role_id

### API_Logs Table
- id, endpoint, http_method
- request_body, response_body
- status_code, username, ip_address
- execution_time_ms, timestamp, error_message

## Testing with cURL

### Register a new user
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "firstName": "Test",
    "lastName": "User"
  }'
```

### Login
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### Access protected endpoint
```bash
curl -X GET http://localhost:8080/api/auth/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## H2 Console

Access the H2 database console at: `http://localhost:8080/h2-console`

- JDBC URL: `jdbc:h2:mem:authdb`
- Username: `sa`
- Password: (leave empty)

## Customization

### Adding New Roles
```java
Role customRole = new Role("ROLE_CUSTOM");
roleRepository.save(customRole);
```

### Adding Public Endpoints
Update `application.yml`:
```yaml
security:
  public-endpoints:
    - /api/auth/login
    - /api/auth/register
    - /api/public/**
```

### Changing JWT Expiration
Update `application.yml`:
```yaml
jwt:
  expiration: 3600000  # 1 hour
```

## Technologies Used

- Spring Boot 3.2.0
- Spring Security 6
- Spring Data JPA
- JWT (JJWT 0.12.3)
- H2 Database
- Lombok
- Maven
- AspectJ (AOP)

## License

This project is open source and available under the MIT License.
