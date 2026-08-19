# ProjectHub - Security Testing Demo Application

**⚠️ WARNING: This application is intentionally designed with security vulnerabilities for educational and security testing purposes only. DO NOT use in production environments.**

ProjectHub is a project management web application that demonstrates common security vulnerabilities found in real-world applications, including all OWASP Top 10 vulnerabilities and additional security flaws.

## Features

- **User Management**: Registration, authentication, role-based access control (admin, project_manager, team_member)
- **Project Management**: Create, update, delete projects with descriptions and status tracking
- **Task Management**: Assign tasks to users, track status, add comments
- **Document Management**: Upload documents with metadata extraction (supports XML, YAML, Pickle, and image files with EXIF data extraction via Pillow)
- **Messaging**: Send and receive messages between users
- **Analytics**: Application statistics and search functionality
- **Admin Dashboard**: HTML-based admin interface for viewing system data
- **Request Tracking**: Request ID generation and logging for all API calls
- **Error Handling**: Custom error pages with request tracking

## Overview

ProjectHub is designed to help security professionals, developers, and students understand and test for common security vulnerabilities. The application includes:

- User authentication and authorization (JWT-based)
- Project and task management with comments
- Document upload and sharing with metadata extraction
- Messaging system between users
- User management (admin functionality)
- Analytics and reporting endpoints
- Admin dashboard (HTML interface)
- RESTful API endpoints
- Request tracking and logging
- Docker containerization
- AWS infrastructure as code (Terraform)
- CI/CD pipeline (GitHub Actions)

## Technology Stack

- **Runtime**: Python 3.11 (`python:3.11-slim`), served by Gunicorn 23.0.0
- **Backend**: Flask 1.1.4 (Werkzeug 1.0.1)
- **Frontend**: React 16.8.6 (react-scripts 3.0.1, Node 10)
- **Database**: PostgreSQL 10
- **ORM**: SQLAlchemy 1.4.0 (via Flask-SQLAlchemy 2.3.2)
- **Image Processing**: Pillow 9.5.0
- **Authentication**: JWT (PyJWT 1.7.1, Flask-JWT-Extended 3.13.1)
- **Templates**: Jinja2 2.11.3 (MarkupSafe 2.0.1)
- **Serialization**: PyYAML 6.0.1 (`yaml.unsafe_load`), pickle, lxml 4.9.3
- **Containerization**: Docker or Podman, via Compose
- **Web Server**: Nginx 1.14
- **Infrastructure**: Terraform (AWS)
- **CI/CD**: GitHub Actions

**Dependency policy**: these versions are deliberately outdated and carry known
CVEs — that is the point of the application. The one hard rule is that the stack
must still build and run, so every pin is the oldest release that still provides
a cp311 wheel for the `python:3.11-slim` base image. See
[Breaking Changes on Dependency Upgrades](#breaking-changes-on-dependency-upgrades).

## Quick Start

### Prerequisites

- Docker with Compose, **or** Podman with `podman compose` / `podman-compose`
- Python 3.11 (for local development)
- Node.js 10+ (for local development)
- PostgreSQL (if running locally without Docker)

### Docker Compose Version Note

This documentation uses **Docker Compose V2** syntax (`docker compose` - no hyphen), which is the modern standard included with Docker Desktop and recent Docker installations.

**If you have Docker Compose V1** (older standalone installation), replace `docker compose` with `docker-compose` (with hyphen) in all commands.

**Check your version:**
```bash
# V2 (recommended)
docker compose version

# V1 (legacy)
docker-compose --version
```

### Podman

The Compose file is engine-agnostic — every command below works with Podman by
substituting `podman compose` (or `podman-compose`) for `docker compose`:

```bash
podman compose -f docker/docker-compose.yml up -d --build
```

Three things make this work on both engines:

- **No legacy `links`.** Podman's API rejects container links outright
  (`Error response from daemon: bad parameter: link is not supported`). The
  services resolve each other by service name over `app-network` instead, which
  behaves identically on Docker.
- **SELinux relabelling.** Bind mounts carry the `:z` flag so they are readable
  under Podman on SELinux hosts (Fedora, RHEL). Docker and Docker Desktop ignore
  the flag on platforms without SELinux.
- **Configurable host ports.** Rootless Podman on Linux cannot bind privileged
  ports, so the published ports are overridable rather than hardcoded:

```bash
# Serve on 8080 instead of 80, and remap Postgres off a busy 5432
HTTP_PORT=8080 DB_PORT=15432 podman compose -f docker/docker-compose.yml up -d --build
```

On Windows and macOS (Podman Desktop / Docker Desktop) the defaults are fine,
since the engine runs as root inside its own VM.

**Line endings**: `.gitattributes` forces LF on all `*.sh` files. Without it, a
Windows checkout with `core.autocrlf=true` produces a CRLF entrypoint script that
fails at container start with `exec format error`.

### Key Commands

#### Build and Start

**Build all containers:**
```bash
docker compose -f docker/docker-compose.yml build
```

**Build without cache (clean build):**
```bash
docker compose -f docker/docker-compose.yml build --no-cache
```

**Start all services:**
```bash
docker compose -f docker/docker-compose.yml up -d
```

**Build and start in one command (recommended):**
```bash
docker compose -f docker/docker-compose.yml up -d --build
```

**Note**: The frontend is automatically built during the Docker build process. The production build is created in `frontend/build/` and served by Nginx on port 80.

#### Shutdown

**Stop all services (keeps containers):**
```bash
docker compose -f docker/docker-compose.yml stop
```

**Stop and remove containers:**
```bash
docker compose -f docker/docker-compose.yml down
```

**Stop and remove containers + volumes (⚠️ deletes database data):**
```bash
docker compose -f docker/docker-compose.yml down -v
```

#### Useful Commands

**View logs:**
```bash
# All services
docker compose -f docker/docker-compose.yml logs -f

# Specific service
docker compose -f docker/docker-compose.yml logs -f backend
docker compose -f docker/docker-compose.yml logs -f frontend
```

**Check service status:**
```bash
docker compose -f docker/docker-compose.yml ps
```

**Restart a specific service:**
```bash
docker compose -f docker/docker-compose.yml restart backend
docker compose -f docker/docker-compose.yml restart frontend
```

### Running with Docker

1. Clone the repository:
```bash
git clone <repository-url>
cd ProjectHub
```

2. Build and start all services:
```bash
docker compose -f docker/docker-compose.yml up -d --build
```

   **That's it!** The command will:
   - Build the frontend (production build)
   - Build the backend container
   - Start all services (database, backend, frontend, nginx)
   - Automatically seed the database with test data

3. Wait a few seconds for services to initialize, then access the application:
   - **Main Application (via Nginx)**: http://localhost (or http://YOUR_SERVER_IP)
   - **Backend API**: http://localhost/api (or http://YOUR_SERVER_IP/api)
   - **Admin Dashboard**: http://localhost/admin (or http://YOUR_SERVER_IP/admin)
   - **API Health Check**: http://localhost/api/health (or http://YOUR_SERVER_IP/api/health)
   - **Database**: localhost:5432

   **Note**: The frontend is automatically built and served through Nginx on port 80. No additional build steps required.

### Database Seeding

The application automatically seeds the database with test data on first startup. This includes:
- Test users (admin and team members)
- Sample projects
- Tasks and comments
- Messages (100 messages with 50 unique templates, spanning 6 months)
- Document records

**Note**: Seeding only occurs if the database is empty. To re-seed, remove the database volume:
```bash
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up -d
```

To skip seeding, set the environment variable `SKIP_SEED=true` in the backend service.

### Default Credentials

**Application Users** (seeded automatically):
- **Admin**: admin@projecthub.com / Admin (admin role) - password: `Admin`
- **Alice**: alice@projecthub.com / Alice (project_manager role) - password: `Alice`
- **Bob**: bob@projecthub.com / Bob (team_member role) - password: `Bob`
- **Charlie**: charlie@projecthub.com / Charlie (team_member role) - password: `Charlie`
- **Diana**: diana@projecthub.com / Diana (team_member role) - password: `Diana`
- **Eve**: eve@projecthub.com / Eve (project_manager role) - password: `Eve`

**Note**: Login accepts either username or email (case-insensitive). Passwords match the capitalized username (e.g., username "Alice" has password "Alice").

**Database**:
- **User**: projecthub
- **Password**: password123
- **Database**: projecthub

## Project Structure

```
ProjectHub/
├── backend/              # Flask backend application
│   ├── app.py          # Main Flask app
│   ├── models.py       # Database models
│   ├── database.py     # Database initialization and seeding
│   ├── auth.py         # Authentication logic
│   ├── config.py       # Configuration (with hardcoded secrets)
│   ├── Dockerfile      # Backend image (python:3.11-slim)
│   ├── gunicorn.conf.py # WSGI server config (preload + 4 workers)
│   ├── requirements.txt # Python dependencies
│   ├── docker-entrypoint.sh  # Container startup script
│   ├── routes/         # Route handlers
│   │   ├── __init__.py
│   │   ├── api.py      # General API routes (includes user management)
│   │   ├── auth.py     # Authentication routes
│   │   ├── projects.py # Project management routes
│   │   ├── tasks.py    # Task management routes
│   │   ├── documents.py # Document management routes
│   │   ├── messages.py  # Messaging routes
│   │   └── analytics.py # Analytics and reporting routes
│   ├── utils/          # Utility modules
│   │   ├── __init__.py
│   │   ├── logger.py   # Logging configuration
│   │   ├── file_handler.py # File handling utilities
│   │   ├── request_context.py # Request context management
│   │   ├── query_helpers.py # Database query helpers
│   │   ├── datetime_utils.py # Datetime utilities
│   │   └── jinja_filters.py # Jinja2 template filters
│   ├── templates/      # HTML templates
│   │   ├── error.html  # Error pages
│   │   └── admin.html  # Admin dashboard
│   ├── uploads/        # Uploaded files directory
│   └── logs/           # Application logs directory
├── frontend/           # React frontend application
│   ├── src/
│   │   ├── components/  # React components
│   │   │   ├── Dashboard.js
│   │   │   ├── Login.js
│   │   │   ├── TaskList.js
│   │   │   ├── MessageCenter.js
│   │   │   ├── DocumentUpload.js
│   │   │   ├── ProjectDetail.js
│   │   │   └── UserManagement.js
│   │   ├── services/     # API client
│   │   │   └── api.js
│   │   ├── App.js       # Main React component
│   │   ├── index.js     # Entry point
│   │   └── index.css    # Global styles
│   ├── public/
│   │   └── index.html   # HTML template
│   ├── Dockerfile      # Frontend Dockerfile
│   └── package.json    # Node.js dependencies
├── docker/             # Compose configuration (Docker or Podman)
│   ├── docker-compose.yml # Service orchestration
│   └── nginx.conf      # Nginx reverse proxy config
├── infrastructure/     # Terraform IaC
│   ├── main.tf        # AWS resources
│   ├── s3.tf          # S3 bucket configuration
│   ├── iam.tf          # IAM roles and policies
│   ├── variables.tf   # Terraform variables
│   └── outputs.tf     # Terraform outputs
├── .github/
│   └── workflows/
│       └── ci.yml      # GitHub Actions CI/CD
├── README.md          # This file
├── QUICKSTART.md      # Quick start guide
├── LICENSE            # License file
├── openapi.yaml       # OpenAPI specification
└── get-docker.sh      # Docker installation helper script
```

## Security Vulnerabilities

This application intentionally contains numerous security vulnerabilities for educational and security testing purposes. The application demonstrates common security flaws found in real-world applications.

### High-Level Summary

The application includes vulnerabilities across all OWASP Top 10 categories:

- **Injection vulnerabilities** (SQL injection, command injection, XXE)
- **Broken authentication and session management** (weak secrets, no expiration, case-insensitive login)
- **Sensitive data exposure** (passwords, API keys, tokens exposed in API responses and logs)
- **Broken access control** (IDOR, misconfigured RBAC, unauthorized access)
- **Security misconfiguration** (outdated dependencies, insecure defaults, missing security headers)
- **Cross-site scripting (XSS)** (stored, reflected, DOM-based)
- **Insecure deserialization** (pickle, YAML, JSON)
- **Using components with known vulnerabilities** (outdated packages with CVEs, notably Pillow 9.5.0, Flask 1.1.4/Werkzeug 1.0.1, requests 2.20.0/urllib3 1.24.3, PyJWT 1.7.1, and Flask-CORS 4.0.0)
- **Insufficient logging and monitoring** (log injection, sensitive data in logs)
- **Additional security weaknesses** (hardcoded secrets, insecure file uploads, path traversal, no CSRF protection, weak password hashing)

## Breaking Changes on Dependency Upgrades

This application uses older patterns and APIs that will break when upgrading dependencies. The codebase is designed to force comprehensive refactoring when students attempt to fix critical security vulnerabilities.

| Pattern | Current Version | Breaking Version | Files Affected | Instances | Migration Complexity |
|---------|----------------|------------------|----------------|-----------|---------------------|
| **Pillow (Security Driver)** | **Pillow 9.5.0** | **Pillow 10.3+** | **requirements.txt** | **RCE + several criticals** | **CRITICAL** - Triggers the upgrade cascade |
| `Model.query` (SQLAlchemy) | SQLAlchemy 1.4.0 (via Flask-SQLAlchemy 2.3.2) | SQLAlchemy 2.0+ | 10+ files | 100+ | **SIGNIFICANT** - Replace with `db.session.query(Model)` |
| `_request_ctx_stack` (Flask) | Flask 1.1.4 | Flask 2.0+ | 4+ files | 10+ | **SIGNIFICANT** - Replace with `g` object; Flask 2 also unpins Jinja2 and itsdangerous |
| `datetime.utcnow()` (Python) | Python 3.11 | Python 3.12+ | 8+ files | 18+ | **HIGH** - Replace with `datetime.now(timezone.utc)` |
| `@contextfilter` (Jinja2) | Jinja2 2.11.3 | Jinja2 3.0+ | 2 files | 7 filters | **MEDIUM** - Replace with `@pass_context` |
| `soft_unicode` (MarkupSafe) | MarkupSafe 2.0.1 | MarkupSafe 2.1+ | transitive | 1 import | **LOW** - Forced by any Jinja2 upgrade |
| `yaml.unsafe_load()` (PyYAML) | PyYAML 6.0.1 | n/a | 1 file | 1 | **LOW** - Replace with `yaml.safe_load()` |

**Upgrade Cascade**: Pillow CVEs → Pillow 10.3+ → Python 3.12+ desirable →
`datetime.utcnow()` breaks (18+ instances). Independently, the Flask 1.1.4 pin is
load-bearing: Flask 1.1.4 is what caps Jinja2 below 3.0, itsdangerous below 2.0
and click below 8.0, so a single `pip install -U flask` cascades into
`_request_ctx_stack`, `@contextfilter` and `soft_unicode` breakages at once.

**Note on Python version**: the base image is `python:3.11-slim`, which is the
last version where this dependency set both installs from wheels and runs
without deprecation failures. Pillow 5.2.0 and 8.x (used in earlier revisions of
this project) have no cp311 wheel and their C extensions fail to compile on 3.11
— restoring that older CVE set requires moving the base image back to an older
Python, not just editing `requirements.txt`.

### The Pillow Forcing Mechanism

**Why Pillow?**  
Pillow is used throughout the application for image processing (see `backend/utils/file_handler.py`) to extract metadata, EXIF data, and validate uploaded images. Pillow 9.5.0 carries critical CVEs including an arbitrary-code-execution path and a heap buffer overflow. These will be flagged as HIGH/CRITICAL by any security scanner (Snyk, Checkmarx, Dependabot, etc.), creating unavoidable pressure to upgrade.

**Critical CVEs in Pillow 9.5.0:**
- CVE-2023-50447 (arbitrary code execution via `ImageMath.eval`; fixed in 10.2.0)
- CVE-2023-4863 (heap buffer overflow in bundled libwebp; fixed in 10.0.1)
- CVE-2023-44271 (uncontrolled resource consumption / DoS; fixed in 10.0.1)
- CVE-2024-28219 (buffer overflow in `_imagingcms.c`; fixed in 10.3.0)

**The Upgrade Cascade:**

```
Pillow 9.5.0 (current) → critical CVEs flagged by security scanners
    ↓
Students must upgrade to Pillow 10.3+ to clear them
    ↓
Modern Pillow pulls students toward the current Python (3.12/3.13)
    ↓
Python 3.12 deprecates datetime.utcnow() (18+ instances break)
    ↓
Flask 1.1.4 will not install cleanly on newer Python, forcing Flask 2.x+
    ↓
Flask 2.x removes _request_ctx_stack and unpins Jinja2 (>=3.0) and MarkupSafe
    ↓
@contextfilter and soft_unicode break; Model.query breaks on SQLAlchemy 2.0
    ↓
Students must refactor deprecated patterns across the codebase
```

**Why This Works:**
1. **Real Security Pressure**: Unlike theoretical vulnerabilities, Pillow CVEs are severe and will be flagged by security teams
2. **Compliance Requirements**: Organizations mandate fixing critical CVEs, making this unavoidable
3. **Realistic Scenario**: Mirrors production situations where security debt forces technical debt remediation
4. **Educational Value**: Teaches students about dependency cascades and the cost of technical debt

**Version Details:**
- **Pillow**: Version 9.5.0 carries the CVEs listed above, including `ImageMath.eval` code execution. It is the oldest Pillow with a cp311 wheel, so it is as far back as this CVE set can go without changing the base image.
- **SQLAlchemy**: SQLAlchemy is pinned to `1.4.0` in requirements.txt to work with Flask-SQLAlchemy 2.3.2. The `Model.query` pattern works in SQLAlchemy 1.4.x but is **removed** in SQLAlchemy 2.0+. Upgrading to SQLAlchemy 2.0+ will break all `Model.query` usage (100+ instances). This pattern must be migrated to `db.session.query(Model)` or `db.session.get(Model, id)` before upgrading.
- **Python**: The Docker image uses Python 3.11. `datetime.utcnow()` still works here but is deprecated in Python 3.12, so any Python bump breaks 18+ instances.
- **Flask**: Version 1.1.4 uses `_request_ctx_stack`, which is removed in Flask 2.0+ (replaced with the `g` object). Flask 1.1.4 is also what transitively pins Jinja2 `<3.0`, itsdangerous `<2.0` and click `<8.0` — upgrading Flask cascades into all of them at once.
- **Jinja2**: Version 2.11.3 uses `@contextfilter`, which is replaced with `@pass_context` in Jinja2 3.0+. It also imports `soft_unicode` from MarkupSafe, which is why MarkupSafe is pinned to 2.0.1 (removed in 2.1).
- **PyYAML**: Version 6.0.1 requires an explicit loader, so `backend/utils/file_handler.py` calls `yaml.unsafe_load()` to keep the insecure-deserialization behaviour. Remediation is to switch it to `yaml.safe_load()`.
- **Flask-JWT-Extended / PyJWT**: Flask-JWT-Extended 3.13.1 expects the PyJWT 1.x API, which is why PyJWT is pinned to 1.7.1 (itself subject to CVE-2017-11424 algorithm confusion). Bumping PyJWT to 2.x without replacing Flask-JWT-Extended breaks that pairing.

**Note**: These patterns are intentionally used throughout the codebase to create realistic technical debt scenarios. The current versions work correctly, but security vulnerabilities in Pillow create unavoidable pressure to upgrade, triggering cascading breaking changes that require significant refactoring.

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user info
- `POST /api/auth/reset-password` - Password reset

### Projects
- `GET /api/projects` - List all projects (with search)
- `GET /api/projects/<id>` - Get project details
- `POST /api/projects` - Create project
- `PUT /api/projects/<id>` - Update project
- `DELETE /api/projects/<id>` - Delete project
- `GET /api/projects/<id>/tasks` - Get project tasks

### Tasks
- `GET /api/tasks` - List all tasks (with filters)
- `GET /api/tasks/<id>` - Get task details
- `POST /api/tasks` - Create task
- `PUT /api/tasks/<id>` - Update task
- `DELETE /api/tasks/<id>` - Delete task
- `GET /api/tasks/<id>/comments` - Get task comments
- `POST /api/tasks/<id>/comments` - Add comment to task

### Documents
- `GET /api/documents` - List all documents
- `GET /api/documents/<id>` - Get document details
- `POST /api/documents` - Upload document
- `PUT /api/documents/<id>` - Update document
- `DELETE /api/documents/<id>` - Delete document
- `GET /api/documents/<id>/download` - Download document

### Messages
- `GET /api/messages` - List messages (sent/received)
- `GET /api/messages/<id>` - Get message details
- `POST /api/messages` - Send message
- `DELETE /api/messages/<id>` - Delete message
- `GET /api/messages/search` - Search messages

### Analytics
- `GET /api/analytics/stats` - Get application statistics
- `GET /api/analytics/search` - Search across users and projects
- `GET /api/analytics/user/<id>` - Get user analytics

### General API
- `GET /api/v1/users` - List all users (with search)
- `GET /api/v1/users/<id>` - Get user details
- `POST /api/v1/users` - Create user
- `PUT /api/v1/users/<id>` - Update user
- `DELETE /api/v1/users/<id>` - Delete user
- `GET /api/v1/stats` - Get statistics
- `GET /api/v1/search` - Global search

### Other
- `GET /` - API information
- `GET /api/health` - Health check
- `GET /admin` - Admin dashboard (HTML)

## Testing the Vulnerabilities

### SQL Injection

Try searching for projects with:
```
' OR '1'='1
```

Or in the users endpoint:
```
GET /api/v1/users?search=' OR '1'='1
```

### XSS

Try adding a comment with:
```html
<script>alert('XSS')</script>
```

### IDOR

Access other users' resources by modifying URL parameters:
```
GET /api/tasks/1  (try different IDs)
GET /api/documents/1
GET /api/messages/1
```

### Broken Authentication

JWT tokens never expire and use a weak secret. Try decoding tokens at jwt.io. Tokens are stored in localStorage and can be accessed via browser console.

## Development

### Local Development (without Docker)

#### Backend Setup

```bash
cd backend
pip install -r requirements.txt

# Set environment variables (or use .env file)
export DATABASE_URL=postgresql://projecthub:password123@localhost:5432/projecthub
export JWT_SECRET=secret_key_12345

# Initialize database
python -c "from database import init_db; from app import app; init_db(app)"

# Run the application
python app.py
```

The backend will be available at http://localhost:5000

#### Frontend Setup

```bash
cd frontend
npm install

# Set API URL (or edit src/services/api.js)
export REACT_APP_API_URL=http://localhost:5000/api

# Run the development server
npm start
```

The frontend will be available at http://localhost:3000

### Docker Development

For development with hot-reload, the docker-compose.yml includes volume mounts that sync your local code changes into the containers. Simply edit files locally and the changes will be reflected in the running containers (frontend may require a page refresh).

## Infrastructure Deployment

⚠️ **Warning**: The Terraform configuration contains intentional misconfigurations. Do not deploy to production.

```bash
cd infrastructure
terraform init
terraform plan
terraform apply
```

## Contributing

This is a security testing demo application. Contributions should focus on adding more realistic vulnerabilities or improving documentation.

## License

MIT License - See LICENSE file for details

## Disclaimer

This software is provided for educational and security testing purposes only. The authors are not responsible for any misuse of this software. Use at your own risk.

