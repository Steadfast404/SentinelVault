# Database Configuration

- App user `sv_app` has restricted DML only permissions
- Migrations use `sv_migrator` which owns the schema
- Migrations run via Alembic
