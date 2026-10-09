-- Create migrator role (DDL, schema owner)
CREATE ROLE sv_migrator WITH LOGIN PASSWORD 'migpassword';
GRANT ALL PRIVILEGES ON DATABASE sentinelvault TO sv_migrator;
GRANT ALL ON SCHEMA public TO sv_migrator;

-- Create app role (DML only)
CREATE ROLE sv_app WITH LOGIN PASSWORD 'apppassword';
GRANT CONNECT ON DATABASE sentinelvault TO sv_app;
GRANT USAGE ON SCHEMA public TO sv_app;

-- Ensure sv_app can access newly created tables/sequences by sv_migrator
ALTER DEFAULT PRIVILEGES FOR ROLE sv_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sv_app;

ALTER DEFAULT PRIVILEGES FOR ROLE sv_migrator IN SCHEMA public
    GRANT SELECT, UPDATE ON SEQUENCES TO sv_app;
