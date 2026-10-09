#!/bin/bash
set -e

generate_secret() {
    openssl rand -hex 32
}

echo "Generating random secrets for SV_* variables in .env.example..."

echo "SV_SECRET_KEY=$(generate_secret)"
echo "SV_JWT_SECRET=$(generate_secret)"
echo "SV_ENCRYPTION_KEY=$(generate_secret)"
