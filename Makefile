.PHONY: help format lint test api frontend clean install analyze docker-build docker-up docker-down docker-logs migrate start validate-postgres clear-scans lint-migrations supabase-diff supabase-push supabase-start supabase-stop supabase-reset supabase-migration-up

# Default target - show help
help:
	@echo "ExtensionShield - Available Make Commands"
	@echo "======================================="
	@echo ""
	@echo "Docker (Recommended):"
	@echo "  make docker-build    - Build Docker container"
	@echo "  make docker-up       - Start container (foreground)"
	@echo "  make docker-down     - Stop container"
	@echo "  make docker-logs     - View container logs"
	@echo ""
	@echo "Code Quality:"
	@echo "  make format          - Format Python code with Black"
	@echo "  make lint            - Run Pylint on source code"
	@echo "  make lint-migrations - Lint Supabase migration files"
	@echo "  make test            - Run pytest test suite"
	@echo "  make precommit       - Run pre-commit hooks on all files"
	@echo ""
	@echo "Run Applications (Local Development):"
	@echo "  make api             - Start FastAPI server (port 8007); use with make frontend for UI"
	@echo "  make frontend        - Start React frontend dev server (port 5173) - use this to see latest UI changes"
	@echo "  make build-and-serve - Build frontend into static/ then start API (app on http://localhost:8007)"
	@echo "  make migrate         - Run Supabase migrations (safe, prod only)"
	@echo "  make start           - Run migrations (if Supabase) then start API"
	@echo "  make validate-postgres - Validate local dev pulls from Supabase Postgres"
	@echo "  make clear-scans       - Delete all scan results from DB (Supabase: set DB_BACKEND=supabase)"
	@echo "  make analyze URL=... - Analyze extension from Chrome Web Store URL"
	@echo "  make analyze-file FILE=... - Analyze local CRX/ZIP file"
	@echo ""
	@echo "Development:"
	@echo "  make install         - Install dependencies with uv"
	@echo "  make clean           - Remove output files and caches"
	@echo ""
	@echo "Supabase (Declarative Schemas):"
	@echo "  make supabase-diff NAME=... - Generate migration from schema changes"
	@echo "  make supabase-push          - Push schema changes to remote"
	@echo "  make supabase-start        - Start local Supabase instance"
	@echo "  make supabase-stop         - Stop local Supabase instance"
	@echo "  make supabase-reset        - Reset local database"
	@echo "  make supabase-migration-up - Apply pending migrations locally"
	@echo ""
	@echo "Deployment (Railway):"
	@echo "  make deploy-check    - Check Railway environment variables"
	@echo "  make deploy          - Deploy to Railway"
	@echo "  make deploy-link     - Link to Railway project (first time)"
	@echo "  make deploy-logs     - View Railway production logs"
	@echo "  make deploy-status   - Check Railway deployment status"
	@echo ""

# Format code with Black
format:
	@echo "Formatting Python code with Black..."
	uv run black .
	@echo "✓ Formatting complete"

# Lint code with Pylint
lint:
	@echo "Running Pylint on source code..."
	uv run pylint src/
	@echo "✓ Linting complete"

# Lint Supabase migrations
lint-migrations:
	@echo "Linting Supabase migrations..."
	python scripts/lint_migrations.py
	@echo "✓ Migration lint complete"

# Run tests
test:
	@echo "Running pytest..."
	uv run pytest
	@echo "✓ Tests complete"

# Run pre-commit hooks
precommit:
	@echo "Running pre-commit hooks..."
	pre-commit run --all-files
	@echo "✓ Pre-commit checks complete"

# Start FastAPI server
api:
	@echo "Starting FastAPI server with auto-reload..."
	@echo "Access at: http://localhost:8007"
	@echo "API docs at: http://localhost:8007/docs"
	uv run extension-shield serve --reload

# Validate local dev is pulling from Supabase Postgres (requires DB_BACKEND=supabase + Supabase env)
validate-postgres:
	@echo "Validating Supabase Postgres connection and scan_results..."
	uv run python scripts/validate_postgres_local.py

# Delete all scan results from DB. For Supabase: make clear-scans DB_BACKEND=supabase (requires .env)
clear-scans:
	@echo "Clearing all scan results from database..."
	DB_BACKEND=$${DB_BACKEND:-supabase} PYTHONPATH=src uv run python scripts/clear_all_scans.py
	@echo "Done."

# Run Supabase migrations (prod only, safe to run multiple times)
migrate:
	@if [ -n "$(DB_BACKEND)" ] && [ "$(DB_BACKEND)" != "supabase" ]; then \
		echo "Skipping Supabase migrations: DB_BACKEND=$(DB_BACKEND)"; \
	elif [ -n "$$SUPABASE_URL" ] && [ -n "$$SUPABASE_SERVICE_ROLE_KEY" ]; then \
		echo "Running Supabase migrations..."; \
		python scripts/run_supabase_migrations.py; \
	else \
		echo "Skipping Supabase migrations: Supabase env not set"; \
	fi

# Start API server (production style)
start: migrate
	@echo "Starting FastAPI server..."
	@echo "Access at: http://localhost:8007"
	@echo "API docs at: http://localhost:8007/docs"
	uvicorn extension_shield.api.main:app --host 0.0.0.0 --port $${PORT:-8007}

# Start React frontend
frontend:
	@echo "Starting React frontend development server..."
	@echo "Access at: http://localhost:5173"
	cd frontend && npm run dev

# Build frontend and copy to static/ so API can serve it on port 8007 (production-like local)
build-and-serve: static
	@echo "Starting API with built frontend at http://localhost:8007"
	@echo "API docs at: http://localhost:8007/docs"
	uv run extension-shield serve --reload

# Build frontend into project root static/ (so API serves it when you run make api)
static:
	@echo "Building frontend..."
	cd frontend && npm run build
	@echo "Copying frontend/dist to static/..."
	@rm -rf static
	@cp -r frontend/dist static
	@echo "Done. Run 'make api' to serve at http://localhost:8007"

# Analyze extension via CLI from URL
analyze:
ifndef URL
	@echo "Error: URL parameter is required"
	@echo "Usage: make analyze URL=https://chromewebstore.google.com/detail/example/abcdef"
	@echo "       make analyze URL=https://... OUTPUT=results.json"
	@exit 1
endif
	@echo "Analyzing Chrome extension from URL..."
ifdef OUTPUT
	uv run extension-shield analyze --url $(URL) --output $(OUTPUT)
else
	uv run extension-shield analyze --url $(URL)
endif

# Analyze local CRX/ZIP file via CLI
analyze-file:
ifndef FILE
	@echo "Error: FILE parameter is required"
	@echo "Usage: make analyze-file FILE=/path/to/extension.crx"
	@echo "       make analyze-file FILE=/path/to/extension.zip OUTPUT=results.json"
	@exit 1
endif
	@echo "Analyzing local extension file..."
ifdef OUTPUT
	uv run extension-shield analyze --file $(FILE) --output $(OUTPUT)
else
	uv run extension-shield analyze --file $(FILE)
endif

# Install dependencies
install:
	@echo "Installing Python dependencies with uv..."
	uv sync

# Clean output and cache files
clean:
	@echo "Cleaning caches..."
	rm -rf .pytest_cache/
	rm -rf .ruff_cache/
	rm -rf **/__pycache__/
	rm -rf **/*.pyc
	@echo "✓ Cleanup complete"

# =============================================================================
# Docker Commands
# =============================================================================

# Build Docker container
docker-build:
	@echo "Building ExtensionShield Docker container..."
	docker compose build
	@echo "✓ Docker build complete"

# Start container in foreground
docker-up:
	@echo "Starting ExtensionShield container..."
	@echo "Access at: http://localhost:8007"
	docker compose up

# Start container in background
docker-up-d:
	@echo "Starting ExtensionShield container in background..."
	docker compose up -d
	@echo "✓ Container started. Access at: http://localhost:8007"

# Stop container
docker-down:
	@echo "Stopping ExtensionShield container..."
	docker compose down
	@echo "✓ Container stopped"

# View container logs
docker-logs:
	docker compose logs -f

# =============================================================================
# Deployment Commands
# =============================================================================

# Check Railway environment variables
deploy-check:
	@echo "Checking Railway environment variables..."
	@./scripts/check_railway_env.sh

# Deploy to Railway (requires Railway CLI and RAILWAY_TOKEN)
deploy:
	@echo "Deploying to Railway..."
	@command -v railway >/dev/null 2>&1 || { echo "Installing Railway CLI..."; npm install -g @railway/cli; }
	railway up
	@echo "✓ Deployment complete"

# Link to existing Railway project
deploy-link:
	@echo "Linking to Railway project..."
	railway login
	railway link
	@echo "✓ Project linked"

# View production logs
deploy-logs:
	railway logs -f

# Check production status
deploy-status:
	railway status

# =============================================================================
# Supabase Declarative Schema Commands
# =============================================================================

# Generate migration from declarative schema changes
supabase-diff:
ifndef NAME
	@echo "Error: NAME parameter is required"
	@echo "Usage: make supabase-diff NAME=add_new_column"
	@exit 1
endif
	@echo "Generating migration from schema changes..."
	npx supabase db diff -f $(NAME)
	@echo "✓ Migration generated. Review supabase/migrations/"

# Push schema changes to remote Supabase project
supabase-push:
	@echo "Pushing schema changes to remote Supabase..."
	npx supabase db push
	@echo "✓ Schema changes pushed"

# Start local Supabase instance
supabase-start:
	@echo "Starting local Supabase instance..."
	npx supabase start
	@echo "✓ Supabase started"

# Stop local Supabase instance
supabase-stop:
	@echo "Stopping local Supabase instance..."
	npx supabase stop
	@echo "✓ Supabase stopped"

# Reset local database
supabase-reset:
	@echo "Resetting local database..."
	npx supabase db reset
	@echo "✓ Database reset"

# Apply pending migrations locally
supabase-migration-up:
	@echo "Applying pending migrations..."
	npx supabase migration up
	@echo "✓ Migrations applied"
