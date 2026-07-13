# ════════════════════════════════════════════════════════════════════════════
#  My Network Guard — Developer Makefile
#  Usage: make <target>
# ════════════════════════════════════════════════════════════════════════════

.PHONY: install install-dev run run-sim run-docker test test-unit test-int \
        test-security lint format security-scan docker-build docker-up \
        docker-down clean coverage help

# ─── Setup ───────────────────────────────────────────────────────────────────

install:
	@echo "📦 Installing production dependencies..."
	pip install -r requirements.txt

install-dev: install
	@echo "🔧 Installing development dependencies..."
	pip install -r requirements-dev.txt

# ─── Run ─────────────────────────────────────────────────────────────────────

run:
	@echo "🚀 Starting My Network Guard (live capture mode)..."
	python main.py --confirm-owner

run-sim:
	@echo "🧪 Starting in simulation mode..."
	python main.py --simulation --confirm-owner

run-docker:
	@echo "🐳 Starting with Docker Compose..."
	docker-compose -f docker/docker-compose.yml up

# ─── Tests ───────────────────────────────────────────────────────────────────

test:
	@echo "🧪 Running full test suite..."
	pytest tests/ -v --tb=short

test-unit:
	@echo "🔬 Running unit tests..."
	pytest tests/unit/ -v --tb=short

test-int:
	@echo "🔗 Running integration tests..."
	pytest tests/integration/ tests/test_heuristics.py -v --tb=short

test-security:
	@echo "🔐 Running OWASP security tests..."
	pytest tests/test_security.py tests/security/ -v --tb=short

coverage:
	@echo "📊 Running tests with coverage report..."
	pytest tests/ --cov=. --cov-report=html --cov-report=term-missing
	@echo "Coverage report saved to htmlcov/index.html"

# ─── Code Quality ─────────────────────────────────────────────────────────────

lint:
	@echo "🔍 Running flake8..."
	flake8 . --max-line-length=120 \
	          --exclude=.git,__pycache__,.venv,scanner_agent/oui_table.py \
	          --per-file-ignores="tests/*:E501"

format:
	@echo "✨ Formatting code with Black..."
	black --line-length=120 .
	@echo "Sorting imports with isort..."
	isort --profile=black .

format-check:
	@echo "🔍 Checking Black formatting..."
	black --check --line-length=120 .
	isort --check-only --profile=black .

# ─── Security ────────────────────────────────────────────────────────────────

security-scan:
	@echo "🛡️  Running SAST with Bandit..."
	bandit -r . -ll --exclude .git,.venv,tests,docker
	@echo "📋 Checking dependencies with Safety..."
	safety check -r requirements.txt

# ─── Docker ──────────────────────────────────────────────────────────────────

docker-build:
	@echo "🐳 Building Docker image..."
	docker build -f docker/Dockerfile -t my-network-guard:latest .

docker-up:
	@echo "🚀 Starting Docker Compose stack..."
	docker-compose -f docker/docker-compose.yml up -d

docker-down:
	@echo "🛑 Stopping Docker Compose stack..."
	docker-compose -f docker/docker-compose.yml down

docker-logs:
	docker-compose -f docker/docker-compose.yml logs -f

# ─── Utility ─────────────────────────────────────────────────────────────────

clean:
	@echo "🧹 Cleaning up..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -name ".coverage" -delete 2>/dev/null || true
	@echo "Done."

help:
	@echo ""
	@echo "  My Network Guard — Developer Commands"
	@echo "  ════════════════════════════════════"
	@echo "  make install      Install production dependencies"
	@echo "  make install-dev  Install dev + test dependencies"
	@echo "  make run          Run with live capture (requires privileges)"
	@echo "  make run-sim      Run in simulation mode (no privileges needed)"
	@echo "  make test         Run full test suite"
	@echo "  make test-unit    Run unit tests only"
	@echo "  make test-int     Run integration tests"
	@echo "  make test-security Run OWASP security tests"
	@echo "  make coverage     Generate HTML coverage report"
	@echo "  make lint         Run flake8 linter"
	@echo "  make format       Format code with Black + isort"
	@echo "  make security-scan Run Bandit SAST + Safety dependency scan"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-up    Start with Docker Compose"
	@echo "  make docker-down  Stop Docker Compose stack"
	@echo "  make clean        Remove build artifacts"
	@echo ""
