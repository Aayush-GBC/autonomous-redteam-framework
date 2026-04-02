.PHONY: install install-dev test lint fmt typecheck clean run scan

# ── Install ────────────────────────────────────────────────────────────────────
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

# ── Quality ────────────────────────────────────────────────────────────────────
test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --cov=artasf --cov-report=term-missing

lint:
	ruff check src/ tests/

fmt:
	ruff format src/ tests/

typecheck:
	mypy src/artasf

# ── Run ────────────────────────────────────────────────────────────────────────
run:
	python -m artasf.ui.cli run

scan:
	python -m artasf.ui.cli scan

# ── Cleanup ────────────────────────────────────────────────────────────────────
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache dist build *.egg-info
