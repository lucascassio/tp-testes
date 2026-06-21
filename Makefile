.PHONY: test test-unit test-integration test-e2e coverage run clean

test:
	python -m pytest tests/ -v

test-unit:
	python -m pytest tests/ -m unit -v

test-integration:
	python -m pytest tests/ -m integration -v

test-e2e:
	python -m pytest tests/ -m e2e -v

coverage:
	python -m pytest tests/ --cov=app --cov-report=term-missing

coverage-html:
	python -m pytest tests/ --cov=app --cov-report=html
	open htmlcov/index.html

run:
	uvicorn app.main:app --reload

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf .pytest_cache htmlcov .coverage coverage.xml junit.xml uploads/
