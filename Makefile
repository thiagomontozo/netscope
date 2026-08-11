.PHONY: dev-backend dev-frontend migrate-up
dev-backend:
	cd backend && go run ./cmd/server
dev-frontend:
	cd frontend && npm run dev
migrate-up:
	@echo "Apply backend/migrations with your approved PostgreSQL migration runner."
