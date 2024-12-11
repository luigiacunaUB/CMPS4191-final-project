include .envrc
#run main application
.PHONY: run/api
run/api:
	@echo 'Running Appliation'
	@go run ./cmd/api/ \
	-port=4000 \
	-env=development \
	-limiter-burst=5 \
	-limiter-rps=2 \
	-limiter-enabled=false \
	-db-dsn=$(BOOKSTORE_DB_DSN) \
	-cors-trusted-origins="http://localhost:8999 http://localhost:9001 http://192.168.0.114:9000"


#enter database
.PHONY: db/sql
db/psql:
	psql $(BOOKSTORE_DB_DSN)

#create migrations
.PHONY: db/migrations/new
db/migrations/new:
	@echo 'Creating Database Migrations for $(name)'
	migrate create -seq -ext=.sql -dir=./migrations $(name)

#up migrations
.PHONY: db/migrations/up
db/migrations/up:
	@echo 'running up migrations'
	migrate -path ./migrations -database $(BOOKSTORE_DB_DSN) up

#down migrations
.PHONY: db/migrations/down
db/migrations/down:
	@echo 'running down migrations'
	migrate -path ./migrations -database $(BOOKSTORE_DB_DSN) down


