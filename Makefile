SHELL=/usr/bin/bash

.PHONY: test
test:
	which gotestsum || go install gotest.tools/gotestsum@latest
	gotestsum -- --mod=vendor -bench=^$$ -race ./...

.PHONY: typos
typos:
	which codespell || pip install codespell
	codespell -S vendor,funcs,.terraform,.git --ignore-words .codespellignore -f

.PHONY: fix-typos
fix-typos:
	which codespell || pip install codespell
	codespell -S vendor,funcs,.terraform --ignore-words .codespellignore -f -w -i1

.PHONY: quality
quality:
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.43.0
	golangci-lint run

.PHONY: update-loader
update-loader:
	python3 scripts/update_loader_rules.py
	@goimports -w loader/rules.go

