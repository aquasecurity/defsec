.PHONY: test
test:
	which gotestsum || go install gotest.tools/gotestsum@latest
	go test -race ./...

.PHONY: rego
rego:
	opa fmt -w internal/rules
	opa test internal/rules --explain fails

.PHONY: typos
typos:
	which codespell || pip3 install codespell
	codespell -S funcs,.terraform,.git --ignore-words .codespellignore -f

.PHONY: fix-typos
fix-typos:
	which codespell || pip3 install codespell
	codespell -S funcs,.terraform --ignore-words .codespellignore -f -w -i1

.PHONY: quality
quality:
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.43.0
	golangci-lint run --timeout 3m --verbose

.PHONY: update-loader
update-loader:
	python3 scripts/update_loader_rules.py
	@goimports -w pkg/rules/rules.go

.PHONY: metadata_lint
metadata_lint:
	go run ./cmd/lint

.PHONY: generate_missing_docs
generate_missing_docs:
	go run ./cmd/avd_generator

.PHONY: id
id:
	@go run ./cmd/id
