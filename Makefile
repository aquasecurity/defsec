DYNAMIC_REGO_FOLDER=./internal/rules/kubernetes/policies/dynamic

.PHONY: test
test:
	go test -race ./...

.PHONY: test-no-localstack
test-no-localstack:
	go test $$(go list ./... | grep -v internal/adapters/cloud/aws | awk -F'github.com/aquasecurity/defsec/' '{print "./"$$2}')

.PHONY: rego
rego: fmt-rego test-rego

.PHONY: fmt-rego
fmt-rego:
	opa fmt -w internal/rules

.PHONY: test-rego
test-rego:
	go test --run Test_AllRegoRules ./test

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
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.47.2
	golangci-lint run --timeout 3m --verbose

.PHONY: update-loader
update-loader:
	python3 scripts/update_loader_rules.py
	@goimports -w pkg/rules/rules.go

.PHONY: metadata_lint
metadata_lint:
	go run ./cmd/lint

.PHONY: docs
docs:
	go run ./cmd/avd_generator

.PHONY: id
id:
	@go run ./cmd/id

.PHONY: update-aws-deps
update-aws-deps:
	@grep aws-sdk-go-v2 go.mod | grep -v '// indirect' | sed 's/^[\t\s]*//g' | sed 's/\s.*//g' | xargs go get
	@go mod tidy

.PHONY: adapter-lint
adapter-lint:
	go run ./cmd/adapter-lint/main.go ./internal/adapters/...
	go run ./cmd/adapter-lint/main.go ./pkg/providers/...

.PHONY: outdated-api-updated
outdated-api-updated:
	sed -i.bak "s|recommendedVersions :=.*|recommendedVersions := $(OUTDATE_API_DATA)|" $(DYNAMIC_REGO_FOLDER)/outdated_api.rego && rm $(DYNAMIC_REGO_FOLDER)/outdated_api.rego.bak
