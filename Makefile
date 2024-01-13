.PHONY: test
test:
	go test -race ./...

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
	which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.54.2
	golangci-lint run --timeout 3m --verbose

.PHONY: schema
schema:
	go run ./cmd/schema generate

.PHONY: update-allowed-actions
update-allowed-actions:
	go run ./cmd/allowed_actions

