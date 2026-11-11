BIN := vault-plugin-secrets-featbit

.PHONY: build test clean
build:
	CGO_ENABLED=0 go build -o $(BIN) ./cmd/$(BIN)
test:
	go test ./...
clean:
	rm -f $(BIN)
