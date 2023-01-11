export GLOG = warn
export BINLOG = warn
export HTTPLOG = warn
export GORACE = halt_on_error=1

test: test_hw0 test_hw1 test_hw2 test_hw3 test_tor

xtest: setbin test

setbin:
	GOOS=darwin GOARCH=amd64 go build -o ./peer/tests/integration/node.darwin.amd64 ./gui/; \
	GOOS=darwin GOARCH=arm64 go build -o ./peer/tests/integration/node.darwin.arm64 ./gui/; \
	GOOS=linux GOARCH=amd64 go build -o ./peer/tests/integration/node.linux.amd64 ./gui/;

test_hw0: test_unit_hw0 test_int_hw0
test_hw1: test_unit_hw1 test_int_hw1
test_hw2: test_unit_hw2 test_int_hw2
test_hw3: test_unit_hw3 test_int_hw3
test_tor : test_unit_dh test_unit_encryption test_unit_tls test_unit_trust test_unit_circuit test_unit_messaging


test_unit_dh:
	go test -v -race -run Test_DH ./peer/tests/unit

test_unit_encryption:
	go test -v -race -run Test_Encryption ./peer/tests/unit

test_unit_tls:
	go test -v -race -run Test_TLS ./peer/tests/unit

test_unit_trust:
	go test -v -race -run Test_Trust ./peer/tests/unit

test_unit_circuit:
	go test -v -race -run Test_Tor_Circuit ./peer/tests/unit

test_unit_messaging:
	go test -v -race -run Test_Tor_Messaging ./peer/tests/unit
	
test_unit_hw0:
	go test -v -race -run Test_HW0 ./peer/tests/unit

test_unit_hw1:
	go test -v -race -run Test_HW1 ./peer/tests/unit

test_unit_hw2:
	go test -v -race -run Test_HW2 ./peer/tests/unit

test_unit_hw3:
	go test -v -race -run Test_HW3 ./peer/tests/unit

test_int_hw0:
	go test -timeout 40m -v -race -run Test_HW0 ./peer/tests/integration

test_int_hw1:
	go test -timeout 40m -v -race -run Test_HW1 ./peer/tests/integration

test_int_hw2:
	go test -timeout 5m -v -race -run Test_HW2 ./peer/tests/integration

test_int_hw3:
	go test -timeout 5m -v -race -run Test_HW3 ./peer/tests/integration

lint:
	# Coding style static check.
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.49.0
	@go mod tidy
	golangci-lint run

vet:
	go vet ./...
