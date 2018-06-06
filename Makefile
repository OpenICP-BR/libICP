all: libicp.a
test: coverage.out
test-html: coverage.out
	go tool cover -html=coverage.out


libicp.a: *.go
	go fmt
	go build -o libicp.a

coverage.out: *.go
	go test -cover -coverprofile=coverage.out	