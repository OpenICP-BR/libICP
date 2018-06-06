all: libicp

libicp: *.go
	go fmt
	go build -o libicp