all: libicp.a

libicp.a: *.go
	go fmt
	go build -o libicp.a