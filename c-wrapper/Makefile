all:
	go build -o stage1.a -buildmode=c-shared stage1.go
	gcc -c libICP.c -o libICP.a