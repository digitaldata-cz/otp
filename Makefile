all: gofmt govet gosec gocritic test

gosec:
	gosec ./...

govet:
	go vet ./...

gofmt:
	gofmt -s -w .

gocritic:
	gocritic check -enableAll -disable='#experimental' ./...

test:
	go test -v ./...