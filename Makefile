go-build:
	@go build -v -o go-groupchat-app *.go

go-run:
	@./go-groupchat-app

run:
	make go-build
	make go-run