remote_enforcer:
	make -C ./cmd/
build:  remote_enforcer
	CGO_ENABLED=1 go build 
