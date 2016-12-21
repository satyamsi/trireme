PROJECT_NAME := remote_enforcer


build: remote_enforcer.go
	CGO_ENABLED=1 go build -o $(PROJECT_NAME) 

package:
	@mkdir -p $(GOPATH)/bin
	mv  $(PROJECT_NAME) $(GOPATH)/bin/$(PROJECT_NAME)
