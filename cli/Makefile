ANSI_RED="\033[0;31m"
ANSI_GREEN="\033[0;32m"
ANSI_BLUE="\033[0;34m"
ANSI_RESET="\033[0m"

ifneq ("$(wildcard /usr/local/opt/coreutils/libexec/gnubin/echo)","")
	ECHO="/usr/local/opt/coreutils/libexec/gnubin/echo"
else
	ECHO="/bin/echo"
endif

.PHONY: all test test-html docs

all: openicpbr-cli
docs:
	xdg-open "http://localhost:6060/pkg/github.com/gjvnq/libICP/cli"
docs-server:
	godoc -http=:6060
test: coverage.out
test-html: coverage.out
	@$(ECHO) -e $(ANSI_GREEN)"Generating coverage report..."$(ANSI_RESET)
	go tool cover -html=coverage.out
	@$(ECHO) -e $(ANSI_BLUE)"Finished target $@"$(ANSI_RESET)


openicpbr-cli: *.go
	@$(ECHO) -e $(ANSI_GREEN)"Fixing imports..."$(ANSI_RESET)
	goimports -w .
	@$(ECHO) -e $(ANSI_GREEN)"Formatting code..."$(ANSI_RESET)
	go fmt
	@$(ECHO) -e $(ANSI_GREEN)"Compiling code..."$(ANSI_RESET)
	go build -o openicpbr-cli
	@$(ECHO) -e $(ANSI_BLUE)"Finished target $@"$(ANSI_RESET)

coverage.out: *.go
	@$(ECHO) -e $(ANSI_GREEN)"Fixing imports..."$(ANSI_RESET)
	goimports -w .
	@$(ECHO) -e $(ANSI_GREEN)"Formatting code..."$(ANSI_RESET)
	go fmt
	@$(ECHO) -e $(ANSI_GREEN)"Testing code..."$(ANSI_RESET)
	go test -cover -coverprofile=coverage.out
	@$(ECHO) -e $(ANSI_BLUE)"Finished target $@"$(ANSI_RESET)