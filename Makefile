#!/usr/bin/make -f

BRANCH               := $(shell git rev-parse --abbrev-ref HEAD)
COMMIT               := $(shell git log -1 --format='%H')
BUILD_DIR            ?= $(CURDIR)/build
GOLANGCILINT_VERSION := 1.51.2

.PHONY: install-linter install-abigen concord concord-linux whisper whisper-linux

###############################################################################
##                                  Version                                  ##
###############################################################################

ifeq (,$(VERSION))
  VERSION := $(shell git describe --exact-match --tags 2>/dev/null | sed 's/^v//')
  # if VERSION is empty, then populate it with branch's name and raw commit hash
  ifeq (,$(VERSION))
    VERSION := $(BRANCH)-$(COMMIT)
  endif
endif

ldflags = -X github.com/cosmos/cosmos-sdk/version.Name=pigeon \
		  -X github.com/cosmos/cosmos-sdk/version.AppName=pigeon \
		  -X github.com/cosmos/cosmos-sdk/version.Version=$(VERSION) \
		  -X github.com/cosmos/cosmos-sdk/version.Commit=$(COMMIT) \
		  -X github.com/palomachain/concord/config.version=$(VERSION) \
		  -X github.com/palomachain/concord/config.commit=$(COMMIT) \

ldflags += $(LDFLAGS)
ldflags := $(strip $(ldflags))

BUILD_FLAGS := -tags "$(build_tags)" -ldflags '$(ldflags)'

###############################################################################
##                            Helping target                                 ##
###############################################################################

RED_TEXT_BEGIN?=\033[0;31m
GREEN_TEXT_BEGIN?=\033[0;32m
YELLOW_TEXT_BEGIN?=\033[0;33m
AZURE_TEXT_BEGIN?=\033[0;36m
COLOURED_TEXT_END?=\033[0m

HELP_ROW_FORMAT := $(shell echo "$(AZURE_TEXT_BEGIN)%-30s$(COLOURED_TEXT_END)%s")

help::
	@echo "$(YELLOW_TEXT_BEGIN)Pigeon$(COLOURED_TEXT_END):"
	@printf "$(HELP_ROW_FORMAT)\n" "TARGET"                  "DESCRIPTION"
	@echo "---------------------------------------------------------------------------------"
	@printf "$(HELP_ROW_FORMAT)\n" "build-linux"             "Builds the application binary for Linux AMD64"
	@printf "$(HELP_ROW_FORMAT)\n" "test"                    "Runs go tests"
	@printf "$(HELP_ROW_FORMAT)\n" "lint"                    "Lints (runs static checks) the code"
	@printf "$(HELP_ROW_FORMAT)\n" "generate-code-from-abi"  "Generates Go code by the smart contract ABI"


go.sum: go.mod
	@echo "--> Ensure dependencies have not been modified"
	@go mod verify

concord: go.sum
	@echo "--> Building..."
	go build -mod=readonly $(BUILD_FLAGS) -o $(BUILD_DIR)/ ./cmd/concord

concord-linux: go.sum
	GOOS=linux GOARCH=amd64 $(MAKE) concord

whisper: go.sum
	@echo "--> Building..."
	go build -mod=readonly $(BUILD_FLAGS) -o $(BUILD_DIR)/ ./cmd/whisper

whisper-linux: go.sum
	GOOS=linux GOARCH=amd64 $(MAKE) whisper

scribe: go.sum
	@echo "--> Building..."
	go build -mod=readonly $(BUILD_FLAGS) -o $(BUILD_DIR)/ ./cmd/scribe

scribe-linux: go.sum
	GOOS=linux GOARCH=amd64 $(MAKE) scribe

relay: go.sum
	@echo "--> Building..."
	go build -mod=readonly $(BUILD_FLAGS) -o $(BUILD_DIR)/ ./cmd/relay

relay-linux: go.sum
	GOOS=linux GOARCH=amd64 $(MAKE) relay

test:
	@echo "--> Testing..."
	@gotestsum ./...

install-linter:
	@bash -c "source "scripts/golangci-lint.sh" && install_golangci_lint '$(GOLANGCILINT_VERSION)' '.'"

lint: install-linter
	@echo "--> Linting..."
	@third_party/golangci-lint run --concurrency 16 ./...

install-abigen:
	@bash -c ". scripts/abigen.sh && build_abigen_binary '$(shell pwd)'"

generate-code-from-abi: install-abigen
	@bash -c ". scripts/abigen.sh && abigen_generate_compass '$(shell pwd)'"

.DEFAULT_GOAL := help
