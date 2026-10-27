# grz_domato Makefile

PY ?= python3
ROOT := $(shell pwd)

# Load local paths if present (see .env.example). Missing file is fine.
ifneq (,$(wildcard $(ROOT)/.env))
include $(ROOT)/.env
export
endif

FIREFOX_SRC ?= $(HOME)/firefox
FIREFOX_BIN ?= $(shell find "$(FIREFOX_SRC)" -name firefox -path "*/dist/bin/firefox" 2>/dev/null | head -n1)

export FIREFOX_SRC
export FIREFOX_BIN

.PHONY: help doctor env audit probe check-rules wgsl scan extract readme clean

help:
	@echo "grz_domato targets:"
	@echo "  make doctor        - Check environment (source, binary, tools)"
	@echo "  make env           - Show current env vars used"
	@echo "  make extract       - Extract WebIDL inventory (dom/webidl -> results/audit/idl_inventory.json)"
	@echo "  make audit         - Run audit_rules.py --show-blocked (needs FIREFOX_SRC/StaticPrefList.yaml)"
	@echo "  make probe         - Run probe_apis.py (full) against built Firefox"
	@echo "  make check-rules   - Run check_rules.py --samples 25"
	@echo "  make wgsl          - Run check_wgsl.py"
	@echo "  make scan          - Run scan_cases.py --samples 16 --case-timeout 45"
	@echo "  make readme        - Open README.md"
	@echo ""
	@echo "Override: make audit FIREFOX_SRC=/path/to/firefox"
	@echo "          make probe FIREFOX_BIN=/path/to/firefox"
	@echo "Or copy .env.example -> .env and set FIREFOX_SRC / FIREFOX_BIN there."

doctor:
	$(PY) tools/doctor.py --source $(FIREFOX_SRC) $(if $(FIREFOX_BIN),--firefox $(FIREFOX_BIN),)

env:
	@echo "FIREFOX_SRC=$(FIREFOX_SRC)"
	@echo "FIREFOX_BIN=$(FIREFOX_BIN)"

extract:
	$(PY) tools/extract_idl.py --source $(FIREFOX_SRC)

audit:
	$(PY) tools/audit_rules.py --source $(FIREFOX_SRC) --show-blocked

probe:
	$(if $(FIREFOX_BIN),,$(error FIREFOX_BIN not set or not found. Set FIREFOX_BIN=... or .env))
	$(PY) tools/probe_apis.py --firefox $(FIREFOX_BIN)

check-rules:
	$(PY) tools/check_rules.py --samples 25

wgsl:
	$(PY) tools/check_wgsl.py

scan:
	$(if $(FIREFOX_BIN),,$(error FIREFOX_BIN not set or not found. Set FIREFOX_BIN=... or .env))
	MOZ_HEADLESS=1 $(PY) tools/scan_cases.py --samples 16 --case-timeout 45 $(if $(FIREFOX_BIN),--firefox $(FIREFOX_BIN),)

clean:
	rm -rf results/audit/* results/scan/* results/probe/* 2>/dev/null || true
	@echo "cleaned results/audit,results/scan,results/probe (kept dirs)"
