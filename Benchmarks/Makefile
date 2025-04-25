# SPDX-FileCopyrightText: 2025 Cisco
#
# SPDX-License-Identifier: Apache-2.0

# Makefile for Swift benchmarking

.PHONY: update bench help

# Update the benchmark baseline for alpha
update:
	swift package --allow-writing-to-package-directory benchmark baseline update alpha

# Compare benchmark results against the alpha baseline
bench:
	swift package benchmark baseline compare alpha

# Default target
.DEFAULT_GOAL := bench

# Add help command
help:
	@echo "Available commands:"
	@echo "  make update  - Update the benchmark baseline for alpha"
	@echo "  make bench   - Run benchmarks and compare against alpha baseline"
	@echo "  make help    - Show this help message"
