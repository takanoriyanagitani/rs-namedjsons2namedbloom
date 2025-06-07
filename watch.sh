#!/bin/sh

cargo \
	watch \
	--watch src \
	--watch Cargo.toml \
	--shell ./check.sh
