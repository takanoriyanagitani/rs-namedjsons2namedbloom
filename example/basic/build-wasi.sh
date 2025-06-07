#!/bin/sh

cargo \
	build \
	--target wasm32-wasip1 \
	--profile release-wasi
