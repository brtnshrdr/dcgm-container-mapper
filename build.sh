#! /bin/bash

echo "Cleaning dist directory"
rm -rf dist/*

echo "Building for AMD64"
GOOS=linux GOARCH=amd64 go build -o dist/dcgm-container-mapper-linux-amd64 main.go

echo "Building for ARM64"
GOOS=linux GOARCH=arm64 go build -o dist/dcgm-container-mapper-linux-arm64 main.go

echo "Setting executable permissions"
chmod +x dist/dcgm-container-mapper-linux-amd64
chmod +x dist/dcgm-container-mapper-linux-arm64

echo "Build complete"