//go:build clientonly

package main

// This policy is compiled into the container binary, independently of its
// entrypoint, command-line flags and mounted configuration.
const clientOnly = true
