//go:build masteronly

package main

// Enforce the container's role independently of its entrypoint and config.
const masterOnly = true
