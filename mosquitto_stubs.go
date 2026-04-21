//go:build test
// +build test

package main

/*
// Weak stubs for mosquitto symbols.
// During normal plugin use these are overridden by the broker's real implementations.
// During `go test` they satisfy the linker so a test binary can be built.
__attribute__((weak)) const char* mosquitto_client_id(const void *client) { (void)client; return ""; }
__attribute__((weak)) const char* mosquitto_client_username(const void *client) { (void)client; return ""; }
*/
import "C"
