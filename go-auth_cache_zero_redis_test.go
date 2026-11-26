//go:build integration

package main

import "testing"

func TestSetCacheZeroSecondsIsOffRedis(t *testing.T) {
	testSetCacheZeroSecondsIsOff(t, "redis")
}
