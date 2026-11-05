package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// mosquitto can load the plugin more than once. A second init is refused and the first state stays.
func TestSecondInitIsRefused(t *testing.T) {
	first := map[string]string{
		"backends":            "files",
		"files_password_path": "test-files/passwords",
		"files_acl_path":      "test-files/acls",
	}
	require.True(t, initPlugin(first, "2.1.2"))
	backends := authPlugin.backends

	second := map[string]string{
		"backends":                "files",
		"files_password_path":     "test-files/passwords",
		"allow_empty_credentials": "true",
	}
	require.False(t, initPlugin(second, "2.1.2"))
	require.Same(t, backends, authPlugin.backends, "the first backends stay")
	require.Equal(t, first, authOpts, "the options of the refused init are not applied")
	require.False(t, authPlugin.allowEmptyCredentials)

	// After cleanup the plugin can start again.
	AuthPluginCleanup()
	require.True(t, initPlugin(first, "2.1.2"))
	AuthPluginCleanup()
}
