package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_ValidKey(t *testing.T) {
	headers := http.Header{"Authorization": []string{"ApiKey abc123"}}
	apiKey, err := GetAPIKey(headers)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	expectedKey := "abc123"
	if apiKey != expectedKey {
		t.Errorf("Expected API key %s, got %s", expectedKey, apiKey)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}
	apiKey, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error ErrNoAuthHeaderIncluded, got %v", err)
	}

	if apiKey != "" {
		t.Errorf("Expected empty API key, got %s", apiKey)
	}
}

func TestGetAPIKey_MalformedAuthHeader(t *testing.T) {
	headers := http.Header{"Authorization": []string{"Bearer token123"}}
	apiKey, err := GetAPIKey(headers)

	expectedErr := errors.New("malformed authorization header")
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error '%v', got '%v'", expectedErr, err)
	}

	if apiKey != "" {
		t.Errorf("Expected empty API key, got %s", apiKey)
	}
}

func TestGetAPIKey_EmptyAuthHeaderValue(t *testing.T) {
	headers := http.Header{"Authorization": []string{""}}
	apiKey, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error ErrNoAuthHeaderIncluded, got %v", err)
	}

	if apiKey != "" {
		t.Errorf("Expected empty API key, got %s", apiKey)
	}
}
