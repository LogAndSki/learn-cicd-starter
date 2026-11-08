package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   error // sentinel error, if one is expected
		wantAnyErr bool // true if any non-nil error is acceptable
	}{
		{
			name:    "valid ApiKey header",
			headers: http.Header{"Authorization": []string{"ApiKey abc123"}},
			wantKey: "abc123",
		},
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "empty authorization header value",
			headers: http.Header{"Authorization": []string{""}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "wrong scheme (Bearer)",
			headers:    http.Header{"Authorization": []string{"Bearer abc123"}},
			wantAnyErr: true,
		},
		{
			name:       "scheme only, no key",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantAnyErr: true,
		},
		{
			name:       "lowercase scheme",
			headers:    http.Header{"Authorization": []string{"apikey abc123"}},
			wantAnyErr: true,
		},
		{
			name:    "extra tokens after key are ignored",
			headers: http.Header{"Authorization": []string{"ApiKey abc123 extra"}},
			wantKey: "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if tt.wantAnyErr {
				if err == nil {
					t.Fatalf("expected an error, got nil (key=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, got)
			}
		})
	}
}