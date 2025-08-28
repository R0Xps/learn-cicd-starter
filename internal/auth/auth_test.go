package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		headerKey string
		headerVal string
		wantStr   string
		wantErr   string
	}

	noAuthHeader := "no authorization header included"
	malformedAuthHeader := "malformed authorization header"

	tests := map[string]test{
		"no authorization header": {
			wantStr: "",
			wantErr: noAuthHeader,
		},
		"empty authorization header": {
			headerKey: "Authorization",
			wantStr:   "",
			wantErr:   noAuthHeader,
		},
		"authorization header with bearer token instead of api key": {
			headerKey: "Authorization",
			headerVal: "Bearer exampleToken",
			wantStr:   "",
			wantErr:   malformedAuthHeader,
		},
		"authorization header missing api key": {
			headerKey: "Authorization",
			headerVal: "ApiKey",
			wantStr:   "",
			wantErr:   malformedAuthHeader,
		},
		"valid authorization header": {
			headerKey: "Authorization",
			headerVal: "ApiKey ValidApiKey",
			wantStr:   "ValidApiKey",
			wantErr:   "not expecting error",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			header := http.Header{}
			header.Set(tc.headerKey, tc.headerVal)

			gotStr, gotErr := GetAPIKey(header)

			if !errorContains(gotErr, tc.wantErr) {
				t.Fatalf("expected error: %v, got error: %v", tc.wantErr, gotErr)
			}

			if gotStr != tc.wantStr {
				t.Fatalf("expected output: %#v, got output: %#v", tc.wantStr, gotStr)
			}
		})
	}
}

func errorContains(got error, want string) bool {
	if got == nil {
		return want == "not expecting error"
	}
	return strings.Contains(got.Error(), want)
}
