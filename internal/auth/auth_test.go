package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	cases := []struct {
		name          string
		header        string
		want          string
		wantErrString string
	}{
		{
			name:          "no authorization header",
			header:        "",
			want:          "",
			wantErrString: "no authorization header included",
		},
		{
			name:          "malformed header - bearer",
			header:        "Bearer sometoken",
			want:          "",
			wantErrString: "malformed authorization header",
		},
		{
			name:          "malformed header - single token",
			header:        "just-a-token",
			want:          "",
			wantErrString: "malformed authorization header",
		},
		{
			name:          "wrong case prefix",
			header:        "apikey mykey",
			want:          "",
			wantErrString: "malformed authorization header",
		},
		{
			name:          "valid header",
			header:        "ApiKey secret-key",
			want:          "secret-key",
			wantErrString: "",
		},
		{
			name:          "valid header with extra parts",
			header:        "ApiKey secret-key extra",
			want:          "secret-key",
			wantErrString: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.header != "" {
				headers.Set("Authorization", tc.header)
			}
			got, err := GetAPIKey(headers)
			if tc.wantErrString != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErrString)
				}
				if err.Error() != tc.wantErrString {
					t.Fatalf("expected error %q, got %q", tc.wantErrString, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected key %q, got %q", tc.want, got)
			}
		})
	}
}
