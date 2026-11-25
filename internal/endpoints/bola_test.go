package endpoints

import "testing"

func TestBolaImpactWholeWordMatching(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		handler string
		want    string
	}{
		// All ten credential/contact words on state-changing methods
		{"password path", "PUT", "/api/users/{id}/password", "update", "account-takeover"},
		{"passwd path", "POST", "/api/users/{id}/passwd", "update", "account-takeover"},
		{"kebab pin", "PUT", "/api/users/{id}/reset-pin", "update", "account-takeover"},
		{"camel pin handler", "POST", "/api/users/{id}/update", "UserController.resetPin", "account-takeover"},
		{"snake pin", "PATCH", "/api/users/{id}/reset_pin", "update", "account-takeover"},
		{"otp acronym", "POST", "/api/users/{id}/resetOTPCode", "update", "account-takeover"},
		{"email", "PUT", "/api/users/{id}/email", "update", "account-takeover"},
		{"mobile", "PUT", "/api/users/{id}/mobile", "update", "account-takeover"},
		{"phone", "PATCH", "/api/users/{id}/phone", "update", "account-takeover"},
		{"mfa", "DELETE", "/api/users/{id}/mfa", "disable", "account-takeover"},
		{"session", "DELETE", "/api/sessions/{sessionId}", "drop", "account-takeover"},
		{"token", "ANY", "/api/users/{id}/refreshToken", "rotate", "account-takeover"},

		// Whole-word negatives: substrings must NOT trigger account-takeover
		{"shipping not pin", "POST", "/api/orders/{id}/shipping", "updateShipping", "logic-abuse"},
		{"mapping not pin", "PUT", "/api/items/{id}/mapping", "saveMapping", "logic-abuse"},
		{"opinion not pin", "PATCH", "/api/posts/{id}/opinion", "editOpinion", "logic-abuse"},
		{"tokenizer not token", "POST", "/api/articles/{id}/tokenizer", "runTokenizer", "logic-abuse"},
		{"plain state change", "DELETE", "/api/cards/{cardId}", "deleteCard", "logic-abuse"},

		// Read methods are always data-exposure, even with credential words
		{"get password", "GET", "/api/users/{id}/password", "getPassword", "data-exposure"},
		{"head token", "HEAD", "/api/users/{id}/token", "checkToken", "data-exposure"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := bolaImpact(Route{Method: tc.method, Path: tc.path, Handler: tc.handler})
			if got != tc.want {
				t.Errorf("bolaImpact(%s %s, %s) = %q, want %q", tc.method, tc.path, tc.handler, got, tc.want)
			}
		})
	}
}
