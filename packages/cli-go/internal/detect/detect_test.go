package detect

import "testing"

// Test values are built from parts so that this file does not itself look
// like it contains real credentials.
func TestFindsSecrets(t *testing.T) {
	hits := []string{
		"-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=",
		"key is AKIA" + "Q3EGRIIOWCJHRXQZ",
		"use ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5",
		"glpat-" + "x9Y8w7V6u5T4s3R2q1P0",
		"xoxb-" + "1234567890-abcdefABCDEF",
		"sk_live_" + "51Hx9ZqLkJv8Q2wE7rT5yU3i",
		"sk-ant-" + "api03-AbCdEfGhIjKlMnOpQrStUvWx",
		"sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"AIza" + "SyD3x9Y8w7V6u5T4s3R2q1P0o9N8m7L6k5J",
		"npm_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5",
		"eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zdWIiOiIxMjM0NTY3ODkw.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV",
		"postgres://admin:" + "Tr0ub4dor3xyz@db.internal:5432/app",
		"PASSWORD=" + "q7Lm2Vx9Rt4Wz8Np",
		`"api_key": "` + `A1b2C3d4E5f6G7h8I9j0"`,
		// A literal value in a filter is still a literal value.
		"env | grep TOKEN=" + "AbcDef12345678",
		"export TOKEN=" + "Ab3dEf9hJk2LmN7p",
	}
	for _, h := range hits {
		if Find(h) == "" {
			t.Errorf("missed: %.30q", h)
		}
	}
}

func TestIgnoresNonSecrets(t *testing.T) {
	misses := []string{
		"Please fix the login bug in auth.go",
		"Authorization: Bearer {{secret:STRIPE_KEY}}",
		"AKIA" + "IOSFODNN7EXAMPLE",
		"password=changeme",
		"password = <your password here>",
		"token=${GITHUB_TOKEN}",
		"postgres://user:" + "password@localhost/db is an example",
		"the secret is that we refactor first",
		"api_key: aaaaaaaaaaaaaaaa",
		"export PASSWORD=$(cat ~/.pgpass)",
		"commit 4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b",
		// Filters and variable references after NAME= are not literal values.
		"env | grep -o 'TOKEN=[A-Za-z0-9]*'",
		"env | grep -E 'TOKEN=|PASSWORD=|SECRET='",
		`sed -n 's/^TOKEN=\(.*\)$/len=\1/p' /proc/1/environ`,
		`grep -P 'TOKEN=\w{32}' app.env`,
		`grep -E 'TOKEN=.{20,}' app.env`,
		"TOKEN=$BG_TOKEN_Value2 ./run.sh",
		"TOKEN=%BG_PASS_Value2% run.cmd",
		`TOKEN=$(aws ssm get-parameter --name /app/token --query Parameter.Value --output text)`,
	}
	for _, m := range misses {
		if kind := Find(m); kind != "" {
			t.Errorf("false positive (%s): %q", kind, m)
		}
	}
}
