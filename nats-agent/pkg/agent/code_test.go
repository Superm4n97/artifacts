package agent

import "testing"

func TestCode(t *testing.T) {
	cases := map[string]string{
		// Test vector from the platform's agent docs.
		"user:alice": "3k6r3ogtlkytcbrhj5q7dp4xpa",
		// Confirmed against a live server's $SYS.REQ.USER.INFO answer.
		AgentIdentity("01a2034e-79ce-7397-b3d0-ac67b916df3c"): "s5vjhdqq2ke3fuohnhtpolcyjq",
	}
	for identity, want := range cases {
		if got := Code(identity); got != want {
			t.Errorf("Code(%q) = %q, want %q", identity, got, want)
		}
		if len(want) != 26 {
			t.Errorf("code %q is not 26 characters", want)
		}
	}
}

func TestAgentIdentity(t *testing.T) {
	if got := AgentIdentity("abc"); got != "service_account:abc" {
		t.Fatalf("AgentIdentity = %q", got)
	}
}
