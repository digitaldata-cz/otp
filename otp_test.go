package otp

import (
	"testing"
	"time"
)

// Test vectors via:
// http://code.google.com/p/google-authenticator/source/browse/libpam/pam_google_authenticator_unittest.c
// https://google-authenticator.googlecode.com/hg/libpam/totp.html

var codeTests = []struct {
	secret string
	value  int64
	code   string
}{
	{"2SH3V3GDW7ZNMGYE", 1, "293240"},
	{"2SH3V3GDW7ZNMGYE", 5, "932068"},
	{"2SH3V3GDW7ZNMGYE", 10000, "050548"},
}

func TestCode(t *testing.T) {
	for _, v := range codeTests {
		c, _ := ComputeCode(v.secret, v.value)
		if c != v.code {
			t.Errorf("computeCode(%s, %d): got %s expected %s\n", v.secret, v.value, c, v.code)
		}
	}
}

func TestScratchCode(t *testing.T) {
	var cotp OTPConfig
	cotp.ScratchCodes = []int{11112222, 22223333}
	var scratchTests = []struct {
		code   string
		result bool
	}{
		{"33334444", false},
		{"11112222", true},
		{"11112222", false},
		{"22223333", true},
		{"22223333", false},
		{"33334444", false},
	}
	for _, s := range scratchTests {
		r, _ := cotp.Authenticate(s.code)
		if r != s.result {
			t.Errorf("scratchcode(%s) failed: got %t expected %t", s.code, r, s.result)
		}
	}
}

func TestTotpCode(t *testing.T) {
	var cotp OTPConfig
	cotp.Secret = "2SH3V3GDW7ZNMGYE"
	cotp.WindowSize = 5

	t0 := time.Now().UTC().Unix() / 30
	var windowTest = []struct {
		code   string
		t0     int64
		result bool
	}{
		{"", t0 - 4, false},
		{"", t0 - 4, false},
		{"", t0 - 3, false},
		{"", t0 - 3, false},
		{"", t0 - 2, true},
		{"", t0 - 2, false},
		{"", t0 - 1, true},
		{"", t0 - 1, false},
		{"", t0, true},
		{"", t0, false},
		{"", t0 + 1, true},
		{"", t0 + 1, false},
		{"", t0 + 2, true},
		{"", t0 + 2, false},
		{"", t0 + 3, false},
		{"", t0 + 3, false},
		{"", t0 + 4, false},
		{"", t0 + 4, false},
	}
	for i := range windowTest {
		windowTest[i].code, _ = ComputeCode(cotp.Secret, windowTest[i].t0)
	}

	for i, s := range windowTest {
		r, _ := cotp.Authenticate(s.code)
		if r != s.result {
			t.Errorf("counterCode(%s) (step %d) failed: got %t expected %t", s.code, i, r, s.result)
		}
	}
}

func TestAuthenticate(t *testing.T) {

	otpconf := &OTPConfig{
		Secret:       "2SH3V3GDW7ZNMGYE",
		WindowSize:   3,
		ScratchCodes: []int{11112222, 22223333},
	}

	type attempt struct {
		code   string
		result bool
	}

	var attempts = []attempt{
		{"foobar", false},   // not digits
		{"1fooba", false},   // not valid number
		{"1111111", false},  // bad length
		{"33334444", false}, // scratch
		{"11112222", true},
		{"11112222", false},
	}

	for _, a := range attempts {
		r, _ := otpconf.Authenticate(a.code)
		if r != a.result {
			t.Errorf("bad result from code=%s: got %t expected %t\n", a.code, r, a.result)
		}
	}

	// I haven't mocked the clock, so we'll just compute one
	t0 := int64(time.Now().UTC().Unix() / 30)
	c, _ := ComputeCode(otpconf.Secret, t0)

	attempts = []attempt{
		{c + "1", false},
		{c, true},
	}

	for _, a := range attempts {
		r, _ := otpconf.Authenticate(a.code)
		if r != a.result {
			t.Errorf("bad result from code=%s: got %t expected %t\n", a.code, r, a.result)
		}
	}

}

func TestProvisionURI(t *testing.T) {
	otpconf := OTPConfig{
		Secret: "x",
	}

	cases := []struct {
		user, iss string
		out       string
	}{
		{"test", "", "otpauth://totp/test?secret=x"},
		{"test", "Company", "otpauth://totp/Company:test?issuer=Company&secret=x"},
	}

	for i, c := range cases {
		got := otpconf.ProvisionURI(c.user, c.iss)
		if got != c.out {
			t.Errorf("%d: want %q, got %q", i, c.out, got)
		}
	}
}
