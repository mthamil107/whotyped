package syslog

import (
	"errors"
	"runtime"
	"testing"
)

func TestFacilityValidation(t *testing.T) {
	for _, ok := range []string{"", "auth", "AUTHPRIV", "local7", "daemon"} {
		if !ValidFacility(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"nope", "local8", "auth "} {
		if ValidFacility(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
	tag, fac, err := normalise("", "")
	if err != nil || tag != DefaultTag || fac != DefaultFacility {
		t.Fatalf("defaults: %q %q %v", tag, fac, err)
	}
	if _, err := New("whotyped", "bogus"); err == nil || errors.Is(err, ErrUnsupported) {
		t.Fatalf("bad facility should fail validation first, got %v", err)
	}
}

func TestNewOnNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux has a real syslog sink")
	}
	s, err := New("", "")
	if s != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v %v", s, err)
	}
}
