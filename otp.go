package otp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"time"
)

// OTPConfig is a one-time-password configuration.  This object will be modified by calls to
// Authenticate and should be saved to ensure the codes are in fact only used
// once.
type OTPConfig struct {
	Secret       string // 10 bytes base32 encoded string of the user's secret
	WindowSize   int    // valid range: technically 0..100 or so, but beyond 3-5 is probably bad security
	UsedCodes    []int  // timestamps in the current window unavailable for re-use
	ScratchCodes []int  // an array of 8-digit numeric codes that can be used to log in
}

// ErrInvalidCode indicate the supplied one-time code was not valid
var (
	ErrInvalidCode      = errors.New("invalid code")
	ErrInvalidSecret    = errors.New("invalid secret")
	ErrInvalidChallenge = errors.New("invalid secret")
)

// ComputeCode computes the response code for a 64-bit challenge 'value' using the secret 'secret'.
func ComputeCode(secret string, challenge int64) (code string, err error) {
	var b []byte
	if b, err = base32.StdEncoding.DecodeString(secret); err != nil {
		return "", ErrInvalidSecret
	}
	hash := hmac.New(sha1.New, b)
	if err = binary.Write(hash, binary.BigEndian, challenge); err != nil {
		return "", ErrInvalidChallenge
	}
	b = hash.Sum(nil)
	offset := b[19] & 0x0f
	code = fmt.Sprintf("%06d", (binary.BigEndian.Uint32(b[offset:offset+4])&0x7fffffff)%1000000)
	return code, nil
}

// New creates OTP authentincation instance
func New(scratchCodes int) *OTPConfig {
	r := make([]byte, 10)
	rand.Read(r)
	otp := &OTPConfig{
		Secret:       base32.StdEncoding.EncodeToString(r),
		WindowSize:   5,
		ScratchCodes: make([]int, scratchCodes),
	}
	for i := 0; i < scratchCodes; i++ {
		otp.ScratchCodes[i] = NewScratchCode()
	}
	return otp
}

// Load deserializes OTP configuration
func Load(data []byte) (otp *OTPConfig, err error) {
	otp = new(OTPConfig)
	var b bytes.Buffer
	b.Write(data)
	err = gob.NewDecoder(&b).Decode(&otp)
	return otp, err
}

// NewScratchCode generates random scratch code (8 digits)
func NewScratchCode() int {
	var r = []rune("0123456789")
	b := make([]rune, 8)
	for i := range b {
		// First character can not be "0"
		if i == 0 {
			b[i] = r[rand.Intn(9)+1]
			continue
		}
		b[i] = r[rand.Intn(10)]
	}
	c, _ := strconv.Atoi(string(b))
	return c
}

// Save serializes OTP configuration
func (otp *OTPConfig) Save() (data []byte, err error) {
	otp.GC()
	var b bytes.Buffer
	err = gob.NewEncoder(&b).Encode(*otp)
	return b.Bytes(), err
}

// Authenticate a one-time-password against the given OTPConfig
// Returns true/false if the authentication was successful.
// Returns error if the password is incorrectly formatted (not a zero-padded 6 or non-zero-padded 8 digit number).
func (otp *OTPConfig) Authenticate(password string) (bool, error) {
	code, err := strconv.Atoi(password)
	if err != nil {
		return false, ErrInvalidCode
	}

	switch {

	// TOTP code
	case len(password) == 6:
		t0 := int(time.Now().UTC().Unix() / 30)
		minT := t0 - (otp.WindowSize / 2)
		maxT := t0 + (otp.WindowSize / 2)
		for t := minT; t <= maxT; t++ {
			if cc, _ := ComputeCode(otp.Secret, int64(t)); cc == password {
				// check "UsedCodes"
				for i := range otp.UsedCodes {
					if otp.UsedCodes[i] == t {
						return false, nil
					}
				}
				otp.UsedCodes = append(otp.UsedCodes, t)
				otp.GC()
				// code OK
				return true, nil
			}
		}
		return false, nil

	// Scratch code
	case len(password) == 8 && password[0] >= '1':
		for i := range otp.ScratchCodes {
			if code == otp.ScratchCodes[i] {
				otp.ScratchCodes = append(otp.ScratchCodes[:i], otp.ScratchCodes[i+1:]...)
				return true, nil
			}
		}
		return false, nil

	default:
		return false, ErrInvalidCode
	}
}

// GC (Garbage collect) - remove old UsedCodes
func (otp *OTPConfig) GC() {
	t0 := int(time.Now().UTC().Unix() / 30)
	minT := t0 - (otp.WindowSize / 2)
	b := make([]int, 0)
	for i := range otp.UsedCodes {
		if otp.UsedCodes[i] >= minT {
			b = append(b, otp.UsedCodes[i])
		}
	}
	otp.UsedCodes = b
}

// ProvisionURI generates a URI that can be turned into a QR code
// to configure a Authenticator app. It respects the recommendations
// on how to avoid conflicting accounts.
// See https://github.com/google/google-authenticator/wiki/Conflicting-Accounts
func (otp *OTPConfig) ProvisionURI(user string, issuer string) string {
	auth := "totp/"
	q := make(url.Values)
	q.Add("secret", otp.Secret)
	if issuer != "" {
		q.Add("issuer", issuer)
		auth += issuer + ":"
	}
	return "otpauth://" + auth + user + "?" + q.Encode()
}
