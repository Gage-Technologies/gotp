package gotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"hash"
	"math"
	"strings"
)

type Hasher struct {
	HashName string
	Digest   func() hash.Hash
}

type OTP struct {
	secret string  // secret in base32 format
	digits int64   // number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
	hasher *Hasher // digest function to use in the HMAC (expected to be sha1)
}

func NewOTP(secret string, digits int64, hasher *Hasher) OTP {
	if hasher == nil {
		hasher = &Hasher{
			HashName: "sha1",
			Digest:   sha1.New,
		}
	}
	return OTP{
		secret: secret,
		digits: digits,
		hasher: hasher,
	}
}

/*
params
    input: the HMAC counter value to use as the OTP input. Usually either the counter, or the computed integer based on the Unix timestamp
*/
func (o *OTP) generateOTP(input int64) string {
	if input < 0 {
		panic("input must be positive integer")
	}
	hasher := hmac.New(o.hasher.Digest, o.byteSecret())
	hasher.Write(Itob(int(input)))
	hmacHash := hasher.Sum(nil)

	offset := int64(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int64(hmacHash[offset]) & 0x7f) << 24) |
		((int64(hmacHash[offset+1] & 0xff)) << 16) |
		((int64(hmacHash[offset+2] & 0xff)) << 8) |
		(int64(hmacHash[offset+3]) & 0xff)

	code = code % int64(math.Pow10(int(o.digits)))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", o.digits), code)
}

func (o *OTP) byteSecret() []byte {
	missingPadding := len(o.secret) % 8
	if missingPadding != 0 {
		o.secret = o.secret + strings.Repeat("=", 8-missingPadding)
	}
	bytes, err := base32.StdEncoding.DecodeString(o.secret)
	if err != nil {
		panic("decode secret failed")
	}
	return bytes
}
