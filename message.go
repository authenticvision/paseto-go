package paseto

import (
	"strings"

	"aidanwoods.dev/go-paseto/internal/encoding"
	t "aidanwoods.dev/go-result"
)

// Message is a building block type, only use if you need to use Paseto
// cryptography without Paseto's token or validator semantics.
type message struct {
	protocol Protocol
	p        payload
	footer   []byte
}

// NewMessage creates a new message from the given token, with an expected
// protocol. If the given token does not match the given token, or if the
// token cannot be parsed, will return an error instead.
func newMessage(protocol Protocol, token string) t.Result[message] {
	var parts deconstructedToken
	if partsRes := deconstructToken(token); partsRes.IsErr() {
		return t.Err[message](partsRes.UnwrapErr())
	} else {
		parts = partsRes.Unwrap()
	}

	if parts.header != protocol.Header() {
		return t.Err[message](errorMessageHeader(protocol, parts.header))
	}

	var pload payload
	if payloadRes := t.AndThen(encoding.Decode(parts.encodedPayload), protocol.newPayload); payloadRes.IsErr() {
		return t.Err[message](newTokenError(payloadRes.UnwrapErr()))
	} else {
		pload = payloadRes.Unwrap()
	}

	var encodedFooter []byte
	if footerRes := encoding.Decode(parts.encodedFooter); footerRes.IsErr() {
		return t.Err[message](footerRes.UnwrapErr())
	} else {
		encodedFooter = footerRes.Unwrap()
	}

	return t.Ok(newMessageFromPayloadAndFooter(pload, encodedFooter))
}

// Header returns the header string for a Paseto message.
func (m message) header() string {
	return m.protocol.Header()
}

// UnsafeFooter returns the footer of a Paseto message. Beware that this footer
// is not cryptographically verified at this stage.
func (m message) unsafeFooter() []byte {
	return m.footer
}

// Encoded returns the string representation of a Paseto message.
func (m message) encoded() string {
	main := m.header() + encoding.Encode(m.p.bytes())

	if len(m.footer) == 0 {
		return main
	}

	return main + "." + encoding.Encode(m.footer)
}

func newMessageFromPayloadAndFooter(payload payload, footer []byte) message {
	// Assume internal callers won't construct bad payloads
	protocol := protocolForPayload(payload).Expect("sanity check for payload failed")
	return message{protocol, payload, footer}
}

type deconstructedToken struct {
	header         string
	encodedPayload string
	encodedFooter  string
}

func deconstructToken(token string) t.Result[deconstructedToken] {
	parts := strings.Split(token, ".")

	partsLen := len(parts)
	if partsLen != 3 && partsLen != 4 {
		return t.Err[deconstructedToken](errorMessageParts(len(parts)))
	}

	header := parts[0] + "." + parts[1] + "."
	encodedPayload := parts[2]

	encodedFooter := ""
	if partsLen == 4 {
		encodedFooter = parts[3]
	}

	return t.Ok(deconstructedToken{
		header:         header,
		encodedPayload: encodedPayload,
		encodedFooter:  encodedFooter,
	})
}

// V2Verify will verify a v2 public paseto message. Will return a pointer to
// the verified token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v2Verify(key V2AsymmetricPublicKey) t.Result[Token] {
	return t.AndThen(v2PublicVerify(m, key), packet.token)
}

// V2Decrypt will decrypt a v2 local paseto message. Will return a pointer to
// the decrypted token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v2Decrypt(key V2SymmetricKey) t.Result[Token] {
	return t.AndThen(v2LocalDecrypt(m, key), packet.token)
}

// V3Verify will verify a v4 public paseto message. Will return a pointer to
// the verified token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v3Verify(key V3AsymmetricPublicKey, implicit []byte) t.Result[Token] {
	return t.AndThen(v3PublicVerify(m, key, implicit), packet.token)
}

// V3Decrypt will decrypt a v3 local paseto message. Will return a pointer to
// the decrypted token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v3Decrypt(key V3SymmetricKey, implicit []byte) t.Result[Token] {
	return t.AndThen(v3LocalDecrypt(m, key, implicit), packet.token)
}

// V4Verify will verify a v4 public paseto message. Will return a pointer to
// the verified token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v4Verify(key V4AsymmetricPublicKey, implicit []byte) t.Result[Token] {
	return t.AndThen(v4PublicVerify(m, key, implicit), packet.token)
}

// V4Decrypt will decrypt a v4 local paseto message. Will return a pointer to
// the decrypted token (but not validated with rules) if successful, or error in
// the event of failure.
func (m message) v4Decrypt(key V4SymmetricKey, implicit []byte) t.Result[Token] {
	return t.AndThen(v4LocalDecrypt(m, key, implicit), packet.token)
}
