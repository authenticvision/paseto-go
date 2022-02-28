package paseto

import (
	"time"
)

// Parser is used to verify or decrypt a token, and can be provided with
// a set of rules.
type Parser struct {
	rules []Rule
}

// NewParser returns a parser with no currently set rules.
func NewParser() Parser {
	return Parser{nil}
}

// NewParserForValidNow returns a parser that will require parsed tokens to be
// valid "now".
func NewParserForValidNow() Parser {
	return Parser{[]Rule{ValidAt(time.Now())}}
}

// MakeParser allows a parser to be constructed with a specified set of rules.
func MakeParser(rules []Rule) Parser {
	return Parser{rules}
}

// ParseV4Local will parse and decrypt a v4 local paseto and validate against
// any parser rules. Error if parsing, decryption, or any rule fails.
func (p Parser) ParseV4Local(key V4SymmetricKey, tainted string, implicit []byte) (*Token, error) {
	var message Message
	var err error

	if message, err = NewMessage(V4Local, tainted); err != nil {
		return nil, err
	}

	var token *Token
	if token, err = message.V4Decrypt(key, implicit); err != nil {
		return nil, err
	}

	return p.validate(*token)
}

// ParseV4Public will parse and verify a v4 public paseto and validate against
// any parser rules. Error if parsing, verification, or any rule fails.
func (p Parser) ParseV4Public(key V4AsymmetricPublicKey, tainted string, implicit []byte) (*Token, error) {
	var message Message
	var err error

	if message, err = NewMessage(V4Public, tainted); err != nil {
		return nil, err
	}

	var token *Token
	if token, err = message.V4Verify(key, implicit); err != nil {
		return nil, err
	}

	return p.validate(*token)
}

// SetRules will overwrite any currently set rules with those specified.
func (p *Parser) SetRules(rules []Rule) {
	p.rules = rules
}

// AddRule will add the given rule(s) to any already specified.
func (p *Parser) AddRule(rule ...Rule) {
	p.rules = append(p.rules, rule...)
}

func (p Parser) validate(token Token) (*Token, error) {
	for _, rule := range p.rules {
		if err := rule(token); err != nil {
			return nil, err
		}
	}

	return &token, nil
}
