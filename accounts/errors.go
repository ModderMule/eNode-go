// Package accounts is the optional user login behind the Meta API: registration,
// passwords, sessions, and the ordered, pluggable steps an account passes before it
// is active (docs/meta-api.md).
//
// Nothing in this package knows about a particular step or payment provider. A step
// type is a Step implementation registered by name in a Registry; the payment step
// and its providers (accounts/payment, accounts/payment/woocommerce) are the first.
package accounts

import (
	"errors"

	"enode/locales"
)

// MsgCodes this package returns. Each must exist in every locales/*.json file.
const (
	CodeAuthRequired       = "auth.required"
	CodeInvalidCredentials = "auth.invalid_credentials"
	CodeSessionExpired     = "auth.session_expired"
	CodePending            = "account.pending"
	CodeActive             = "account.active"
	CodeExpired            = "account.expired"
	CodeDisabled           = "account.disabled"
	CodeUsernameTaken      = "account.username_taken"
	CodeUsernameInvalid    = "account.username_invalid"
	CodeEmailInvalid       = "account.email_invalid"
	CodeWeakPassword       = "account.weak_password"
	CodePasswordMismatch   = "account.password_mismatch"
	CodeRegistrationClosed = "account.registration_closed"
	CodeRegistered         = "account.registered"
	CodeLoggedOut          = "account.logged_out"
	CodeRateLimited        = "ratelimit.exceeded"
	CodeInvalidForm        = "request.invalid_form"
	CodeServerError        = "server.error"
)

// Errors of the operator actions.
var (
	ErrNoExpiry    = errors.New("accounts: the account's access does not expire")
	ErrUnknownStep = errors.New("accounts: no such step is configured")
)

// Kind classifies an Error for a transport to map onto its own status codes.
type Kind uint8

const (
	// KindInvalid: the request was malformed or failed validation.
	KindInvalid Kind = iota + 1
	// KindUnauthenticated: no credential, or a wrong one.
	KindUnauthenticated
	// KindForbidden: a valid login whose account may not do this yet.
	KindForbidden
	// KindConflict: the thing already exists.
	KindConflict
	// KindUnavailable: a dependency (database, payment provider) failed.
	KindUnavailable
	// KindRateLimited: too many attempts.
	KindRateLimited
)

// Error carries a MsgCode to the caller. Its Error() text is the English message,
// safe to show; the cause is kept for logs only.
type Error struct {
	Kind    Kind
	MsgCode string
	cause   error
}

// NewError returns an Error without a cause.
func NewError(kind Kind, code string) *Error { return &Error{Kind: kind, MsgCode: code} }

// WrapError returns an Error that keeps cause for logging.
func WrapError(kind Kind, code string, cause error) *Error {
	return &Error{Kind: kind, MsgCode: code, cause: cause}
}

func (e *Error) Error() string { return locales.T(locales.Default, e.MsgCode) }

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.cause }

// AsError returns err as an *Error, wrapping anything else as a server error.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return WrapError(KindUnavailable, CodeServerError, err)
}
