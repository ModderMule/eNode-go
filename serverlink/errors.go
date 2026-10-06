package serverlink

import (
	"errors"

	"enode/locales"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectproto"
	metav1 "github.com/ModderMule/enodemeta/gen/enode/meta/v1"
)

// MsgCodes this package returns. Each must exist in every locales/*.json file.
// The last five are shared with the Meta API and the accounts.
const (
	CodeDisabled       = "serversearch.disabled"
	CodeUnauthorized   = "serversearch.unauthorized"
	CodeBrowseDisabled = "serversearch.browse_disabled"
	CodeCursorInvalid  = "serversearch.cursor_invalid"

	CodeUnavailable         = "search.unavailable"
	CodeSearchDisabled      = "search.disabled"
	CodeSearchQueryRequired = "search.query_required"
	CodeSearchQueryTooLong  = "search.query_too_long"
	CodeRateLimited         = "ratelimit.exceeded"
)

// MsgCodeOf returns the MsgCode a ServerSearch error carries in its ErrorInfo
// detail, or "" when it carries none.
func MsgCodeOf(err error) string {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return ""
	}
	for _, d := range ce.Details() {
		if msg, derr := connectproto.UnmarshalErrorDetail(d); derr == nil {
			if info, ok := msg.(*metav1.ErrorInfo); ok {
				return info.GetMsgCode()
			}
		}
	}
	return ""
}

// connectError builds the error a caller sees: the code, the English text of
// msgCode, and the msgCode itself as an ErrorInfo detail.
func connectError(code connect.Code, msgCode string) error {
	e := connect.NewError(code, locales.T(locales.Default, msgCode))
	if d, err := connectproto.NewErrorDetail(&metav1.ErrorInfo{MsgCode: msgCode}); err == nil {
		e = e.WithDetail(d)
	}
	return e
}
