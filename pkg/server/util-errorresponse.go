package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Message returned to users for Internal Server Error errors
const internalServerErrorMessage = "An internal error occurred"

// ResponseError is used to send JSON responses with an error
type ResponseError struct {
	// Error message
	Message string
	// Status code
	Code int
}

// NewResponseError creates a new ErrorResponse with the code and message
func NewResponseError(code int, message string) ResponseError {
	return ResponseError{
		Message: message,
		Code:    code,
	}
}

// NewResponseErrorf creates a new ErrorResponse with the code and formatted message
func NewResponseErrorf(code int, messageFmt string, args ...any) ResponseError {
	return ResponseError{
		Message: fmt.Sprintf(messageFmt, args...),
		Code:    code,
	}
}

// MarshalJSON implements a JSON marshaller that returns an object with the error key
func (e ResponseError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Error string `json:"error"`
	}{
		Error: e.Message,
	})
}

// Error implements the error interface
func (e ResponseError) Error() string {
	return e.Message
}

// AbortWithErrorJSON aborts a Gin context and sends a response with a JSON error message.
// Pass an ErrorResponse object to be able to customize the status code; it defaults to 500 otherwise.
// If the status code is >= 500, the message is not sent to users directly.
func AbortWithErrorJSON(c *gin.Context, err error) {
	enc := json.NewEncoder(c.Writer)
	enc.SetEscapeHTML(false)

	// Add to the Gin error list
	_ = c.Error(err)

	// Abort the Gin context to stop processing handlers
	c.Abort()

	var errRes ResponseError
	switch {
	case errors.As(err, &errRes):
		// Error is of type ErrorResponse
		// If the error is >= 500, we must not show the actual error to the user
		if errRes.Code >= 500 {
			errRes.Message = internalServerErrorMessage
		}

	default:
		// Any other error
		// Assume this is an Internal Server Error
		errRes.Code = http.StatusInternalServerError
		errRes.Message = internalServerErrorMessage
	}

	// Send the response
	c.Header("Content-Type", "application/json")
	c.Status(errRes.Code)
	_ = enc.Encode(errRes)
}
