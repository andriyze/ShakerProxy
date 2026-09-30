package agentapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

const (
	maxAPIErrorMessageBytes = 400
	maxAPIErrorCandidates   = 20
)

// APIError is a non-200 control API response. Message is the server's
// plain-language sentence (bounded and control-character free) that says
// what went wrong and what to do next; Candidates lists devices when a
// device reference was ambiguous.
type APIError struct {
	Status     int
	Code       string
	Message    string
	Candidates []DeviceMatch
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("agent API returned HTTP %d", e.Status)
}

func decodeAPIError(response *http.Response) error {
	failure := &APIError{Status: response.StatusCode}
	body, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyBytes+1))
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if len(body) > maxErrorBodyBytes {
		return failure
	}
	var envelope struct {
		Error struct {
			Code       string        `json:"code"`
			Message    string        `json:"message"`
			Candidates []DeviceMatch `json:"candidates"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return failure
	}
	failure.Code = boundedErrorText(envelope.Error.Code, 64)
	failure.Message = boundedErrorText(envelope.Error.Message, maxAPIErrorMessageBytes)
	for _, candidate := range envelope.Error.Candidates {
		if len(failure.Candidates) == maxAPIErrorCandidates {
			break
		}
		if validateDeviceMatch(candidate) == nil {
			failure.Candidates = append(failure.Candidates, candidate)
		}
	}
	return failure
}

func boundedErrorText(value string, maximum int) string {
	if !utf8.ValidString(value) {
		return ""
	}
	var builder strings.Builder
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			character = ' '
		}
		if builder.Len()+utf8.RuneLen(character) > maximum {
			break
		}
		builder.WriteRune(character)
	}
	return strings.TrimSpace(builder.String())
}
