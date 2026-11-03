package httpresponse

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteSuccessUsesEnvelope(t *testing.T) {
	response := httptest.NewRecorder()
	WriteSuccess(response, http.StatusOK, map[string]bool{"ready": true})
	want := "{\"code\":\"success\",\"msg\":\"ok\",\"data\":{\"ready\":true}}\n"
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != jsonContentType || response.Body.String() != want {
		t.Fatalf("response = status %d, content type %q, body %q", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
}

func TestWriteErrorUsesNullData(t *testing.T) {
	response := httptest.NewRecorder()
	WriteError(response, http.StatusBadRequest, "invalid_request", "request is invalid")
	want := "{\"code\":\"invalid_request\",\"msg\":\"request is invalid\",\"data\":null}\n"
	if response.Code != http.StatusBadRequest || response.Body.String() != want {
		t.Fatalf("response = status %d, body %q", response.Code, response.Body.String())
	}
}
