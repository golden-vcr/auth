package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/golden-vcr/auth"
	"github.com/golden-vcr/server-common/hmac"
)

func (s *Server) handlePostServiceToken(res http.ResponseWriter, req *http.Request) {
	// Read the request body preemptively so we can verify the signature
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	// The request should carry a signature that was generated by HMAC-encrypting a few
	// request headers alongside the body: verify this signature to ensure that the
	// request is coming from an authorized internal service
	err = s.verifier.Verify(req, body)
	if err != nil {
		if errors.Is(err, hmac.ErrVerificationFailed) {
			http.Error(res, "access denied", http.StatusUnauthorized)
		} else {
			http.Error(res, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// The request's Content-Type must indicate JSON if set
	contentType := req.Header.Get("content-type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		http.Error(res, "content-type not supported", http.StatusBadRequest)
		return
	}

	// Parse the payload from the request body
	var payload auth.ServiceTokenRequest
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	if payload.User.Id == "" {
		http.Error(res, "invalid payload: 'user.id' is required", http.StatusBadRequest)
		return
	}
	if payload.User.Login == "" {
		http.Error(res, "invalid payload: 'user.login' is required", http.StatusBadRequest)
		return
	}
	if payload.User.DisplayName == "" {
		http.Error(res, "invalid payload: 'user.displayName' is required", http.StatusBadRequest)
		return
	}

	// Our request is valid and authenticated: issue a short-lived JWT that permits
	// viewer-level access to the requested user
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":                 time.Now().Format(time.RFC3339),
		"exp":                 time.Now().Add(15 * time.Minute).Format(time.RFC3339),
		"twitch_user_id":      payload.User.Id,
		"twitch_user_login":   payload.User.Login,
		"twitch_display_name": payload.User.DisplayName,
	})
	token.Header["kid"] = s.jwtSigningKeyId
	jwtString, err := token.SignedString(s.jwtSigningKey)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("content-type", "application/jwt")
	res.Write([]byte(jwtString))
}