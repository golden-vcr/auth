package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

var ErrForeignToken = errors.New("token was not issued by the auth service")

func (c *client) retrieveSigningKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	key := c.getKey(kid)
	if key == nil {
		c.keyCacheMu.Lock()
		if err := c.fetchJWKS(ctx); err != nil {
			c.keyCacheMu.Unlock()
			return nil, err
		}
		c.keyCacheMu.Unlock()
		key = c.getKey(kid)
	}
	if key == nil {
		return nil, fmt.Errorf("no such key")
	}
	return key, nil
}

func (c *client) getKey(kid string) *rsa.PublicKey {
	c.keyCacheMu.RLock()
	defer c.keyCacheMu.RUnlock()

	if c.keyCacheExpiresAt.Before(time.Now()) {
		return nil
	}
	key, ok := c.keyCache[kid]
	if !ok {
		return nil
	}
	return &key
}

// fetchJWKS makes a request to the auth server at /.well-known/jwks.json to retrieve a
// fresh JWK Set, indicating the public keys corresponding to all the possible private
// keys that the auth service would have used for signing when issuing JWTs to internal
// services. Once it's retrieved that JSON payload, it parses each key to rsa.PublicKey
// and updates c.keyCache and c.keyCacheExpiresAt.
func (c *client) fetchJWKS(ctx context.Context) error {
	url := c.authUrl + "/.well-known/jwks.json"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch %s: got response %d", url, res.StatusCode)
	}
	contentType := res.Header.Get("content-type")
	if !strings.HasPrefix(contentType, "application/json") {
		return fmt.Errorf("invalid response from %s: unexpected content-type '%s'", url, contentType)
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body from %s: %w", url, err)
	}
	newKeyCache, err := parseJWKS(data)
	if err != nil {
		return fmt.Errorf("failed to parse response body from %s: %w", url, err)
	}
	c.keyCache = newKeyCache
	c.keyCacheExpiresAt = time.Now().Add(c.keyCacheTTL)
	return nil
}

// parseJWKS accepts the raw JSON payload received from jwks.json and parses it to
// return a map containg each rsa.PublicKey, indexed by its string 'kid' value
func parseJWKS(data []byte) (map[string]rsa.PublicKey, error) {
	result := make(map[string]rsa.PublicKey)
	jwks, err := jwk.Parse(data)
	if err != nil {
		return nil, err
	}
	for i := 0; i < jwks.Len(); i++ {
		key, ok := jwks.Get(i)
		if !ok {
			break
		}
		if key.KeyType() != "RSA" {
			fmt.Printf("WARNING: Key %s has unexpected type %s\n", key.KeyID(), key.KeyType())
			continue
		}
		var rawKey rsa.PublicKey
		if err := key.Raw(&rawKey); err != nil {
			fmt.Printf("ERROR: Failed to get raw value for RSA key %s\n", key.KeyID())
			continue
		}
		result[key.KeyID()] = rawKey
	}
	return result, nil
}

func (c *client) parseAndVerifyJWT(ctx context.Context, accessToken string) (*jwt.Token, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		iss, err := token.Claims.GetIssuer()
		if err != nil || iss != c.jwtIssuer {
			return nil, ErrForeignToken
		}
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("missing 'kid' header")
		}
		key, err := c.retrieveSigningKey(ctx, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve signing key with id %s: %w", kid, err)
		}
		return key, nil
	})
	if errors.Is(err, jwt.ErrTokenMalformed) {
		return nil, ErrForeignToken
	}
	return token, err
}
