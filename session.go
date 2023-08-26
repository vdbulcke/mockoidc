package mockoidc

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Session stores a User and their OIDC options across requests
type Session struct {
	SessionID           string
	Scopes              []string
	OIDCNonce           string
	User                User
	Granted             bool
	CodeChallenge       string
	CodeChallengeMethod string
}

// PARSession stores PAR request
type PARSession struct {
	RequestID           string
	ClientID            string `json:"client_id"`
	ClientSecret        string `json:"client_secret"`
	ResponseType        string `json:"response_type"`
	RedirectURI         string `json:"redirect_uri"`
	Scopes              string `json:"scope"`
	Nonce               string `json:"nonce"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	AcrValues           string `json:"acr_values"`
}

func (ps *PARSession) toMap() map[string]string {

	return map[string]string{
		"client_id":             ps.ClientID,
		"client_secret":         ps.ClientID,
		"response_type":         ps.ClientID,
		"redirect_uri":          ps.ClientID,
		"scopes":                ps.ClientID,
		"nonce":                 ps.ClientID,
		"code_challenge":        ps.ClientID,
		"code_challenge_method": ps.ClientID,
		"state":                 ps.State,
		"acr_values":            ps.ClientID,
	}

}

// SessionStore manages our Session objects
type SessionStore struct {
	Store     map[string]*Session
	PARstore  map[string]*PARSession
	CodeQueue *CodeQueue
}

// IDTokenClaims are the mandatory claims any User.Claims implementation
// should use in their jwt.Claims building.
type IDTokenClaims struct {
	Nonce string `json:"nonce,omitempty"`
	*jwt.RegisteredClaims
}

// NewSessionStore initializes the SessionStore for this server
func NewSessionStore() *SessionStore {
	return &SessionStore{
		Store:     make(map[string]*Session),
		PARstore:  make(map[string]*PARSession),
		CodeQueue: &CodeQueue{},
	}
}

// NewSession creates a new Session for a User
func (ss *SessionStore) NewSession(scope string, nonce string, user User, codeChallenge string, codeChallengeMethod string) (*Session, error) {
	sessionID, err := ss.CodeQueue.Pop()
	if err != nil {
		return nil, err
	}

	session := &Session{
		SessionID:           sessionID,
		Scopes:              strings.Split(scope, " "),
		OIDCNonce:           nonce,
		User:                user,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	ss.Store[sessionID] = session

	return session, nil
}

func (ss *SessionStore) StorePARRequest(parReq *PARSession) (string, error) {
	reqID, err := randomNonce(10)
	if err != nil {
		return "", err
	}
	parReq.RequestID = reqID

	ss.PARstore[reqID] = parReq

	return reqID, nil

}

func (ss *SessionStore) ClearCache() {
	ss.PARstore = make(map[string]*PARSession)
	ss.Store = make(map[string]*Session)
}

// GetSPARRequestByID looks up the PAR resuest
func (ss *SessionStore) GetPARRequestByID(id string) (*PARSession, error) {
	session, ok := ss.PARstore[id]
	if !ok {
		return nil, errors.New("PAR session not found")
	}
	delete(ss.PARstore, id)
	return session, nil
}

// GetSessionByID looks up the Session
func (ss *SessionStore) GetSessionByID(id string) (*Session, error) {
	session, ok := ss.Store[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

// GetSessionByToken decodes a token and looks up a Session based on the
// session ID claim.
func (ss *SessionStore) GetSessionByToken(token *jwt.Token) (*Session, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	sessionID := claims["jti"].(string)
	return ss.GetSessionByID(sessionID)
}

// AccessToken returns the JWT token with the appropriate claims for
// an access token
func (s *Session) AccessToken(config *Config, cb CryptoBackend, now time.Time) (string, error) {
	// get standard claims
	standardClaims := s.standardClaims(config, config.AccessTTL, now)

	// add user specific Access token claims
	claims, err := s.User.AccessTokenClaims(standardClaims)
	if err != nil {
		return "", err
	}

	return cb.SignJWT(claims)
}

// RefreshToken returns the JWT token with the appropriate claims for
// a refresh token
func (s *Session) RefreshToken(config *Config, cb CryptoBackend, now time.Time) (string, error) {
	// get standard claims
	standardClaims := s.standardClaims(config, config.AccessTTL, now)

	// add user specific Access token claims
	claims, err := s.User.RefreshTokenClaims(standardClaims)
	if err != nil {
		return "", err
	}

	return cb.SignJWT(claims)
}

// IDToken returns the JWT token with the appropriate claims for a user
// based on the scopes set.
func (s *Session) IDToken(config *Config, cb CryptoBackend, now time.Time) (string, error) {
	base := &IDTokenClaims{
		RegisteredClaims: s.standardClaims(config, config.AccessTTL, now),
		Nonce:            s.OIDCNonce,
	}
	claims, err := s.User.Claims(s.Scopes, base)
	if err != nil {
		return "", err
	}

	return cb.SignJWT(claims)
}

func (s *Session) standardClaims(config *Config, ttl time.Duration, now time.Time) *jwt.RegisteredClaims {
	return &jwt.RegisteredClaims{
		Audience:  []string{config.ClientID},
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		ID:        s.SessionID,
		IssuedAt:  jwt.NewNumericDate(now),
		Issuer:    config.Issuer,
		NotBefore: jwt.NewNumericDate(now),
		Subject:   s.User.ID(),
	}
}
