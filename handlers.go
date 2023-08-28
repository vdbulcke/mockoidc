package mockoidc

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/golang-jwt/jwt/v4"
)

const (
	IssuerBase                         = "/oidc"
	AuthorizationEndpoint              = "/oidc/authorize"
	IntrospectEndpoint                 = "/oidc/introspect"
	PushedAuthorizationRequestEndpoint = "/oidc/par"
	TokenEndpoint                      = "/oidc/token"
	UserinfoEndpoint                   = "/oidc/userinfo"
	JWKSEndpoint                       = "/oidc/.well-known/jwks.json"
	DiscoveryEndpoint                  = "/oidc/.well-known/openid-configuration"

	InvalidRequest       = "invalid_request"
	InvalidClient        = "invalid_client"
	InvalidGrant         = "invalid_grant"
	UnsupportedGrantType = "unsupported_grant_type"
	InvalidScope         = "invalid_scope"
	//UnauthorizedClient = "unauthorized_client"
	InternalServerError = "internal_server_error"

	applicationJSON = "application/json; charset=utf-8"
	openidScope     = "openid"
)

var (
	GrantTypesSupported = []string{
		"authorization_code",
		"refresh_token",
		"client_credentials",
	}
	ResponseTypesSupported = []string{
		"code",
	}
	SubjectTypesSupported = []string{
		"public",
	}
	IDTokenSigningAlgValuesSupported = []string{
		"RS256",
	}
	ScopesSupported = []string{
		"openid",
		"email",
		"groups",
		"profile",
	}
	TokenEndpointAuthMethodsSupported = []string{
		"client_secret_basic",
		"client_secret_post",
	}
	ClaimsSupported = []string{
		"sub",
		"email",
		"email_verified",
		"preferred_username",
		"phone_number",
		"address",
		"groups",
		"iss",
		"aud",
	}
)

// https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2
type PARResponse struct {
	RequestUri string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// PAR handles Pushed Authorization Request
//
//	stores PAR request in session store for later use on
//	the authorization endpoint
//
// returns a request_uri and expiration
func (m *MockOIDC) PAR(rw http.ResponseWriter, req *http.Request) {

	// parse PAR request
	body := req.Body
	defer body.Close()

	d := json.NewDecoder(body)
	var parReq *PARSession
	err := d.Decode(&parReq)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	// validate Request
	if !m.validPARRequest(rw, parReq) {
		return
	}

	reqID, err := m.SessionStore.StorePARRequest(parReq)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	parResp := &PARResponse{
		RequestUri: reqID,
		ExpiresIn:  120,
	}

	resp, err := json.Marshal(parResp)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	noCache(rw)
	// PAR Response MUST be 201
	jsonResponseWithStatusCode(rw, resp, http.StatusCreated)

}

// Authorize implements the `authorization_endpoint` in the OIDC flow.
// if request_contains 'request_uri' then looks up PAR request from session store
//
//	and ignores all other parameters
//
// else handles all authorization parameters directly.
// It is the initial request that "authenticates" a user in the OAuth2
// flow and redirects the client to the application `redirect_uri`.
func (m *MockOIDC) Authorize(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	var nonce, scope, state, redirect_uri, codeChallenge, codeChallengeMethod string

	// if PAR
	if req.Form.Get("request_uri") != "" {
		// mandatory client_id ?
		// validClient := assertEqual("client_id", m.ClientID,
		// 	InvalidClient, "Invalid client id", rw, req)
		// if !validClient {
		// 	return
		// }

		// get PAR request from store
		parReq, err := m.SessionStore.GetPARRequestByID(req.Form.Get("request_uri"))
		if err != nil {
			internalServerError(rw, err.Error())
			return
		}

		scope = parReq.Scopes
		nonce = parReq.Nonce
		state = parReq.State
		codeChallenge = parReq.CodeChallenge
		codeChallengeMethod = parReq.CodeChallengeMethod
		redirect_uri = parReq.RedirectURI

	} else {
		valid := assertPresence(
			[]string{"scope", "state", "client_id", "response_type", "redirect_uri"}, rw, req)
		if !valid {
			return
		}

		if !validateScope(rw, req) {
			return
		}
		validClient := assertEqual("client_id", m.ClientID,
			InvalidClient, "Invalid client id", rw, req)
		if !validClient {
			return
		}
		validType := assertEqual("response_type", "code",
			UnsupportedGrantType, "Invalid response type", rw, req)
		if !validType {
			return
		}
		if !validateCodeChallengeMethodSupported(rw, req.Form.Get("code_challenge_method"), m.CodeChallengeMethodsSupported) {
			return
		}

		scope = req.Form.Get("scope")
		nonce = req.Form.Get("nonce")
		state = req.Form.Get("state")
		codeChallenge = req.Form.Get("code_challenge")
		codeChallengeMethod = req.Form.Get("code_challenge_method")
		redirect_uri = req.Form.Get("redirect_uri")

	}

	session, err := m.SessionStore.NewSession(
		scope,
		nonce,
		m.UserQueue.Pop(),
		codeChallenge,
		codeChallengeMethod,
	)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	redirectURI, err := url.Parse(redirect_uri)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}
	params, _ := url.ParseQuery(redirectURI.RawQuery)
	params.Set("code", session.SessionID)
	params.Set("state", state)
	redirectURI.RawQuery = params.Encode()

	http.Redirect(rw, req, redirectURI.String(), http.StatusFound)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// Token implements the `token_endpoint` in OIDC and responds to requests
// from the application servers that contain the client ID & Secret along
// with the code from the `authorization_endpoint`. It returns the various
// OAuth tokens to the application server for the User authenticated by the
// during the `authorization_endpoint` request (persisted across requests via
// the `code`).
// Reference: https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
func (m *MockOIDC) Token(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	// validate client_id and grant_type
	if !m.validateMandatoryTokenParams(rw, req) {
		return
	}

	var (
		session *Session
		valid   bool
	)
	grantType := req.Form.Get("grant_type")
	switch grantType {
	case "authorization_code":
		// get authz code from session store
		if session, valid = m.validateCodeGrant(rw, req); !valid {
			return
		}

		// if not PKCE
		if session.CodeChallenge == "" || session.CodeChallengeMethod == "" {
			// validate client_secret
			if !m.validateClientSecret(rw, req) {
				return
			}

		}

		// if PKCE (this will return true if not PKCE)
		if !m.validateCodeChallenge(rw, req, session) {
			return
		}

	case "refresh_token":
		if session, valid = m.validateRefreshGrant(rw, req); !valid {
			return
		}
	case "client_credentials":

		scope := req.Form.Get("scope")
		// create a dummy session
		session, err = m.SessionStore.NewSession(
			scope,
			"",
			m.UserQueue.Pop(),
			"",
			"",
		)
		if err != nil {
			internalServerError(rw, err.Error())
			return
		}

	default:
		errorResponse(rw, InvalidRequest,
			fmt.Sprintf("Invalid grant type: %s", grantType), http.StatusBadRequest)
		return
	}

	tr := &tokenResponse{
		RefreshToken: req.Form.Get("refresh_token"),
		TokenType:    "bearer",
		ExpiresIn:    int(m.AccessTTL.Seconds()),
	}
	err = m.setTokens(tr, session, grantType)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	resp, err := json.Marshal(tr)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}
	noCache(rw)
	jsonResponse(rw, resp)
}

// Instrospect Implements token introspection endpoints
// Referene: https://www.rfc-editor.org/rfc/rfc7662.html
func (m *MockOIDC) Instrospect(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	// validate token param
	if !m.validateMandatoryIntrospectParams(rw, req) {
		return
	}

	t := req.Form.Get("token")

	// WARNING: Don't do this in prod,
	//          decode jwt without checking signature
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(t, jwt.MapClaims{})
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	// cast claims interface as MapClaims
	tokenClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		internalServerError(rw, "invalid claims format")
		return
	}

	// set introspect standard properties
	tokenClaims["active"] = true

	for k, v := range m.IntrospectTemplate {

		// template only works for string
		tpl, ok := v.(string)
		if ok {
			value, err := m.templateClaims(tpl, (*map[string]interface{})(&tokenClaims))
			if err != nil {
				internalServerError(rw, err.Error())
				return
			}

			tokenClaims[k] = value
		} else {
			tokenClaims[k] = v
		}

	}

	resp, err := json.Marshal(tokenClaims)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}
	noCache(rw)
	jsonResponse(rw, resp)
}

// templateClaims takes tpl go tempate and claims map and input
// returns templated string or an error
func (m *MockOIDC) templateClaims(tpl string, claims *map[string]interface{}) (string, error) {
	var out bytes.Buffer

	t, err := template.New("introspect").Parse(tpl)
	if err != nil {
		return "", err
	}

	err = t.Execute(&out, claims)
	if err != nil {
		return "", err
	}

	return out.String(), nil
}

func (m *MockOIDC) AdminClearCache(rw http.ResponseWriter, req *http.Request) {
	m.SessionStore.ClearCache()
	rw.Header().Set("X-Status", "cache-cleared")
	rw.WriteHeader(http.StatusOK)

}

func (m *MockOIDC) validateTokenParams(rw http.ResponseWriter, req *http.Request) bool {
	if !assertPresence([]string{"client_id", "client_secret", "grant_type"}, rw, req) {
		return false
	}

	equal := assertEqual("client_id", m.ClientID,
		InvalidClient, "Invalid client id", rw, req)
	if !equal {
		return false
	}
	equal = assertEqual("client_secret", m.ClientSecret,
		InvalidClient, "Invalid client secret", rw, req)
	if !equal {
		return false
	}

	return true
}

// validateMandatoryTokenParams mandatory paramaters
// PKCE and refresh_token flow do NOT require a client_secret
func (m *MockOIDC) validateMandatoryTokenParams(rw http.ResponseWriter, req *http.Request) bool {

	if !assertPresence([]string{"client_id", "grant_type"}, rw, req) {
		return false
	}

	equal := assertEqual("client_id", m.ClientID,
		InvalidClient, "Invalid client id", rw, req)
	if !equal {
		return false
	}

	return true
}

// validateMandatoryIntrospectParams mandatory paramaters
// for introspect endpoint
func (m *MockOIDC) validateMandatoryIntrospectParams(rw http.ResponseWriter, req *http.Request) bool {

	if !assertPresence([]string{"token"}, rw, req) {
		return false
	}

	return true
}

// validateClientSecret  paramater
func (m *MockOIDC) validateClientSecret(rw http.ResponseWriter, req *http.Request) bool {

	if !assertPresence([]string{"client_secret"}, rw, req) {
		return false
	}

	equal := assertEqual("client_secret", m.ClientSecret,
		InvalidClient, "Invalid client secret", rw, req)
	if !equal {
		return false
	}

	return true
}

// validPARRequest
func (m *MockOIDC) validPARRequest(rw http.ResponseWriter, req *PARSession) bool {

	mandatoryParam := []string{"client_id", "client_secret", "response_type", "redirect_uri", "scopes", "nonce", "state"}
	parMap := req.toMap()
	for _, p := range mandatoryParam {
		if _, ok := parMap[p]; !ok {
			errorResponse(rw, InvalidRequest, fmt.Sprintf("missing mandatory parameter %s", p), http.StatusUnauthorized)
			return false
		}

	}

	// validate Auth
	if m.ClientID != req.ClientID || m.ClientSecret != req.ClientSecret {
		errorResponse(rw, InvalidRequest, "wrong client_id/client_secret", http.StatusUnauthorized)
		return false
	}

	// validate scopes
	if !validateScopeParam(rw, req.Scopes) {
		return false
	}

	// PKCE
	if req.CodeChallenge != "" {
		if req.CodeChallengeMethod == "" {
			errorResponse(rw, InvalidRequest, fmt.Sprintf("missing mandatory parameter '%s' with  'code_challenge'", "code_challenge_method"), http.StatusUnauthorized)
			return false
		}

		validMethod := false
		for _, supportedMethod := range m.CodeChallengeMethodsSupported {
			if req.CodeChallengeMethod == supportedMethod {
				validMethod = true
			}
		}

		if !validMethod {
			errorResponse(rw, InvalidRequest, fmt.Sprintf("Unsupported 'code_challenge_method' '%s'", req.CodeChallengeMethod), http.StatusUnauthorized)
			return false
		}

	}

	return true
}

func (m *MockOIDC) validateCodeGrant(rw http.ResponseWriter, req *http.Request) (*Session, bool) {
	if !assertPresence([]string{"code"}, rw, req) {
		return nil, false
	}
	equal := assertEqual("grant_type", "authorization_code",
		UnsupportedGrantType, "Invalid grant type", rw, req)
	if !equal {
		return nil, false
	}

	code := req.Form.Get("code")
	session, err := m.SessionStore.GetSessionByID(code)
	if err != nil || session.Granted {
		errorResponse(rw, InvalidGrant, fmt.Sprintf("Invalid code: %s", code),
			http.StatusUnauthorized)
		return nil, false
	}
	session.Granted = true

	return session, true
}

func (m *MockOIDC) validateCodeChallenge(rw http.ResponseWriter, req *http.Request, session *Session) bool {
	if session.CodeChallenge == "" || session.CodeChallengeMethod == "" {
		return true
	}

	codeVerifier := req.Form.Get("code_verifier")
	if codeVerifier == "" {
		errorResponse(rw, InvalidGrant, "Invalid code verifier. Expected code but client sent none.", http.StatusUnauthorized)
		return false
	}

	challenge, err := GenerateCodeChallenge(session.CodeChallengeMethod, codeVerifier)
	if err != nil {
		errorResponse(rw, InvalidRequest, fmt.Sprintf("Invalid code verifier. %v", err.Error()), http.StatusUnauthorized)
		return false
	}

	if challenge != session.CodeChallenge {
		errorResponse(rw, InvalidGrant, "Invalid code verifier. Code challenge did not match hashed code verifier.", http.StatusUnauthorized)
		return false
	}

	return true
}

func (m *MockOIDC) validateRefreshGrant(rw http.ResponseWriter, req *http.Request) (*Session, bool) {
	if !assertPresence([]string{"refresh_token"}, rw, req) {
		return nil, false
	}

	equal := assertEqual("grant_type", "refresh_token",
		UnsupportedGrantType, "Invalid grant type", rw, req)
	if !equal {
		return nil, false
	}

	refreshToken := req.Form.Get("refresh_token")
	token, authorized := m.authorizeToken(refreshToken, rw)
	if !authorized {
		return nil, false
	}

	session, err := m.SessionStore.GetSessionByToken(token)
	if err != nil {
		errorResponse(rw, InvalidGrant, "Invalid refresh token",
			http.StatusUnauthorized)
		return nil, false
	}
	return session, true
}

func (m *MockOIDC) setTokens(tr *tokenResponse, s *Session, grantType string) error {
	var err error
	tr.AccessToken, err = s.AccessToken(m.Config(), m.CryptoBackend, m.Now())
	if err != nil {
		return err
	}
	if len(s.Scopes) > 0 && s.Scopes[0] == openidScope {
		tr.IDToken, err = s.IDToken(m.Config(), m.CryptoBackend, m.Now())
		if err != nil {
			return err
		}
	}

	// if IssueNewRefreshTokenOnRefreshToken => always generate a new refresh token
	// else only generate a new refresh token for grantType other than refresh_token
	if m.IssueNewRefreshTokenOnRefreshToken || grantType != "refresh_token" {
		tr.RefreshToken, err = s.RefreshToken(m.Config(), m.CryptoBackend, m.Now())
		if err != nil {
			return err
		}
	}
	return nil
}

// Userinfo returns the User details for the User associated with the passed
// Access Token. Data is scoped down to the session's access scope set in the
// initial `authorization_endpoint` call.
func (m *MockOIDC) Userinfo(rw http.ResponseWriter, req *http.Request) {
	token, authorized := m.authorizeBearer(rw, req)
	if !authorized {
		return
	}

	session, err := m.SessionStore.GetSessionByToken(token)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	resp, err := session.User.Userinfo(session.Scopes)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}
	jsonResponse(rw, resp)
}

type discoveryResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// https://www.rfc-editor.org/rfc/rfc9126.html#name-authorization-server-metada
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"  `
	TokenEndpoint                      string `json:"token_endpoint"`
	JWKSUri                            string `json:"jwks_uri"`
	UserinfoEndpoint                   string `json:"userinfo_endpoint"`
	IntrospectEndpoint                 string `json:"introspection_endpoint"`

	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// Discovery renders the OIDC discovery document and partial RFC-8414 authorization
// server metadata hosted at `/.well-known/openid-configuration`.
func (m *MockOIDC) Discovery(rw http.ResponseWriter, _ *http.Request) {
	discovery := &discoveryResponse{
		Issuer:                             m.Issuer(),
		AuthorizationEndpoint:              m.AuthorizationEndpoint(),
		TokenEndpoint:                      m.TokenEndpoint(),
		JWKSUri:                            m.JWKSEndpoint(),
		UserinfoEndpoint:                   m.UserinfoEndpoint(),
		PushedAuthorizationRequestEndpoint: m.PushedAuthorizationRequestEndpoint(),
		IntrospectEndpoint:                 m.IntrospectEndpoint(),

		GrantTypesSupported:               GrantTypesSupported,
		ResponseTypesSupported:            ResponseTypesSupported,
		SubjectTypesSupported:             SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  IDTokenSigningAlgValuesSupported,
		ScopesSupported:                   ScopesSupported,
		TokenEndpointAuthMethodsSupported: TokenEndpointAuthMethodsSupported,
		ClaimsSupported:                   ClaimsSupported,
		CodeChallengeMethodsSupported:     m.CodeChallengeMethodsSupported,
	}

	resp, err := json.Marshal(discovery)
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}
	jsonResponse(rw, resp)
}

// JWKS returns the public key in JWKS format to verify in tokens
// signed with our Keypair.PrivateKey.
func (m *MockOIDC) JWKS(rw http.ResponseWriter, _ *http.Request) {
	jwks, err := m.CryptoBackend.JWKS()
	if err != nil {
		internalServerError(rw, err.Error())
		return
	}

	jsonResponse(rw, jwks)
}

func (m *MockOIDC) authorizeBearer(rw http.ResponseWriter, req *http.Request) (*jwt.Token, bool) {
	header := req.Header.Get("Authorization")
	parts := strings.SplitN(header, " ", 2)
	if len(parts) < 2 || parts[0] != "Bearer" {
		errorResponse(rw, InvalidRequest, "Invalid authorization header",
			http.StatusUnauthorized)
		return nil, false
	}

	return m.authorizeToken(parts[1], rw)
}

func (m *MockOIDC) authorizeToken(t string, rw http.ResponseWriter) (*jwt.Token, bool) {
	token, err := m.CryptoBackend.VerifyJWT(t)
	if err != nil {
		errorResponse(rw, InvalidRequest, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		internalServerError(rw, "Unable to extract token claims")
		return nil, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		internalServerError(rw, "Unable to extract token expiration")
		return nil, false
	}
	if m.Now().Unix() > int64(exp) {
		errorResponse(rw, InvalidRequest, "The token is expired", http.StatusUnauthorized)
		return nil, false
	}
	return token, true
}

func assertPresence(params []string, rw http.ResponseWriter, req *http.Request) bool {
	for _, param := range params {
		if req.Form.Get(param) != "" {
			continue
		}
		errorResponse(
			rw,
			InvalidRequest,
			fmt.Sprintf("The request is missing the required parameter: %s", param),
			http.StatusBadRequest,
		)
		return false
	}
	return true
}

func assertEqual(param, value, errorType, errorMsg string, rw http.ResponseWriter, req *http.Request) bool {
	formValue := req.Form.Get(param)
	if subtle.ConstantTimeCompare([]byte(value), []byte(formValue)) == 0 {
		errorResponse(rw, errorType, fmt.Sprintf("%s: %s", errorMsg, formValue),
			http.StatusUnauthorized)
		return false
	}
	return true
}

func validateScope(rw http.ResponseWriter, req *http.Request) bool {
	allowed := make(map[string]struct{})
	for _, scope := range ScopesSupported {
		allowed[scope] = struct{}{}
	}

	scopes := strings.Split(req.Form.Get("scope"), " ")
	for _, scope := range scopes {
		if _, ok := allowed[scope]; !ok {
			errorResponse(rw, InvalidScope, fmt.Sprintf("Unsupported scope: %s", scope),
				http.StatusBadRequest)
			return false
		}
	}
	return true
}

func validateScopeParam(rw http.ResponseWriter, requestedScope string) bool {
	allowed := make(map[string]struct{})
	for _, scope := range ScopesSupported {
		allowed[scope] = struct{}{}
	}

	scopes := strings.Split(requestedScope, " ")
	for _, scope := range scopes {
		if _, ok := allowed[scope]; !ok {
			errorResponse(rw, InvalidScope, fmt.Sprintf("Unsupported scope: %s, must be one of %s", scope, ScopesSupported),
				http.StatusBadRequest)
			return false
		}
	}
	return true
}

func validateCodeChallengeMethodSupported(rw http.ResponseWriter, method string, supportedMethods []string) bool {
	if method != "" && !contains(method, supportedMethods) {
		errorResponse(rw, InvalidRequest, "Invalid code challenge method", http.StatusBadRequest)
		return false
	}
	return true
}

func errorResponse(rw http.ResponseWriter, error, description string, statusCode int) {
	errJSON := map[string]string{
		"error":             error,
		"error_description": description,
	}
	resp, err := json.Marshal(errJSON)
	if err != nil {
		http.Error(rw, error, http.StatusInternalServerError)
	}

	noCache(rw)
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(statusCode)

	_, err = rw.Write(resp)
	if err != nil {
		panic(err)
	}
}

func internalServerError(rw http.ResponseWriter, errorMsg string) {
	errorResponse(rw, InternalServerError, errorMsg, http.StatusInternalServerError)
}

func jsonResponse(rw http.ResponseWriter, data []byte) {
	noCache(rw)
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(http.StatusOK)

	_, err := rw.Write(data)
	if err != nil {
		panic(err)
	}
}

func jsonResponseWithStatusCode(rw http.ResponseWriter, data []byte, statusCode int) {
	noCache(rw)
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(statusCode)

	_, err := rw.Write(data)
	if err != nil {
		panic(err)
	}
}

func noCache(rw http.ResponseWriter) {
	rw.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
	rw.Header().Set("Pragma", "no-cache")
}

func contains(value string, list []string) bool {
	for _, element := range list {
		if element == value {
			return true
		}
	}
	return false
}
