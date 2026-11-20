package oauthserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

func (ts *OAuthClientTestSuite) mintApprovedCode(clientID uuid.UUID, user *models.User, verifier string) string {
	params := models.NewOAuthServerAuthorizationParams{
		ClientID:    clientID,
		RedirectURI: "https://example.com/callback",
		Scope:       "profile",
		TTL:         time.Hour,
	}
	if verifier != "" {
		challenge := sha256.Sum256([]byte(verifier))
		params.CodeChallenge = base64.RawURLEncoding.EncodeToString(challenge[:])
		params.CodeChallengeMethod = "S256"
	}
	auth := models.NewOAuthServerAuthorization(params)
	require.NoError(ts.T(), models.CreateOAuthServerAuthorization(ts.DB, auth))
	require.NoError(ts.T(), auth.SetUser(ts.DB, user.ID))

	req := httptest.NewRequest(http.MethodPost, "/oauth/authorizations/"+auth.AuthorizationID+"/consent",
		bytes.NewReader(consentBody(OAuthServerConsentActionApprove)))
	route := chi.NewRouteContext()
	route.URLParams.Add("authorization_id", auth.AuthorizationID)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, route)
	require.NoError(ts.T(), ts.Server.OAuthServerConsent(httptest.NewRecorder(), req.WithContext(shared.WithUser(ctx, user))))

	approved, err := models.FindOAuthServerAuthorizationByID(ts.DB, auth.AuthorizationID)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), approved.AuthorizationCode)
	return *approved.AuthorizationCode
}

func (ts *OAuthClientTestSuite) exchangeCode(client *models.OAuthServerClient, code, verifier string) error {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	ctx := shared.WithOAuthServerClient(req.Context(), client)
	params := &OAuthTokenParams{GrantType: GrantTypeAuthorizationCode, Code: code, CodeVerifier: verifier}
	return ts.Server.handleAuthorizationCodeGrant(ctx, httptest.NewRecorder(), req.WithContext(ctx), params)
}

func (ts *OAuthClientTestSuite) requireInvalidGrant(err error) {
	ts.T().Helper()
	var oauthErr *apierrors.OAuthError
	require.ErrorAs(ts.T(), err, &oauthErr)
	require.Equal(ts.T(), "invalid_grant", oauthErr.Err)
}

func (ts *OAuthClientTestSuite) TestAuthCodeReplayRace() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("replay-race@example.com")
	code := ts.mintApprovedCode(client.ID, user, "")

	const n = 10
	start := make(chan struct{})
	var wg sync.WaitGroup
	var success int32

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			<-start
			if err := ts.exchangeCode(client, code, ""); err == nil {
				atomic.AddInt32(&success, 1)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(ts.T(), int32(1), success, "authorization code must be single-use: expected exactly one successful redemption, got %d", success)

	_, err := models.FindOAuthServerAuthorizationByCode(ts.DB, code)
	assert.True(ts.T(), models.IsNotFoundError(err), "authorization code should be consumed after redemption")
}

func (ts *OAuthClientTestSuite) TestRevokeGrantRacesAuthCodeExchange() {
	client, _ := ts.createTestOAuthClient()
	user := ts.createTestUser("revoke-race@example.com")

	for i := 0; i < 10; i++ {
		code := ts.mintApprovedCode(client.ID, user, "")
		start := make(chan struct{})
		exchanged := make(chan error, 1)
		revoked := make(chan error, 1)
		go func() {
			<-start
			exchanged <- ts.exchangeCode(client, code, "")
		}()
		go func() {
			<-start
			revoked <- ts.revokeGrant(user, client.ID)
		}()
		close(start)

		exchangeErr, revokeErr := <-exchanged, <-revoked
		require.NoError(ts.T(), revokeErr)
		if exchangeErr != nil {
			ts.requireInvalidGrant(exchangeErr)
		}

		ts.requireInvalidGrant(ts.exchangeCode(client, code, ""))
		count, err := ts.DB.Q().Where("user_id = ? AND oauth_client_id = ?", user.ID, client.ID).Count(&models.Session{})
		require.NoError(ts.T(), err)
		require.Zero(ts.T(), count, "revocation must remove any session created by a winning exchange")
	}
}
