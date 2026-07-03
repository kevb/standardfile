package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v5"
	argon2 "github.com/mdouchement/simple-argon2"
	"github.com/mdouchement/standardfile/internal/model"
	"github.com/mdouchement/standardfile/internal/server"
	sessionpkg "github.com/mdouchement/standardfile/internal/server/session"
	"github.com/mdouchement/standardfile/pkg/libsf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fastjson"
)

func TestFilesDisabled(t *testing.T) {
	engine, ctrl, _, cleanup := setup()
	defer cleanup()

	_, session := createUserWithSession(ctrl)
	resp := request(engine, http.MethodPost, "/v1/files/valet-tokens", []byte(`{"operation":"read","resources":[]}`), map[string]string{
		"Authorization": "Bearer " + accessToken(ctrl, session),
		"Content-Type":  "application/json",
	})

	assert.NotEqual(t, http.StatusOK, resp.Code)
}

func TestFilesValetTokenValidation(t *testing.T) {
	engine, ctrl, _, cleanup := setupFiles(t)
	defer cleanup()

	_, session := createUserWithSession(ctrl)
	auth := "Bearer " + accessToken(ctrl, session)
	fileID := uuid.Must(uuid.NewV4()).String()

	resp := request(engine, http.MethodPost, "/v1/files/valet-tokens", []byte(`{"operation":"read","resources":[{"remoteIdentifier":"`+fileID+`"},{"remoteIdentifier":"`+fileID+`"}]}`), map[string]string{
		"Authorization": auth,
		"Content-Type":  "application/json",
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.JSONEq(t, `{"success":false,"reason":"invalid-parameters"}`, resp.Body.String())

	resp = request(engine, http.MethodPost, "/v1/files/valet-tokens", []byte(`{"operation":"move","resources":[{"remoteIdentifier":"`+fileID+`"}]}`), map[string]string{
		"Authorization": auth,
		"Content-Type":  "application/json",
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.JSONEq(t, `{"success":false,"reason":"invalid-parameters"}`, resp.Body.String())

	resp = request(engine, http.MethodPost, "/v1/files/valet-tokens", []byte(`{"operation":"read","resources":[{"remoteIdentifier":"../escape"}]}`), map[string]string{
		"Authorization": auth,
		"Content-Type":  "application/json",
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.JSONEq(t, `{"success":false,"reason":"invalid-parameters"}`, resp.Body.String())
}

func TestFilesLifecycle(t *testing.T) {
	engine, ctrl, filesPath, cleanup := setupFiles(t)
	defer cleanup()

	user, session := createUserWithSession(ctrl)
	auth := "Bearer " + accessToken(ctrl, session)
	fileID := uuid.Must(uuid.NewV4()).String()

	writeToken := valetToken(t, engine, auth, "write", fileID, 10)
	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/create-session", nil, map[string]string{
		"x-valet-token": writeToken,
	}).Code)

	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/chunk", []byte("hello"), map[string]string{
		"x-valet-token": writeToken,
		"x-chunk-id":    "1",
		"Content-Type":  "application/octet-stream",
	}).Code)
	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/chunk", []byte("world"), map[string]string{
		"x-valet-token": writeToken,
		"x-chunk-id":    "2",
		"Content-Type":  "application/octet-stream",
	}).Code)
	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/chunk", []byte("WORLD"), map[string]string{
		"x-valet-token": writeToken,
		"x-chunk-id":    "2",
		"Content-Type":  "application/octet-stream",
	}).Code)

	resp := request(engine, http.MethodPost, "/v1/files/upload/close-session", nil, map[string]string{
		"x-valet-token": writeToken,
	})
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.JSONEq(t, `{"success":true,"message":"File uploaded successfully"}`, resp.Body.String())
	assert.FileExists(t, filepath.Join(filesPath, user.ID, fileID))

	readToken := valetToken(t, engine, auth, "read", fileID, 0)
	resp = request(engine, http.MethodGet, "/v1/files", nil, map[string]string{
		"x-valet-token": readToken,
		"x-chunk-size":  "5",
		"Range":         "bytes=0-",
	})
	assert.Equal(t, http.StatusPartialContent, resp.Code)
	assert.Equal(t, "bytes", resp.Header().Get("Accept-Ranges"))
	assert.Equal(t, "bytes 0-4/10", resp.Header().Get("Content-Range"))
	assert.Equal(t, "hello", resp.Body.String())

	resp = request(engine, http.MethodGet, "/v1/files", nil, map[string]string{
		"x-valet-token": readToken,
		"x-chunk-size":  "100",
		"Range":         "bytes=5-",
	})
	assert.Equal(t, http.StatusPartialContent, resp.Code)
	assert.Equal(t, "bytes 5-9/10", resp.Header().Get("Content-Range"))
	assert.Equal(t, "WORLD", resp.Body.String())

	resp = request(engine, http.MethodGet, "/v1/files", nil, map[string]string{
		"x-valet-token": writeToken,
		"x-chunk-size":  "5",
		"Range":         "bytes=0-",
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)

	deleteToken := valetToken(t, engine, auth, "delete", fileID, 0)
	resp = request(engine, http.MethodDelete, "/v1/files", nil, map[string]string{
		"x-valet-token": deleteToken,
	})
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.JSONEq(t, `{"success":true}`, resp.Body.String())

	resp = request(engine, http.MethodGet, "/v1/files", nil, map[string]string{
		"x-valet-token": readToken,
		"x-chunk-size":  "5",
		"Range":         "bytes=0-",
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestFilesAcceptValetTokenQueryAndBody(t *testing.T) {
	engine, ctrl, _, cleanup := setupFiles(t)
	defer cleanup()

	_, session := createUserWithSession(ctrl)
	auth := "Bearer " + accessToken(ctrl, session)
	fileID := uuid.Must(uuid.NewV4()).String()
	writeToken := valetToken(t, engine, auth, "write", fileID, 4)

	resp := request(engine, http.MethodPost, "/v1/files/upload/create-session?valetToken="+writeToken, nil, nil)
	assert.Equal(t, http.StatusOK, resp.Code)

	resp = request(engine, http.MethodPost, "/v1/files/upload/close-session", []byte(`{"valetToken":"`+writeToken+`"}`), map[string]string{
		"Content-Type": "application/json",
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "no chunks")

	resp = request(engine, http.MethodPost, "/v1/files/upload/chunk", []byte(`{"valetToken":"`+writeToken+`"}`), map[string]string{
		"Content-Type": "application/json",
		"x-chunk-id":   "1",
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "Invalid valet token")
}

func TestFilesCrossUserIsolation(t *testing.T) {
	engine, ctrl, _, cleanup := setupFiles(t)
	defer cleanup()

	_, sessionA := createUserWithSession(ctrl)
	authA := "Bearer " + accessToken(ctrl, sessionA)
	_, sessionB := createUserWithSessionEmail(t, ctrl, "other@example.test")
	authB := "Bearer " + accessToken(ctrl, sessionB)
	fileID := uuid.Must(uuid.NewV4()).String()

	writeToken := valetToken(t, engine, authA, "write", fileID, 4)
	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/create-session", nil, map[string]string{"x-valet-token": writeToken}).Code)
	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/chunk", []byte("data"), map[string]string{
		"x-valet-token": writeToken,
		"x-chunk-id":    "1",
	}).Code)
	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/close-session", nil, map[string]string{"x-valet-token": writeToken}).Code)

	readTokenB := valetToken(t, engine, authB, "read", fileID, 0)
	resp := request(engine, http.MethodGet, "/v1/files", nil, map[string]string{
		"x-valet-token": readTokenB,
		"x-chunk-size":  "4",
		"Range":         "bytes=0-",
	})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}

func TestFilesRejectBadChunkAndRange(t *testing.T) {
	engine, ctrl, _, cleanup := setupFiles(t)
	defer cleanup()

	_, session := createUserWithSession(ctrl)
	auth := "Bearer " + accessToken(ctrl, session)
	fileID := uuid.Must(uuid.NewV4()).String()
	writeToken := valetToken(t, engine, auth, "write", fileID, 4)

	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/create-session", nil, map[string]string{"x-valet-token": writeToken}).Code)
	assert.Equal(t, http.StatusBadRequest, request(engine, http.MethodPost, "/v1/files/upload/chunk", []byte("data"), map[string]string{
		"x-valet-token": writeToken,
		"x-chunk-id":    "0",
	}).Code)

	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/chunk", []byte("data"), map[string]string{
		"x-valet-token": writeToken,
		"x-chunk-id":    "1",
	}).Code)
	assert.Equal(t, http.StatusOK, request(engine, http.MethodPost, "/v1/files/upload/close-session", nil, map[string]string{"x-valet-token": writeToken}).Code)

	readToken := valetToken(t, engine, auth, "read", fileID, 0)
	assert.Equal(t, http.StatusBadRequest, request(engine, http.MethodGet, "/v1/files", nil, map[string]string{
		"x-valet-token": readToken,
		"x-chunk-size":  "4",
	}).Code)
}

func TestFilesURLDiscovery(t *testing.T) {
	engine, ctrl, _, cleanup := setupFiles(t)
	defer cleanup()

	ctrl.SubscriptionPayload = []byte(`{"meta":{"auth":{}},"data":{"user":{}}}`)
	ctrl.FeaturesPayload = []byte(`{"meta":{"auth":{}},"data":{}}`)
	engine = server.EchoEngine(ctrl)

	user, session := createUserWithSession(ctrl)
	resp := request(engine, http.MethodGet, "/v1/users/"+user.ID+"/features", nil, map[string]string{
		"Authorization": "Bearer " + accessToken(ctrl, session),
	})
	assert.Equal(t, http.StatusOK, resp.Code)

	v, err := fastjson.Parse(resp.Body.String())
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:5000", string(v.Get("meta", "server", "filesServerUrl").GetStringBytes()))
}

func TestFilesURLDiscoveryWithoutSubscriptionPayload(t *testing.T) {
	engine, ctrl, _, cleanup := setupFiles(t)
	defer cleanup()

	user, session := createUserWithSession(ctrl)
	resp := request(engine, http.MethodGet, "/v1/users/"+user.ID+"/subscription", nil, map[string]string{
		"Authorization": "Bearer " + accessToken(ctrl, session),
	})
	assert.Equal(t, http.StatusOK, resp.Code)

	v, err := fastjson.Parse(resp.Body.String())
	require.NoError(t, err)
	assert.Equal(t, user.ID, string(v.Get("meta", "auth", "userUuid").GetStringBytes()))
	assert.Equal(t, "http://localhost:5000", string(v.Get("meta", "server", "filesServerUrl").GetStringBytes()))
	assert.Equal(t, user.ID, string(v.Get("data", "user", "uuid").GetStringBytes()))
	assert.Equal(t, user.Email, string(v.Get("data", "user", "email").GetStringBytes()))
}

func setupFiles(t *testing.T) (engine *echo.Echo, ctrl server.Controller, filesPath string, cleanup func()) {
	t.Helper()

	_, ctrl, _, baseCleanup := setup()
	filesPath = t.TempDir()
	ctrl.Files = server.FilesConfig{
		Enabled:       true,
		Path:          filesPath,
		PublicURL:     "http://localhost:5000",
		ValetTokenTTL: ctrl.AccessTokenExpirationTime,
		MaxChunkBytes: 5,
		QuotaBytes:    -1,
	}
	engine = server.EchoEngine(ctrl)

	return engine, ctrl, filesPath, baseCleanup
}

func valetToken(t *testing.T, engine *echo.Echo, auth, operation, fileID string, size int64) string {
	t.Helper()

	payload, err := json.Marshal(map[string]any{
		"operation": operation,
		"resources": []map[string]any{
			{
				"remoteIdentifier":    fileID,
				"unencryptedFileSize": size,
			},
		},
	})
	require.NoError(t, err)

	resp := request(engine, http.MethodPost, "/v1/files/valet-tokens", payload, map[string]string{
		"Authorization": auth,
		"Content-Type":  "application/json",
	})
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())

	v, err := fastjson.Parse(resp.Body.String())
	require.NoError(t, err)
	return string(v.Get("valetToken").GetStringBytes())
}

func request(engine *echo.Echo, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

func createUserWithSessionEmail(t *testing.T, ctrl server.Controller, email string) (*model.User, *model.Session) {
	t.Helper()

	password, err := argon2.GenerateFromPasswordString("password42", argon2.Default)
	require.NoError(t, err)

	user := model.NewUser()
	user.Email = email
	user.Version = libsf.ProtocolVersion4
	user.Password = password
	user.PasswordCost = 110000
	user.PasswordNonce = "nonce42"
	user.PasswordUpdatedAt = 0
	require.NoError(t, ctrl.Database.Save(user))

	session := &model.Session{
		APIVersion:   "20200115",
		UserAgent:    "Go-http-client/1.1",
		UserID:       user.ID,
		ExpireAt:     time.Now().Add(ctrl.RefreshTokenExpirationTime - 100*time.Millisecond).UTC(),
		AccessToken:  sessionpkg.SecureToken(8),
		RefreshToken: sessionpkg.SecureToken(8),
	}
	require.NoError(t, ctrl.Database.Save(session))
	return user, session
}
