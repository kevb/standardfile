package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v5"
	"github.com/mdouchement/standardfile/internal/server/session"
	"github.com/o1egl/paseto/v2"
)

const (
	fileValetAudience = "file_valet_token"

	fileOperationRead   = "read"
	fileOperationWrite  = "write"
	fileOperationDelete = "delete"
)

type FilesConfig struct {
	Enabled       bool
	Path          string
	PublicURL     string
	ValetTokenTTL time.Duration
	MaxChunkBytes int64
	QuotaBytes    int64
}

type files struct {
	config FilesConfig
	secret []byte
}

type fileValetTokenRequest struct {
	Operation string                   `json:"operation"`
	Resources []fileValetTokenResource `json:"resources"`
}

type fileValetTokenResource struct {
	RemoteIdentifier    string `json:"remoteIdentifier"`
	UnencryptedFileSize int64  `json:"unencryptedFileSize"`
}

type fileValetClaims struct {
	UserID              string
	RemoteIdentifier    string
	Operation           string
	UnencryptedFileSize int64
}

func newFiles(config FilesConfig, secret []byte) *files {
	if config.ValetTokenTTL == 0 {
		config.ValetTokenTTL = 30 * time.Minute
	}
	if config.MaxChunkBytes == 0 {
		config.MaxChunkBytes = 100000000
	}
	return &files{
		config: config,
		secret: secret,
	}
}

func (h *files) ValetTokens(c *echo.Context) error {
	var params fileValetTokenRequest
	if err := c.Bind(&params); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]any{
			"success": false,
			"reason":  "invalid-parameters",
		})
	}

	if len(params.Resources) != 1 || !isFileOperation(params.Operation) {
		return c.JSON(http.StatusBadRequest, map[string]any{
			"success": false,
			"reason":  "invalid-parameters",
		})
	}

	resource := params.Resources[0]
	if _, err := uuid.FromString(resource.RemoteIdentifier); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]any{
			"success": false,
			"reason":  "invalid-parameters",
		})
	}

	user := currentUser(c)
	if user == nil {
		return c.JSON(http.StatusUnauthorized, map[string]any{
			"error": map[string]any{
				"tag":     "invalid-auth",
				"message": "Invalid login credentials.",
			},
		})
	}

	now := time.Now().UTC()
	token := paseto.JSONToken{
		Issuer:     "standardfile",
		Audience:   fileValetAudience,
		Subject:    user.ID,
		Jti:        session.SecureToken(24),
		IssuedAt:   now,
		NotBefore:  now,
		Expiration: now.Add(h.config.ValetTokenTTL),
	}
	token.Set("remoteIdentifier", resource.RemoteIdentifier)
	token.Set("operation", params.Operation)
	token.Set("unencryptedFileSize", resource.UnencryptedFileSize)

	valetToken, err := paseto.Encrypt(h.secret, token, []byte{})
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]any{
		"success":    true,
		"valetToken": valetToken,
	})
}

func (h *files) CreateUploadSession(c *echo.Context) error {
	claims, err := h.readValetToken(c, fileOperationWrite)
	if err != nil {
		return fileAuthError(c, err)
	}

	root, err := h.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	if err := root.MkdirAll(h.partsDir(claims), 0700); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]any{
		"success":  true,
		"uploadId": claims.RemoteIdentifier,
	})
}

func (h *files) UploadChunk(c *echo.Context) error {
	claims, err := h.readValetToken(c, fileOperationWrite)
	if err != nil {
		return fileAuthError(c, err)
	}

	chunkID, err := parsePositiveInt(c.Request().Header.Get("x-chunk-id"))
	if err != nil {
		return fileBadRequest(c, "Missing or invalid x-chunk-id header.")
	}

	root, err := h.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	partsDir := h.partsDir(claims)
	if err := root.MkdirAll(partsDir, 0700); err != nil {
		return err
	}

	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, h.config.MaxChunkBytes)
	tempName := path.Join(partsDir, fmt.Sprintf("%d.tmp.%s", chunkID, randomHex(8)))
	f, err := root.OpenFile(tempName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(f, c.Request().Body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = root.Remove(tempName)
		if strings.Contains(copyErr.Error(), "request body too large") {
			return fileBadRequest(c, "Chunk is too large.")
		}
		return copyErr
	}
	if closeErr != nil {
		_ = root.Remove(tempName)
		return closeErr
	}

	if err := root.Rename(tempName, path.Join(partsDir, strconv.Itoa(chunkID))); err != nil {
		_ = root.Remove(tempName)
		return err
	}

	return c.JSON(http.StatusOK, map[string]any{
		"success": true,
	})
}

func (h *files) CloseUploadSession(c *echo.Context) error {
	claims, err := h.readValetToken(c, fileOperationWrite)
	if err != nil {
		return fileAuthError(c, err)
	}

	root, err := h.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	partsDir := h.partsDir(claims)
	entries, err := fs.ReadDir(root.FS(), partsDir)
	if err != nil {
		return fileBadRequest(c, "Upload session not found.")
	}

	ids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.Contains(entry.Name(), ".") {
			continue
		}
		id, err := strconv.Atoi(entry.Name())
		if err != nil || id < 1 {
			return fileBadRequest(c, "Upload session contains invalid chunks.")
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	if len(ids) == 0 {
		return fileBadRequest(c, "Upload session contains no chunks.")
	}
	for i, id := range ids {
		if id != i+1 {
			return fileBadRequest(c, "Upload session is missing chunks.")
		}
	}

	if err := root.MkdirAll(claims.UserID, 0700); err != nil {
		return err
	}

	finalPath := h.filePath(claims)
	tempPath := path.Join(claims.UserID, fmt.Sprintf(".%s.tmp.%s", claims.RemoteIdentifier, randomHex(8)))
	out, err := root.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	var size int64
	for _, id := range ids {
		part, err := root.Open(path.Join(partsDir, strconv.Itoa(id)))
		if err != nil {
			_ = out.Close()
			_ = root.Remove(tempPath)
			return err
		}
		n, copyErr := io.Copy(out, part)
		closeErr := part.Close()
		size += n
		if copyErr != nil {
			_ = out.Close()
			_ = root.Remove(tempPath)
			return copyErr
		}
		if closeErr != nil {
			_ = out.Close()
			_ = root.Remove(tempPath)
			return closeErr
		}
	}
	if err := out.Close(); err != nil {
		_ = root.Remove(tempPath)
		return err
	}

	if err := h.checkQuota(root, claims, size); err != nil {
		_ = root.Remove(tempPath)
		return fileBadRequest(c, err.Error())
	}

	if err := root.Rename(tempPath, finalPath); err != nil {
		_ = root.Remove(tempPath)
		return err
	}
	_ = root.RemoveAll(partsDir)

	return c.JSON(http.StatusOK, map[string]any{
		"success": true,
		"message": "File uploaded successfully",
	})
}

func (h *files) Download(c *echo.Context) error {
	claims, err := h.readValetToken(c, fileOperationRead)
	if err != nil {
		return fileAuthError(c, err)
	}

	chunkSize, err := parsePositiveInt64(c.Request().Header.Get("x-chunk-size"))
	if err != nil {
		return fileBadRequest(c, "Missing or invalid x-chunk-size header.")
	}
	if chunkSize > h.config.MaxChunkBytes {
		chunkSize = h.config.MaxChunkBytes
	}

	start, err := parseRangeStart(c.Request().Header.Get("Range"))
	if err != nil {
		return fileBadRequest(c, "Missing or invalid Range header.")
	}

	root, err := h.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	filePath := h.filePath(claims)
	info, err := root.Stat(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fileBadRequest(c, "File not found.")
		}
		return err
	}
	if start < 0 || start >= info.Size() {
		return fileBadRequest(c, "Invalid range.")
	}

	end := start + chunkSize - 1
	if end >= info.Size() {
		end = info.Size() - 1
	}
	length := end - start + 1

	f, err := root.Open(filePath)
	if err != nil {
		return err
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		_ = f.Close()
		return err
	}
	defer f.Close()

	c.Response().Header().Set("Accept-Ranges", "bytes")
	c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, info.Size()))
	c.Response().Header().Set(echo.HeaderContentLength, strconv.FormatInt(length, 10))
	return c.Stream(http.StatusPartialContent, "application/octet-stream", io.LimitReader(f, length))
}

func (h *files) Delete(c *echo.Context) error {
	claims, err := h.readValetToken(c, fileOperationDelete)
	if err != nil {
		return fileAuthError(c, err)
	}

	root, err := h.openRoot()
	if err != nil {
		return err
	}
	defer root.Close()

	if err := root.Remove(h.filePath(claims)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	_ = root.RemoveAll(h.partsDir(claims))

	return c.JSON(http.StatusOK, map[string]any{
		"success": true,
	})
}

func (h *files) readValetToken(c *echo.Context, operation string) (*fileValetClaims, error) {
	raw := c.Request().Header.Get("x-valet-token")
	if raw == "" {
		return nil, errors.New("missing valet token")
	}

	var token paseto.JSONToken
	if err := paseto.Decrypt(raw, h.secret, &token, nil); err != nil {
		return nil, err
	}
	if err := token.Validate(
		paseto.IssuedBy("standardfile"),
		paseto.ForAudience(fileValetAudience),
		paseto.ValidAt(time.Now()),
	); err != nil {
		return nil, err
	}

	var remoteIdentifier string
	if err := token.Get("remoteIdentifier", &remoteIdentifier); err != nil {
		return nil, err
	}
	var tokenOperation string
	if err := token.Get("operation", &tokenOperation); err != nil {
		return nil, err
	}
	var unencryptedFileSize int64
	_ = token.Get("unencryptedFileSize", &unencryptedFileSize)

	if tokenOperation != operation {
		return nil, errors.New("operation not permitted")
	}
	if _, err := uuid.FromString(token.Subject); err != nil {
		return nil, err
	}
	if _, err := uuid.FromString(remoteIdentifier); err != nil {
		return nil, err
	}

	return &fileValetClaims{
		UserID:              token.Subject,
		RemoteIdentifier:    remoteIdentifier,
		Operation:           tokenOperation,
		UnencryptedFileSize: unencryptedFileSize,
	}, nil
}

func (h *files) openRoot() (*os.Root, error) {
	return os.OpenRoot(h.config.Path)
}

func (h *files) filePath(claims *fileValetClaims) string {
	return path.Join(claims.UserID, claims.RemoteIdentifier)
}

func (h *files) partsDir(claims *fileValetClaims) string {
	return path.Join(claims.UserID, ".parts", claims.RemoteIdentifier)
}

func (h *files) checkQuota(root *os.Root, claims *fileValetClaims, newSize int64) error {
	if h.config.QuotaBytes < 0 {
		return nil
	}

	usage, err := h.userUsage(root, claims.UserID)
	if err != nil {
		return err
	}
	if info, err := root.Stat(h.filePath(claims)); err == nil {
		usage -= info.Size()
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if usage+newSize > h.config.QuotaBytes {
		return errors.New("File upload quota exceeded.")
	}
	return nil
}

func (h *files) userUsage(root *os.Root, userID string) (int64, error) {
	var total int64
	err := fs.WalkDir(root.FS(), userID, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == userID {
			return nil
		}
		if entry.IsDir() {
			if strings.HasPrefix(name, path.Join(userID, ".parts")) {
				return fs.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	return total, err
}

func isFileOperation(operation string) bool {
	switch operation {
	case fileOperationRead, fileOperationWrite, fileOperationDelete:
		return true
	default:
		return false
	}
}

func parsePositiveInt(value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		return 0, errors.New("invalid positive integer")
	}
	return n, nil
}

func parsePositiveInt64(value string) (int64, error) {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New("invalid positive integer")
	}
	return n, nil
}

func parseRangeStart(value string) (int64, error) {
	if !strings.HasPrefix(value, "bytes=") || !strings.HasSuffix(value, "-") {
		return 0, errors.New("invalid range")
	}
	return strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(value, "bytes="), "-"), 10, 64)
}

func fileAuthError(c *echo.Context, _ error) error {
	return c.JSON(http.StatusUnauthorized, map[string]any{
		"error": map[string]any{
			"tag":     "invalid-auth",
			"message": "Invalid valet token.",
		},
	})
}

func fileBadRequest(c *echo.Context, message string) error {
	return c.JSON(http.StatusBadRequest, map[string]any{
		"error": map[string]any{
			"tag":     "invalid-parameters",
			"message": message,
		},
	})
}

func randomHex(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
