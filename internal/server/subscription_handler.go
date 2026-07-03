package server

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/valyala/fastjson"
)

type subscription struct {
	SubscriptionPayload []byte
	FeaturesPayload     []byte
	FilesServerURL      string
}

func (h *subscription) SubscriptionV1(c *echo.Context) error {
	user := currentUser(c)

	// The official Standard Notes client has a race condition,
	// the features endpoint will only be called when delaying response...
	time.Sleep(1 * time.Second)

	// Overrides some fields of the raw payload to match the current user.
	payload := h.SubscriptionPayload
	if len(payload) == 0 {
		payload = []byte(`{"meta":{"auth":{}},"data":{"user":{}}}`)
	}
	v, err := fastjson.ParseBytes(payload)
	if err != nil {
		return err
	}
	h.setMetaAuthUserUUID(v, user.ID)
	h.setFilesServerURL(v)
	v.Get("data", "user").Set("uuid", new(fastjson.Arena).NewString(user.ID))
	v.Get("data", "user").Set("email", new(fastjson.Arena).NewString(user.Email))

	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	return c.String(http.StatusOK, v.String())
}

func (h *subscription) Features(c *echo.Context) error {
	user := currentUser(c)

	// Overrides some fields of the raw payload to match the current user.
	payload := h.FeaturesPayload
	if len(payload) == 0 {
		payload = []byte(`{"meta":{"auth":{}},"data":{}}`)
	}
	v, err := fastjson.ParseBytes(payload)
	if err != nil {
		return err
	}
	h.setMetaAuthUserUUID(v, user.ID)
	h.setFilesServerURL(v)
	v.Get("data").Set("userUuid", new(fastjson.Arena).NewString(user.ID))

	c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	return c.String(http.StatusOK, v.String())
}

func (h *subscription) setMetaAuthUserUUID(v *fastjson.Value, userID string) {
	arena := new(fastjson.Arena)
	meta := v.Get("meta")
	if meta == nil {
		meta = arena.NewObject()
		v.Set("meta", meta)
	}
	auth := meta.Get("auth")
	if auth == nil {
		auth = arena.NewObject()
		meta.Set("auth", auth)
	}
	auth.Set("userUuid", arena.NewString(userID))
}

func (h *subscription) setFilesServerURL(v *fastjson.Value) {
	if h.FilesServerURL == "" {
		return
	}

	arena := new(fastjson.Arena)
	meta := v.Get("meta")
	if meta == nil {
		meta = arena.NewObject()
		v.Set("meta", meta)
	}
	server := meta.Get("server")
	if server == nil {
		server = arena.NewObject()
		meta.Set("server", server)
	}
	server.Set("filesServerUrl", arena.NewString(h.FilesServerURL))
}
