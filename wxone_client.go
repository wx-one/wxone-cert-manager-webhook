package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type wxOneClient struct {
	host   string
	tenant string
	http   *http.Client
	cookie string
}

func newWxOneClient(host, tenant string) *wxOneClient {
	h := strings.TrimSuffix(strings.TrimSpace(host), "/")
	return &wxOneClient{
		host:   h,
		tenant: tenant,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *wxOneClient) Login(ctx context.Context, username, password string) error {
	chBody, _, err := c.postJSON(ctx, c.host+"/challenge", map[string]string{
		"username": username,
	})
	if err != nil {
		return err
	}

	var ch map[string]any
	if err := json.Unmarshal(chBody, &ch); err != nil {
		return err
	}

	salt, _ := ch["salt"].(string)
	challenge, _ := ch["challenge"].(string)
	date, _ := ch["date"].(string)

	rounds := 1
	if rf, ok := ch["rounds"].(float64); ok && int(rf) > 0 {
		rounds = int(rf)
	}

	h := sha512.Sum512([]byte(strings.ToUpper(password) + salt))
	seed := challenge + date + c.tenant + hex.EncodeToString(h[:])
	h = sha512.Sum512([]byte(seed))

	for i := 1; i < rounds; i++ {
		seed = challenge + date + c.tenant + hex.EncodeToString(h[:])
		h = sha512.Sum512([]byte(seed))
	}

	hashedPassword := hex.EncodeToString(h[:])

	_, hdr, err := c.postJSON(ctx, c.host+"/login", map[string]string{
		"username": username,
		"password": hashedPassword,
	})
	if err != nil {
		return err
	}

	setCookie := hdr.Get("Set-Cookie")
	if setCookie == "" {
		return fmt.Errorf("missing Set-Cookie in login response")
	}
	parts := strings.Split(setCookie, ";")
	c.cookie = parts[0]
	return nil
}

func (c *wxOneClient) postJSON(
	ctx context.Context,
	url string,
	body any,
) ([]byte, http.Header, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, resp.Header, fmt.Errorf("http %d: %s",
			resp.StatusCode, string(rb))
	}

	return rb, resp.Header, nil
}
