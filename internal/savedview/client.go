package savedview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

type Client struct {
	endpoint *url.URL
	token    []byte
	client   *http.Client
}

func NewClient(endpoint string, token []byte, client *http.Client) (*Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !validToken(token) {
		return nil, errors.New("saved view client configuration is invalid")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{endpoint: parsed, token: append([]byte(nil), token...), client: client}, nil
}

func validToken(token []byte) bool {
	if len(token) < 32 || len(token) > 128 {
		return false
	}
	for _, char := range token {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func (c *Client) List(ctx context.Context, actor string, filter ListFilter) (Page, error) {
	if filter.Scope != "" && filter.Scope != ScopePersonal && filter.Scope != ScopeShared || filter.Page != "" && filter.Page != "live-traffic" {
		return Page{}, errors.New("saved view list request is invalid")
	}
	values := url.Values{}
	if filter.Scope != "" {
		values.Set("scope", string(filter.Scope))
	}
	if filter.Page != "" {
		values.Set("page", filter.Page)
	}
	var page Page
	if err := c.request(ctx, http.MethodGet, "/v1/saved-views", values, actor, nil, &page); err != nil {
		return Page{}, err
	}
	if page.Schema != SchemaVersion || len(page.Views) > MaxViewsPerRequest {
		return Page{}, errors.New("saved view service returned an invalid list")
	}
	for _, view := range page.Views {
		if err := ValidateView(view); err != nil || view.Scope == ScopePersonal && view.Owner != actor || filter.Scope != "" && view.Scope != filter.Scope || filter.Page != "" && view.Page != filter.Page {
			return Page{}, errors.New("saved view service returned a view outside the requested scope")
		}
	}
	return page, nil
}

func (c *Client) Get(ctx context.Context, actor, id string) (View, error) {
	if !ValidID(id) {
		return View{}, errors.New("saved view lookup is invalid")
	}
	var view View
	err := c.request(ctx, http.MethodGet, "/v1/saved-views/"+id, nil, actor, nil, &view)
	if err == nil && (ValidateView(view) != nil || view.ID != id || view.Scope == ScopePersonal && view.Owner != actor) {
		return View{}, errors.New("saved view service returned an invalid view")
	}
	return view, err
}

func (c *Client) Create(ctx context.Context, actor string, configuration Configuration) (View, error) {
	var view View
	err := c.request(ctx, http.MethodPost, "/v1/saved-views", nil, actor, configuration, &view)
	if err == nil && (ValidateView(view) != nil || view.Owner != actor || view.LastEditor != actor || view.Revision != 1) {
		return View{}, errors.New("saved view service returned an invalid created view")
	}
	return view, err
}

func (c *Client) Update(ctx context.Context, actor, id string, update Update) (View, error) {
	if !ValidID(id) || update.ExpectedRevision < 1 {
		return View{}, errors.New("saved view update request is invalid")
	}
	var view View
	err := c.request(ctx, http.MethodPut, "/v1/saved-views/"+id, nil, actor, update, &view)
	if err == nil && (ValidateView(view) != nil || view.ID != id || view.Owner != actor || view.LastEditor != actor || view.Revision != update.ExpectedRevision+1) {
		return View{}, errors.New("saved view service returned an invalid updated view")
	}
	return view, err
}

func (c *Client) Delete(ctx context.Context, actor, id string, expectedRevision int64) error {
	if !ValidID(id) || expectedRevision < 1 {
		return errors.New("saved view delete request is invalid")
	}
	values := url.Values{"expected_revision": {strconv.FormatInt(expectedRevision, 10)}}
	return c.request(ctx, http.MethodDelete, "/v1/saved-views/"+id, values, actor, nil, nil)
}

func (c *Client) History(ctx context.Context, actor, id string) (History, error) {
	if !ValidID(id) {
		return History{}, errors.New("saved view history request is invalid")
	}
	var history History
	err := c.request(ctx, http.MethodGet, "/v1/saved-views/"+id+"/history", nil, actor, nil, &history)
	if err != nil {
		return History{}, err
	}
	if history.Schema != SchemaVersion || history.ViewID != id || len(history.Versions) > MaxHistory {
		return History{}, errors.New("saved view service returned invalid history")
	}
	var prior int64 = 1<<63 - 1
	for _, version := range history.Versions {
		if version.Revision >= prior || version.Revision != version.Snapshot.Revision || version.Editor != version.Snapshot.LastEditor || version.ChangedAt.IsZero() || ValidateView(version.Snapshot) != nil {
			return History{}, errors.New("saved view service returned invalid history")
		}
		prior = version.Revision
	}
	return history, nil
}

func (c *Client) request(ctx context.Context, method, path string, values url.Values, actor string, body, destination any) error {
	if c == nil || c.endpoint == nil || c.client == nil || !ValidActor(actor) || !strings.HasPrefix(path, "/v1/saved-views") {
		return errors.New("saved view client request is invalid")
	}
	endpoint := *c.endpoint
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	if values != nil {
		endpoint.RawQuery = values.Encode()
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil || len(encoded) > 32<<10 {
			return errors.New("saved view request body is invalid or oversized")
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+string(c.token))
	request.Header.Set("X-ShakerProxy-Actor", actor)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("request saved view service: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusNoContent {
		var failure struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure)
		switch response.StatusCode {
		case http.StatusNotFound:
			return ErrNotFound
		case http.StatusConflict:
			if failure.Error.Code == "saved_view_limit" {
				return ErrLimit
			}
			return ErrConflict
		case http.StatusForbidden:
			return ErrForbidden
		case http.StatusBadRequest, http.StatusUnprocessableEntity:
			message := failure.Error.Message
			if len(message) > 512 {
				message = message[:512]
			}
			return &InvalidError{Message: message}
		default:
			return fmt.Errorf("saved view service returned HTTP %d", response.StatusCode)
		}
	}
	if destination == nil {
		if response.StatusCode != http.StatusNoContent {
			return errors.New("saved view service returned an unexpected response")
		}
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("saved view service returned an invalid content type")
	}
	limited := &io.LimitedReader{R: response.Body, N: maxResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N <= 0 {
		return errors.New("saved view service returned invalid or oversized JSON")
	}
	return nil
}
