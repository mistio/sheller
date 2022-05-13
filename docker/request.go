package docker

import (
	"fmt"
	"net/http"
	"net/url"
)

func attachRequest(opts *attachOptions) (*http.Request, error) {
	//create empty url to be populated
	u := &url.URL{}
	u.Scheme = "https"
	u.Host = opts.Host + ":" + opts.Port
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("Unrecognised URL scheme in %v", u)
	}

	u.Path = fmt.Sprintf("/containers/%s/attach/ws", opts.MachineID)
	u.RawQuery = "logs=1&stdin=1&stdout=1"
	// todo: enable customized options

	return &http.Request{
		Method: http.MethodGet,
		URL:    u,
	}, nil
}
