package dev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bmizerany/pat"
)

type HTTPServer struct {
	Address            string
	TLSAddress         string
	Pool               *AppPool
	Debug              bool
	Events             *Events
	IgnoredStaticPaths []string
	Domains            []string

	mux           *pat.PatternServeMux
	unixTransport *http.Transport
	unixProxy     *httputil.ReverseProxy
	tcpTransport  *http.Transport
	tcpProxy      *httputil.ReverseProxy
}

const (
	dialerTimeout         = 5 * time.Second
	keepAlive             = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	expectContinueTimeout = 1 * time.Second
	proxyFlushInternal    = 1 * time.Second
)

func (h *HTTPServer) Setup() {
	h.unixTransport = &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			socketPath, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			dialer := net.Dialer{
				Timeout:   dialerTimeout,
				KeepAlive: keepAlive,
			}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
	}

	h.unixProxy = &httputil.ReverseProxy{
		Director:      func(_ *http.Request) {},
		Transport:     h.unixTransport,
		FlushInterval: proxyFlushInternal,
	}

	h.tcpTransport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialerTimeout,
			KeepAlive: keepAlive,
		}).DialContext,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
	}

	h.tcpProxy = &httputil.ReverseProxy{
		Director:      func(_ *http.Request) {},
		Transport:     h.tcpTransport,
		FlushInterval: proxyFlushInternal,
	}

	h.Pool.AppClosed = h.AppClosed

	h.mux = pat.New()

	h.mux.Get("/status", http.HandlerFunc(h.status))
	h.mux.Get("/events", http.HandlerFunc(h.events))
}

func (h *HTTPServer) AppClosed(app *App) {
	// Whenever an app is closed, wipe out all idle conns. This
	// obviously closes down more than just this one apps connections
	// but that's ok.
	h.unixTransport.CloseIdleConnections()
	h.tcpTransport.CloseIdleConnections()
}

func (h *HTTPServer) removeTLD(host string) string {
	colon := strings.LastIndexByte(host, ':')
	if colon != -1 {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}

	if strings.HasSuffix(host, ".xip.io") || strings.HasSuffix(host, ".nip.io") {
		parts := strings.Split(host, ".")
		if len(parts) < 6 {
			return ""
		}

		name := strings.Join(parts[:len(parts)-6], ".")

		return name
	}

	// h.Domains is sorted by decreasing complexity
	for _, tld := range h.Domains {
		if strings.HasSuffix(host, "."+tld) {
			return strings.TrimSuffix(host, "."+tld)
		}
	}

	dot := strings.LastIndexByte(host, '.')

	if dot == -1 {
		return host
	} else {
		return host[:dot]
	}
}

func (h *HTTPServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if h.Debug {
		fmt.Fprintf(os.Stderr, "%s: %s '%s' (host=%s)\n",
			time.Now().Format(time.RFC3339Nano),
			req.Method, req.URL.Path, req.Host)
	}

	if req.Host == "puma-dev" {
		h.mux.ServeHTTP(w, req)
		return
	}

	name := h.removeTLD(req.Host)

	// Check for API requests.
	apiPattern := regexp.MustCompile(`^api\.(pco|churchcenter)\.(test|codes)$`)
	apiMatch := apiPattern.FindStringSubmatch(req.Host)
	if apiMatch != nil {
		// Both api.pco.test and api.churchcenter.test go to the API app by default,
		// but we need to check the path to be sure.
		v2Pattern := regexp.MustCompile(`^\/([\w-]+)\/v2`)
		v2Match := v2Pattern.FindStringSubmatch(req.URL.Path)
		if v2Match != nil && v2Match[1] != "global" {
			// The path indicates a different app, e.g. /services/v2/
			// ...so we'll proxy to that app instead.
			name = fmt.Sprintf("%s.pco", v2Match[1])
			// We have to change the host header to match the app to which we're sending the request.
			req.Header.Set("Host", fmt.Sprintf("%s.pco.test", v2Match[1]))
			req.Header.Set("X-PCO-API-Engine-Host", req.Host)
		} else {
			// This is a plain request to the API app.
			name = "api.pco"
		}
	}

	// Check for Church Center requests.
	ccAppPattern := regexp.MustCompile(`^\/(giving|groups|people|publishing|registrations)`)
	ccPattern := regexp.MustCompile(`^([\w-]+)\.churchcenter\.(test|codes)$`)
	ccSubdomainMatch := ccPattern.FindStringSubmatch(req.Host)
	if ccSubdomainMatch != nil && ccSubdomainMatch[1] != "api" {
		ccPathMatch := ccAppPattern.FindStringSubmatch(req.URL.Path)
		if ccPathMatch != nil {
			// This is a request for a specific Church Center app.
			name = fmt.Sprintf("%s.pco", ccPathMatch[1])
			// We have to change the host header to match the app to which we're sending the request.
			req.Header.Set("Host", fmt.Sprintf("%s.pco.test", ccPathMatch[1]))
			// The path needs to be rewritten to include the subdomain and directory
			// so the app knows from whence this request actually came.
			req.URL.Path = ccAppPattern.ReplaceAllString(req.URL.Path, "/church_center")
			// This matches `?foo=bar...` and captures the `foo=bar` part.
			paramsPattern := regexp.MustCompile(`\?(.*)$|$`)
			req.URL.Path = paramsPattern.ReplaceAllString(req.URL.Path,
				fmt.Sprintf("?church_center_directory=%s&church_center_subdomain=%s&$1", ccPathMatch[1], ccSubdomainMatch[1]),
			)
		} else {
			// This is a plain request to the Church Center app itself.
			name = "churchcenter"
		}
	}

	// Check to see if the path starts with ~api or ~ccapi.
	squigglyPattern := regexp.MustCompile(`^\/~(api|ccapi)\/([\w-]+)`)
	squigglyMatch := squigglyPattern.FindStringSubmatch(req.URL.Path)
	if squigglyMatch != nil {
		// Ahhh, this is a same-domain request in disguise! We need to proxy this
		// to a different app than the hostname indicates.
		name = fmt.Sprintf("%s.pco", squigglyMatch[2])
		req.Header.Set("Host", fmt.Sprintf("%s.pco.test", squigglyMatch[2]))
		req.Header.Set("X-PCO-API-Engine-Host", req.Host)
	}

	app, err := h.Pool.FindAppByDomainName(name)
	if err != nil {
		if err == ErrUnknownApp {
			h.Events.Add("unknown_app", "name", name, "host", req.Host)
		} else {
			h.Events.Add("lookup_error", "error", err.Error())
		}

		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}

	err = app.WaitTilReady()
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}

	if h.shouldServePublicPathForApp(app, req) {
		safeURLPath := path.Clean(req.URL.Path)
		path := filepath.Join(app.dir, "public", safeURLPath)

		fi, err := os.Stat(path)
		if err == nil && !fi.IsDir() {
			if ofile, err := os.Open(path); err == nil {
				http.ServeContent(w, req, req.URL.Path, fi.ModTime(), io.ReadSeeker(ofile))
				return
			}
		}
	}

	if req.TLS == nil {
		req.Header.Set("X-Forwarded-Proto", "http")
	} else {
		req.Header.Set("X-Forwarded-Proto", "https")
	}

	req.URL.Scheme, req.URL.Host = app.Scheme, app.Address()
	if app.Scheme == "httpu" {
		req.URL.Scheme, req.URL.Host = "http", app.Address()
		h.unixProxy.ServeHTTP(w, req)
	} else {
		req.URL.Scheme, req.URL.Host = app.Scheme, app.Address()
		h.tcpProxy.ServeHTTP(w, req)
	}
}

func (h *HTTPServer) shouldServePublicPathForApp(a *App, req *http.Request) bool {
	reqPath := path.Clean(req.URL.Path)

	if !a.Public {
		return false
	}

	if reqPath == "/" {
		return false
	}

	for _, ignoredPath := range h.IgnoredStaticPaths {
		if strings.HasPrefix(reqPath, ignoredPath) {
			if h.Debug {
				fmt.Fprintf(os.Stdout, "Not serving '%s' as it matches a path in no-serve-public-paths\n", reqPath)
			}
			return false
		}
	}

	return true
}

func (h *HTTPServer) status(w http.ResponseWriter, req *http.Request) {
	type appStatus struct {
		Scheme  string `json:"scheme"`
		Address string `json:"address"`
		Status  string `json:"status"`
		Log     string `json:"log"`
	}

	statuses := map[string]appStatus{}

	h.Pool.ForApps(func(a *App) {
		var status string

		switch a.Status() {
		case Dead:
			status = "dead"
		case Booting:
			status = "booting"
		case Running:
			status = "running"
		default:
			status = "unknown"
		}

		statuses[a.Name] = appStatus{
			Scheme:  a.Scheme,
			Address: a.Address(),
			Status:  status,
			Log:     a.Log(),
		}
	})

	json.NewEncoder(w).Encode(statuses)
}

func (h *HTTPServer) events(w http.ResponseWriter, req *http.Request) {
	h.Events.WriteTo(w)
}
