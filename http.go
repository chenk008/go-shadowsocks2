package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	io_ "github.com/cobratbq/goutils/std/io"
	http_ "github.com/cobratbq/goutils/std/net/http"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

var ErrBlockedHost = errors.New("host is blocked")

type HTTPProxyHandler struct {
	server    string
	UserAgent string
	shadow    func(net.Conn) net.Conn
}

func localHTTP(addr, server string, shadow func(net.Conn) net.Conn) {
	logf("HTTP proxy %s <-> %s", addr, server)
	err := http.ListenAndServe(addr, &HTTPProxyHandler{server: server, shadow: shadow})
	if err != nil {
		logf("failed to listen %s: %v", addr, err)
	}
}

func (h *HTTPProxyHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	var err error
	switch req.Method {
	case "CONNECT":
		// it is https
		err = h.handleConnect(resp, req)
	default:
		err = h.processRequest(resp, req)
	}
	if err != nil {
		log.Println("Error serving proxy relay:", err.Error())
	}
}

func (h *HTTPProxyHandler) getConn() (net.Conn, error) {
	rc, err := net.Dial("tcp", h.server)
	if err != nil {
		return nil, err
	}
	if config.TCPCork {
		rc = timedCork(rc, 10*time.Millisecond, 1280)
	}

	rc = h.shadow(rc)
	return rc, nil
}

// TODO append body that explains the error as is expected from 5xx http status codes
func (h *HTTPProxyHandler) processRequest(resp http.ResponseWriter, req *http.Request) error {
	// TODO what to do when body of request is very large?
	body, err := ioutil.ReadAll(req.Body)
	defer req.Body.Close()
	logRequest(req)
	// Verification of requests is already handled by net/http library.
	// Establish connection with socks proxy
	rc, err := h.getConn()
	if err != nil {
		logf("failed to connect to server %v: %v", h.server, err)
		resp.WriteHeader(http.StatusInternalServerError)
		return err
	}
	defer rc.Close()
	targetHost := req.Host
	if !strings.Contains(targetHost, ":") {
		targetHost += ":80"
	}
	tgt := socks.ParseAddr(targetHost)
	logf("proxy %s <-> %s <-> %s", req.RemoteAddr, h.server, string(tgt))
	if _, err = rc.Write(tgt); err != nil {
		logf("failed to send target address: %v", err)
		return err
	}

	// Prepare request for socks proxy
	proxyReq, err := http.NewRequest(req.Method, req.RequestURI, bytes.NewReader(body))
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		return err
	}
	// Transfer headers to proxy request
	copyHeaders(proxyReq.Header, req.Header)
	if h.UserAgent != "" {
		// Add specified user agent as header.
		proxyReq.Header.Add("User-Agent", h.UserAgent)
	}
	// Send request to socks proxy
	if err = proxyReq.Write(rc); err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		return err
	}
	// Read proxy response
	proxyRespReader := bufio.NewReader(rc)
	proxyResp, err := http.ReadResponse(proxyRespReader, proxyReq)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		return err
	}
	// Transfer headers to client response
	copyHeaders(resp.Header(), proxyResp.Header)
	// Verification of response is already handled by net/http library.
	resp.WriteHeader(proxyResp.StatusCode)
	_, err = io.Copy(resp, proxyResp.Body)
	io_.CloseLogged(proxyResp.Body, "Error closing response body: %+v")
	return err
}

// TODO append body that explains the error as is expected from 5xx http status codes
func (h *HTTPProxyHandler) handleConnect(resp http.ResponseWriter, req *http.Request) error {
	defer io_.CloseLogged(req.Body, "Error while closing request body: %+v")
	logRequest(req)
	// Establish connection with socks proxy
	rc, err := h.getConn()
	if err != nil {
		logf("failed to connect to server %v: %v", h.server, err)
		resp.WriteHeader(http.StatusInternalServerError)
		return err
	}
	defer rc.Close()
	tgt := socks.ParseAddr(req.URL.Host)
	logf("proxy %s <-> %s <-> %s", req.RemoteAddr, h.server, tgt)
	if _, err = rc.Write(tgt); err != nil {
		logf("failed to send target address: %v", err)
		return err
	}

	// Acquire raw connection to the client
	clientInput, clientConn, err := http_.HijackConnection(resp)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		return err
	}
	defer io_.CloseLogged(clientConn, "Failed to close connection to local client: %+v")
	// Send 200 Connection established to client to signal tunnel ready
	// Responses to CONNECT requests MUST NOT contain any body payload.
	// TODO add additional headers to proxy server's response? (Via)
	_, err = clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		return err
	}
	// Start copying data from one connection to the other
	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(&wg, rc, clientInput)
	go transfer(&wg, clientConn, rc)
	wg.Wait()
	return nil
}

// log the request
func logRequest(req *http.Request) {
	logf("proto:%s, method:%s, host:%s", req.Proto, req.Method, req.Host)
}

const connectionHeader = "Connection"

var hopByHopHeaders = map[string]struct{}{
	connectionHeader:       {},
	"Keep-Alive":           {},
	"Proxy-Authorization":  {},
	"Proxy-Authentication": {},
	"TE":                   {},
	"Trailer":              {},
	"Transfer-Encoding":    {},
	"Upgrade":              {},
}

func copyHeaders(dst http.Header, src http.Header) {
	var dynDropHdrs = map[string]struct{}{}
	if vals, ok := src[connectionHeader]; ok {
		for _, v := range vals {
			processConnectionHdr(dynDropHdrs, v)
		}
	}
	for k, vals := range src {
		// This assumes that Connection header is also an element of
		// hop-by-hop headers such that it will not be processed twice,
		// but instead is dropped with the others.
		if _, drop := hopByHopHeaders[k]; drop {
			continue
		} else if _, drop := dynDropHdrs[k]; drop {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// tokenPatternRegex is the raw string pattern that should be compiled.
const tokenPatternRegex = `^[\d\w\!#\$%&'\*\+\-\.\^_\|~` + "`" + `]+$`

// tokenPattern is the pattern of a valid token.
var tokenPattern = regexp.MustCompile(tokenPatternRegex)

// processConnectionHdr processes the Connection header and adds all headers
// listed in value as droppable headers.
func processConnectionHdr(dropHdrs map[string]struct{}, value string) []string {
	var bad []string
	parts := strings.Split(value, ",")
	for _, part := range parts {
		header := strings.TrimSpace(part)
		if tokenPattern.MatchString(header) {
			dropHdrs[header] = struct{}{}
		} else {
			bad = append(bad, header)
		}
	}
	return bad
}

// transfer may be launched as goroutine. It that copies all content from one
// connection to the next.
func transfer(wg *sync.WaitGroup, dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src)
	// Skip all error handling, because we simply cannot distinguish between
	// expected and unexpected events. Logging this will only produce noise.
	wg.Done()
}
