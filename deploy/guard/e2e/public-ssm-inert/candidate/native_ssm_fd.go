// Prerelease tooling only. Fixed AWS PortSession reuse; no session token in argv.
// Upstream source: aws/session-manager-plugin@7cde6748cc6cffbc69546b4de08e603cd39be6d8.
// Caller must pin the compiled executable and complete upstream/vendor closure.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/session-manager-plugin/src/communicator"
	"github.com/aws/session-manager-plugin/src/config"
	"github.com/aws/session-manager-plugin/src/datachannel"
	"github.com/aws/session-manager-plugin/src/log"
	"github.com/aws/session-manager-plugin/src/message"
	"github.com/aws/session-manager-plugin/src/sessionmanagerplugin/session"
	"github.com/aws/session-manager-plugin/src/sessionmanagerplugin/session/portsession"
	"github.com/aws/session-manager-plugin/src/version"
	"github.com/gorilla/websocket"
)

// Never format upstream error values: some include StreamUrl or handshake data.
func refuse() { os.Exit(126) }
func need(v bool) {
	if !v {
		refuse()
	}
}

type closedLog struct{}

func (closedLog) Tracef(string, ...interface{})          {}
func (closedLog) Debugf(string, ...interface{})          {}
func (closedLog) Infof(string, ...interface{})           {}
func (closedLog) Warnf(string, ...interface{}) error     { return nil }
func (closedLog) Errorf(string, ...interface{}) error    { refuse(); return nil }
func (closedLog) Criticalf(string, ...interface{}) error { refuse(); return nil }
func (closedLog) Trace(...interface{})                   {}
func (closedLog) Debug(...interface{})                   {}
func (closedLog) Info(...interface{})                    {}
func (closedLog) Warn(...interface{}) error              { return nil }
func (closedLog) Error(...interface{}) error             { refuse(); return nil }
func (closedLog) Critical(...interface{}) error          { refuse(); return nil }
func (closedLog) Flush()                                 {}
func (closedLog) Close()                                 {}
func (closedLog) WithContext(...string) log.T            { return closedLog{} }

type publicPlan struct {
	Schema    int    `json:"schema"`
	Purpose   string `json:"purpose"`
	RunID     int64  `json:"run_id"`
	Attempt   int    `json:"attempt"`
	Source    string `json:"source"`
	Context   string `json:"context"`
	Challenge string `json:"challenge"`
	Instance  string `json:"instance"`
	LocalPort int    `json:"local_port"`
	StartedMS int64  `json:"started_ms"`
	UntilMS   int64  `json:"until_ms"`
	Scratch   string `json:"scratch"`
}
type privateInput struct {
	Response struct {
		SessionID string `json:"SessionId"`
		StreamURL string `json:"StreamUrl"`
		Token     string `json:"TokenValue"`
	} `json:"response"`
	Credentials struct {
		Access       string `json:"access_key_id"`
		Secret       string `json:"secret_access_key"`
		Token        string `json:"session_token"`
		ExpirationMS int64  `json:"expiration_ms"`
		Role         string `json:"role_arn"`
	} `json:"credentials"`
	PlanSHA string `json:"plan_sha256"`
}

func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) bool
	read = func(depth int) bool {
		if depth > 32 {
			return false
		}
		t, err := d.Token()
		if err != nil {
			return false
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return false
					}
					seen[name] = true
					if !read(depth + 1) {
						return false
					}
				}
				last, err := d.Token()
				return err == nil && last == json.Delim('}')
			case '[':
				for d.More() {
					if !read(depth + 1) {
						return false
					}
				}
				last, err := d.Token()
				return err == nil && last == json.Delim(']')
			default:
				return false
			}
		}
		return true
	}
	if !read(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
func strict(raw []byte, value interface{}) {
	need(uniqueJSON(raw))
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	need(d.Decode(value) == nil)
	var extra interface{}
	need(d.Decode(&extra) == io.EOF)
}

func protectedFile(path string, maximum int) []byte {
	need(filepath.IsAbs(path) && filepath.Clean(path) == path)
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		var info syscall.Stat_t
		need(syscall.Lstat(parent, &info) == nil && info.Mode&syscall.S_IFMT == syscall.S_IFDIR && info.Uid == 0 && info.Mode&0022 == 0)
		if parent == "/" {
			break
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	need(err == nil)
	f := os.NewFile(uintptr(fd), "public-plan")
	defer f.Close()
	var before, after, current syscall.Stat_t
	need(syscall.Fstat(fd, &before) == nil && before.Mode&syscall.S_IFMT == syscall.S_IFREG && before.Uid == 0 && before.Nlink == 1 && before.Mode&0022 == 0 && before.Size > 0 && before.Size <= int64(maximum))
	raw := frame(f, maximum)
	need(syscall.Fstat(fd, &after) == nil && syscall.Lstat(path, &current) == nil && sameStat(before, after) && sameStat(after, current) && int64(len(raw)) == before.Size)
	return raw
}

func sameStat(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func portProperties(raw []byte, localPort int) {
	var values map[string]string
	strict(raw, &values)
	for k, v := range values {
		need(k == "portNumber" || k == "localPortNumber" || k == "type" || (k == "localConnectionType" || k == "localUnixSocket") && v == "")
	}
	need(values["portNumber"] == "22222" && values["localPortNumber"] == strconv.Itoa(localPort) && values["type"] == "LocalPortForwarding")
}

// All callbacks, including PortSession's replacement callback, call this
// wrapper. Unexpected actions refuse BEFORE upstream KMS/legacy-shell dispatch.
type ownedChannel struct {
	datachannel.IDataChannel
	localPort            int
	requested, completed bool
	assertLive           func()
	streamsReady         atomic.Bool
}

func (c *ownedChannel) SendInputDataMessage(l log.T, payload message.PayloadType, raw []byte) error {
	c.assertLive()
	// PortSession's first mux input is produced only after InitializeStreams has
	// initialized both muxClient and mgsConn. Do not invoke its handler earlier.
	if payload == message.Output {
		c.streamsReady.Store(true)
	}
	return c.IDataChannel.SendInputDataMessage(l, payload, raw)
}
func (c *ownedChannel) RegisterOutputStreamHandler(handler datachannel.OutputStreamDataMessageHandler, specific bool) {
	if !specific {
		refuse()
	} // No legacy ProcessFirstMessage fallback.
	c.IDataChannel.RegisterOutputStreamHandler(func(l log.T, packet message.ClientMessage) (bool, error) {
		c.assertLive()
		if !c.streamsReady.Load() {
			return false, nil
		}
		return handler(l, packet)
	}, true)
}

// Retain this callback for the whole channel, including PortSession.Initialize.
// Its replacement callback would dereference an uninitialized muxClient on ACK.
type websocketConnection interface {
	SetWriteDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetReadLimit(int64)
	WriteMessage(int, []byte) error
	ReadMessage() (int, []byte, error)
	Close() error
}

// The check also lives at the actual socket boundary, below TLS/Gorilla's
// internal serialization and automatic control frames. No library writer may
// replace the original socket cutoff with its own later deadline.
func originalSocketDeadline(sampledNow time.Time, monotonicUntil time.Time, untilMS int64) time.Time {
	remaining := monotonicUntil.Sub(sampledNow)
	wall := time.UnixMilli(untilMS).Sub(sampledNow)
	if wall < remaining {
		remaining = wall
	}
	need(remaining > 0)
	return sampledNow.Add(remaining)
}

type deadlineConnection struct {
	net.Conn
	assertLive func()
	deadline   func() time.Time
}

func (c *deadlineConnection) bounded(value time.Time) time.Time {
	original := c.deadline()
	if value.IsZero() || original.Before(value) {
		return original
	}
	return value
}
func (c *deadlineConnection) Write(raw []byte) (int, error) {
	c.assertLive()
	need(c.Conn.SetWriteDeadline(c.deadline()) == nil)
	c.assertLive()
	return c.Conn.Write(raw)
}
func (c *deadlineConnection) SetWriteDeadline(value time.Time) error {
	return c.Conn.SetWriteDeadline(c.bounded(value))
}
func (c *deadlineConnection) SetReadDeadline(value time.Time) error {
	return c.Conn.SetReadDeadline(c.bounded(value))
}
func (c *deadlineConnection) SetDeadline(value time.Time) error {
	return c.Conn.SetDeadline(c.bounded(value))
}

type ownedWebsocket struct {
	assertLive                      func()
	deadline                        func() time.Time
	onMessage                       func([]byte)
	dial                            func(context.Context, string, http.Header) (websocketConnection, error)
	connection                      websocketConnection
	lock                            sync.Mutex
	channelToken, streamURL, region string
	signer                          *v4.Signer
	credentials                     aws.Credentials
	opened                          bool
}

var _ communicator.IWebSocketChannel = (*ownedWebsocket)(nil)

func (w *ownedWebsocket) Initialize(_ log.T, url, token, region string, signer *v4.Signer, credentials aws.Credentials) {
	w.assertLive()
	need(!w.opened && w.streamURL == "" && region == "eu-central-1" && signer != nil)
	w.streamURL = url
	w.channelToken = token
	w.region = region
	w.signer = signer
	w.credentials = credentials
}
func (w *ownedWebsocket) GetChannelToken() string        { return w.channelToken }
func (w *ownedWebsocket) GetStreamUrl() string           { return w.streamURL }
func (w *ownedWebsocket) SetChannelToken(string)         { refuse() }
func (w *ownedWebsocket) SetStreamUrl(string)            { refuse() }
func (w *ownedWebsocket) SetCredentials(aws.Credentials) { refuse() }
func (w *ownedWebsocket) Open(l log.T) error {
	w.assertLive()
	need(!w.opened && w.streamURL != "" && w.signer != nil)
	ctx, cancel := context.WithDeadline(context.Background(), w.deadline())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", w.streamURL, nil)
	need(err == nil)
	empty := sha256.Sum256(nil)
	w.assertLive()
	need(w.signer.SignHTTP(ctx, w.credentials, request, hex.EncodeToString(empty[:]), config.ServiceName, w.region, time.Now()) == nil)
	w.assertLive()
	connection, err := w.dial(ctx, w.streamURL, request.Header)
	w.assertLive()
	need(err == nil && connection != nil)
	w.connection = connection
	w.opened = true
	connection.SetReadLimit(1024 * 1024)
	need(connection.SetReadDeadline(w.deadline()) == nil)
	// Failure is immediately fatal; no read/reconnect retry or SDK provider.
	go func() {
		for {
			kind, raw, err := connection.ReadMessage()
			if err != nil {
				refuse()
			}
			need(kind == websocket.TextMessage || kind == websocket.BinaryMessage)
			w.dispatch(raw)
		}
	}()
	w.StartPings(l, config.PingTimeInterval)
	return nil
}
func (w *ownedWebsocket) dispatch(raw []byte) {
	w.assertLive()
	need(w.onMessage != nil)
	w.onMessage(raw)
}
func (w *ownedWebsocket) SendMessage(_ log.T, raw []byte, kind int) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	// All data and ping writers share this lock. There is no hidden upstream
	// mutex between this synchronous check and the bounded socket write.
	w.assertLive()
	need(w.opened && w.connection != nil && len(raw) > 0 && len(raw) <= 1024*1024)
	need(kind == websocket.TextMessage || kind == websocket.BinaryMessage || kind == websocket.PingMessage)
	need(w.connection.SetWriteDeadline(w.deadline()) == nil)
	w.assertLive()
	err := w.connection.WriteMessage(kind, raw)
	w.assertLive()
	return err
}
func (w *ownedWebsocket) StartPings(l log.T, interval time.Duration) {
	need(interval > 0)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			need(w.SendMessage(l, []byte("keepalive"), websocket.PingMessage) == nil)
		}
	}()
}
func (w *ownedWebsocket) Close(log.T) error {
	w.lock.Lock()
	defer w.lock.Unlock()
	need(w.opened && w.connection != nil)
	w.opened = false
	return w.connection.Close()
}
func (w *ownedWebsocket) SetOnError(func(error))    {} // Always fixed fatal, never replaced.
func (w *ownedWebsocket) SetOnMessage(func([]byte)) {} // Fixed original dispatcher.

func (c *ownedChannel) OutputMessageHandler(l log.T, stop datachannel.Stop, sid string, raw []byte) error {
	c.assertLive()
	need(len(raw) > 0 && len(raw) <= 1024*1024)
	var packet message.ClientMessage
	need(packet.DeserializeClientMessage(l, raw) == nil && packet.Validate() == nil)
	switch packet.MessageType {
	case message.OutputStreamMessage:
		switch message.PayloadType(packet.PayloadType) {
		case message.HandshakeRequestPayloadType:
			need(!c.requested && !c.completed)
			var request message.HandshakeRequestPayload
			strict(packet.Payload, &request)
			need(len(request.RequestedClientActions) == 1 && request.RequestedClientActions[0].ActionType == message.SessionType)
			need(version.DoesAgentSupportTCPMultiplexing(l, request.AgentVersion) && version.DoesAgentSupportTerminateSessionFlag(l, request.AgentVersion))
			var params struct {
				SessionType string          `json:"SessionType"`
				Properties  json.RawMessage `json:"Properties"`
			}
			strict(request.RequestedClientActions[0].ActionParameters, &params)
			need(params.SessionType == config.PortPluginName)
			portProperties(params.Properties, c.localPort)
			c.requested = true
		case message.HandshakeCompletePayloadType:
			need(c.requested && !c.completed)
			var complete message.HandshakeCompletePayload
			strict(packet.Payload, &complete)
			c.completed = true
		case message.Output, message.Flag:
			need(c.completed)
		default:
			refuse()
		}
	case message.AcknowledgeMessage, message.StartPublicationMessage, message.PausePublicationMessage:
	default:
		refuse() // Closed or unknown channel cannot provide readiness.
	}
	return c.IDataChannel.OutputMessageHandler(l, stop, sid, raw)
}
func pipe(fd int) *os.File {
	var s syscall.Stat_t
	need(syscall.Fstat(fd, &s) == nil && s.Mode&syscall.S_IFMT == syscall.S_IFIFO && s.Nlink == 0 && s.Uid == 62347)
	f := os.NewFile(uintptr(fd), "anonymous")
	need(f != nil)
	return f
}
func frame(f *os.File, limit int) []byte {
	raw, e := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	need(e == nil && len(raw) > 0 && len(raw) <= limit)
	return raw
}
func main() {
	defer func() {
		if recover() != nil {
			refuse()
		}
	}()
	need(os.Getuid() == 62347 && os.Getgid() == 62347 && len(os.Args) == 3)
	var limits syscall.Rlimit
	need(syscall.Getrlimit(syscall.RLIMIT_CORE, &limits) == nil && limits.Cur == 0 && limits.Max == 0)
	swaps, e := os.ReadFile("/proc/swaps")
	need(e == nil && len(strings.Split(strings.TrimSpace(string(swaps)), "\n")) == 1)
	// FD1/2 were already /dev/null in the guarded parent. Replace library output
	// handles too; arbitrary server CustomerMessage/ChannelClosed is discarded.
	null, e := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	need(e == nil)
	need(syscall.Dup2(int(null.Fd()), 1) == nil && syscall.Dup2(int(null.Fd()), 2) == nil)
	null.Close()
	os.Stdout = os.NewFile(1, "discarded")
	os.Stderr = os.NewFile(2, "discarded")
	ready := pipe(4)
	private := pipe(3)
	planRaw := protectedFile(os.Args[1], 8192)
	digest := sha256.Sum256(planRaw)
	need(hex.EncodeToString(digest[:]) == os.Args[2])
	var p publicPlan
	strict(planRaw, &p)
	hex64 := regexp.MustCompile("^[0-9a-f]{64}$")
	need(p.Schema == 1 && p.Purpose == "native-ssm-owned-port-session" && p.RunID > 0 && p.Attempt > 0 && p.Attempt <= 100 && regexp.MustCompile("^[0-9a-f]{40}$").MatchString(p.Source) && hex64.MatchString(p.Context) && hex64.MatchString(p.Challenge))
	need(regexp.MustCompile("^i-[0-9a-f]{17}$").MatchString(p.Instance) && p.LocalPort >= 20000 && p.LocalPort <= 60000)
	expectedScratch := fmt.Sprintf("/run/zunder-native-transport-%d-%d/%s/scratch", p.RunID, p.Attempt, p.Instance)
	need(p.Scratch == expectedScratch)
	var scratch syscall.Stat_t
	need(syscall.Lstat(p.Scratch, &scratch) == nil && scratch.Mode&syscall.S_IFMT == syscall.S_IFDIR && scratch.Uid == 0 && scratch.Gid == 62347 && scratch.Mode&0777 == 0770)
	entries, err := os.ReadDir(p.Scratch)
	need(err == nil && len(entries) == 0)
	for parent := filepath.Dir(p.Scratch); ; parent = filepath.Dir(parent) {
		var info syscall.Stat_t
		need(syscall.Lstat(parent, &info) == nil && info.Mode&syscall.S_IFMT == syscall.S_IFDIR && info.Uid == 0 && info.Mode&0022 == 0)
		if parent == "/" {
			break
		}
	}
	// No ambient AWS/config/proxy/Go diagnostics survive into the plugin. The
	// parent must already supply this clean environment before process startup.
	for _, item := range os.Environ() {
		key := strings.SplitN(item, "=", 2)[0]
		need(key == "PATH" || key == "LANG" || key == "HOME" || key == "TMPDIR")
	}
	need(os.Getenv("PATH") == "/usr/bin:/bin" && os.Getenv("LANG") == "C.UTF-8" && os.Getenv("HOME") == "/nonexistent" && os.Getenv("TMPDIR") == p.Scratch)
	sampledNow := time.Now()
	now := sampledNow.UnixMilli()
	need(p.StartedMS <= now && now < p.UntilMS && p.UntilMS <= p.StartedMS+6000000)
	until := sampledNow.Add(time.UnixMilli(p.UntilMS).Sub(sampledNow))
	assertLive := func() {
		now := time.Now().UnixMilli()
		need(p.StartedMS <= now && now < p.UntilMS && time.Now().Before(until))
	}
	go func() {
		for {
			assertLive()
			time.Sleep(100 * time.Millisecond)
		}
	}()
	raw := frame(private, 65536)
	private.Close()
	var secret privateInput
	strict(raw, &secret)
	for i := range raw {
		raw[i] = 0
	}
	need(secret.PlanSHA == os.Args[2] && secret.Credentials.Role == "arn:aws:iam::436632189317:role/zunder-release-native-host-control" && secret.Credentials.ExpirationMS >= p.UntilMS)
	for _, v := range []string{secret.Credentials.Access, secret.Credentials.Secret, secret.Credentials.Token} {
		need(len(v) > 0 && len(v) <= 8192 && regexp.MustCompile("^[A-Za-z0-9/+=._-]+$").MatchString(v))
	}
	need(regexp.MustCompile("^[A-Za-z0-9_.:@-]{1,200}$").MatchString(secret.Response.SessionID) && len(secret.Response.Token) > 0 && len(secret.Response.Token) <= 16384)
	u, e := url.Parse(secret.Response.StreamURL)
	need(e == nil && u.Scheme == "wss" && u.Host == "ssmmessages.eu-central-1.amazonaws.com" && u.User == nil && u.Fragment == "" && u.RawPath == "" && u.Path == "/v1/data-channel/"+secret.Response.SessionID)
	query, e := url.ParseQuery(u.RawQuery)
	need(e == nil && len(query) == 1 && len(query["role"]) == 1 && query.Get("role") == "publish_subscribe")
	l := closedLog{}
	dc := &ownedChannel{IDataChannel: &datachannel.DataChannel{}, localPort: p.LocalPort, assertLive: assertLive}
	client := make([]byte, 16)
	_, e = rand.Read(client)
	need(e == nil)
	client[6] = (client[6] & 15) | 64
	client[8] = (client[8] & 63) | 128
	clientID := fmt.Sprintf("%x-%x-%x-%x-%x", client[:4], client[4:6], client[6:8], client[8:10], client[10:])
	s := session.Session{DataChannel: dc, SessionId: secret.Response.SessionID, StreamUrl: secret.Response.StreamURL, TokenValue: secret.Response.Token, TargetId: p.Instance, Region: "eu-central-1", Endpoint: "https://ssm.eu-central-1.amazonaws.com", ClientId: clientID, IsAwsCliUpgradeNeeded: true, Signer: v4.NewSigner(), Credentials: aws.Credentials{AccessKeyID: secret.Credentials.Access, SecretAccessKey: secret.Credentials.Secret, SessionToken: secret.Credentials.Token, CanExpire: true, Expires: time.UnixMilli(secret.Credentials.ExpirationMS)}}
	// Use only exported channel primitives. No Session.Execute/OpenDataChannel,
	// retry/resume callback, default SDK provider, legacy first-message handler,
	// or SDK termination scheduler is installed by this call graph.
	assertLive()
	dc.Initialize(l, s.ClientId, s.SessionId, s.TargetId, true)
	deadline := func() time.Time {
		assertLive()
		return originalSocketDeadline(time.Now(), until, p.UntilMS)
	}
	ws := &ownedWebsocket{assertLive: assertLive, deadline: deadline, dial: func(ctx context.Context, url string, headers http.Header) (websocketConnection, error) {
		dialer := websocket.Dialer{Proxy: nil, HandshakeTimeout: 30 * time.Second, NetDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			assertLive()
			conn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, address)
			assertLive()
			if err != nil {
				return nil, err
			}
			return &deadlineConnection{Conn: conn, assertLive: assertLive, deadline: deadline}, nil
		}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		conn, response, err := dialer.DialContext(ctx, url, headers)
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return conn, err
	}, onMessage: func(input []byte) { need(dc.OutputMessageHandler(l, refuse, s.SessionId, input) == nil) }}
	dc.SetWsChannel(ws)
	dc.SetWebsocket(l, s.StreamUrl, s.TokenValue, s.Region, s.Signer, s.Credentials)
	dc.GetWsChannel().SetOnError(func(error) { refuse() })
	dc.GetWsChannel().SetOnMessage(func(input []byte) { assertLive(); need(dc.OutputMessageHandler(l, refuse, s.SessionId, input) == nil) })
	assertLive()
	need(dc.Open(l) == nil)
	assertLive()
	need(dc.ResendStreamDataMessageScheduler(l) == nil)
	go func() { <-dc.IsStreamMessageResendTimeout(); refuse() }()
	select {
	case ok := <-s.DataChannel.IsSessionTypeSet():
		need(ok)
	case <-time.After(30 * time.Second):
		refuse()
	}
	assertLive()
	need(s.DataChannel.GetSessionType() == config.PortPluginName)
	agent := s.DataChannel.GetAgentVersion()
	need(version.DoesAgentSupportTCPMultiplexing(l, agent) && version.DoesAgentSupportTerminateSessionFlag(l, agent))
	props := s.DataChannel.GetSessionProperties()
	encoded, e := json.Marshal(props)
	need(e == nil && len(encoded) <= 8192)
	portProperties(encoded, p.LocalPort)
	s.SessionType = config.PortPluginName
	s.SessionProperties = props
	port := portsession.PortSession{}
	port.Initialize(l, &s)
	assertLive()
	// Negotiation is only a public observation. Parent independently verifies
	// listener ownership and SSH host key before any native private frame.
	_, e = fmt.Fprintf(ready, "{\"kind\":\"actual-native-ssm-port-negotiated\",\"plan_sha256\":\"%s\",\"pid\":%d}\n", os.Args[2], os.Getpid())
	need(e == nil)
	ready.Close()
	need(port.SetSessionHandlers(l) == nil)
	refuse() // Unexpected normal return is not lifecycle or cleanup evidence.
}
