// Public, inert fixtures only. No network, SDK, AWS or transport credential.
package main

import (
	"bytes"
	"context"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/session-manager-plugin/src/datachannel"
	"github.com/aws/session-manager-plugin/src/log"
	"github.com/aws/session-manager-plugin/src/message"
	"net"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

type poisonStringer struct{}

func (poisonStringer) String() string { panic("must never format arguments") }
func TestJSONDuplicatesAndUnknownFields(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":{"x":1,"x":2}}`, `[true] false`, `{"a":[{"x":1,"x":1}]}`} {
		if uniqueJSON([]byte(raw)) {
			t.Fatal("duplicate/trailing JSON admitted")
		}
	}
	for _, raw := range []string{`{"a":[true,{"b":"x"}]}`, `{}`, `[null]`} {
		if !uniqueJSON([]byte(raw)) {
			t.Fatal("valid bounded JSON refused")
		}
	}
}
func TestDiscardLoggerNeverFormats(t *testing.T) {
	l := closedLog{}
	p := poisonStringer{}
	l.Trace(p)
	l.Debug(p)
	l.Info(p)
	l.Warn(p)
	l.Tracef("%s", p)
	l.Debugf("%s", p)
	l.Infof("%s", p)
	l.Warnf("%s", p)
}
func TestRefusalChild(t *testing.T) {
	switch os.Getenv("ZUNDER_PUBLIC_INERT_TEST") {
	case "duplicate":
		var v map[string]int
		strict([]byte(`{"a":1,"a":2}`), &v)
	case "unknown":
		var v struct {
			Known int `json:"known"`
		}
		strict([]byte(`{"known":1,"extra":2}`), &v)
	case "port":
		portProperties([]byte(`{"portNumber":"22222","localPortNumber":"24001","type":"LocalPortForwarding","localUnixSocket":"/tmp/foreign"}`), 24001)
	case "legacy":
		portProperties([]byte(`{"portNumber":"22222","localPortNumber":"24001","type":"Shell"}`), 24001)
	case "logger":
		closedLog{}.Errorf("%s", poisonStringer{})
	case "empty-packet":
		(&ownedChannel{assertLive: func() {}}).OutputMessageHandler(closedLog{}, func() {}, "public", nil)
	default:
		return
	}
	t.Fatal("refusal branch returned")
}
func TestFatalRefusalsDoNotPrintInputsOrContinue(t *testing.T) {
	for _, test := range []string{"duplicate", "unknown", "port", "legacy", "logger", "empty-packet"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRefusalChild$")
		cmd.Env = []string{"ZUNDER_PUBLIC_INERT_TEST=" + test}
		raw, err := cmd.CombinedOutput()
		status, ok := err.(*exec.ExitError)
		if !ok || status.ExitCode() != 126 || len(bytes.TrimSpace(raw)) != 0 {
			t.Fatalf("fixed refusal behavior differs: %s", test)
		}
	}
}
func TestExactPortProperties(t *testing.T) {
	portProperties([]byte(`{"portNumber":"22222","localPortNumber":"24001","type":"LocalPortForwarding"}`), 24001)
}

type fakeConnection struct {
	sent          int
	writeDeadline time.Time
}

func (f *fakeConnection) SetWriteDeadline(deadline time.Time) error {
	f.writeDeadline = deadline
	return nil
}
func (f *fakeConnection) SetReadDeadline(time.Time) error { return nil }
func (f *fakeConnection) SetReadLimit(int64)              {}
func (f *fakeConnection) WriteMessage(int, []byte) error  { f.sent++; return nil }
func (f *fakeConnection) ReadMessage() (int, []byte, error) {
	panic("No actual reader allowed in public fixture")
}
func (f *fakeConnection) Close() error { return nil }
func TestExpiredDialCannotReleasePrivateHandshake(t *testing.T) {
	expired := false
	fake := &fakeConnection{}
	guard := func() {
		if expired {
			panic("public fixed expired marker")
		}
	}
	ws := &ownedWebsocket{assertLive: guard, deadline: func() time.Time { return time.Now().Add(time.Second) }, streamURL: "wss://public.invalid", signer: v4.NewSigner(), region: "eu-central-1",
		dial: func(context.Context, string, http.Header) (websocketConnection, error) {
			expired = true
			return fake, nil
		}}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expired dial admitted")
			}
		}()
		ws.Open(closedLog{})
		ws.SendMessage(closedLog{}, []byte("public token sentinel"), 1)
	}()
	if fake.sent != 0 {
		t.Fatal("handshake sent after cutoff")
	}
}
func TestPortCallbackReplacementCannotDereferenceUninitializedMux(t *testing.T) {
	received := false
	ws := &ownedWebsocket{assertLive: func() {}, onMessage: func(raw []byte) { received = bytes.Equal(raw, []byte("public ACK")) }}
	ws.SetOnMessage(func([]byte) { panic("uninitialized PortSession callback must not run") })
	ws.dispatch([]byte("public ACK"))
	if !received {
		t.Fatal("fixed original dispatcher did not receive ACK")
	}
}
func TestQueuedWriteChecksCutoffAfterSerialization(t *testing.T) {
	expired := false
	fake := &fakeConnection{}
	ws := &ownedWebsocket{opened: true, connection: fake, assertLive: func() {
		if expired {
			panic("public expired marker")
		}
	}, deadline: func() time.Time { return time.Now().Add(time.Second) }}
	ws.lock.Lock()
	finished := make(chan bool, 1)
	go func() {
		defer func() { finished <- recover() != nil }()
		ws.SendMessage(closedLog{}, []byte("public token sentinel"), 1)
	}()
	expired = true
	ws.lock.Unlock()
	if !<-finished || fake.sent != 0 {
		t.Fatal("serialized write crossed cutoff")
	}
}
func TestSocketWriteDeadlineIsBoundToOriginalAuthority(t *testing.T) {
	original := time.Now().Add(time.Second)
	fake := &fakeConnection{}
	ws := &ownedWebsocket{opened: true, connection: fake, assertLive: func() {}, deadline: func() time.Time { return original }}
	if ws.SendMessage(closedLog{}, []byte("public payload"), 1) != nil || fake.sent != 1 || !fake.writeDeadline.Equal(original) {
		t.Fatal("actual write did not use original deadline")
	}
}

type fakeDataChannel struct {
	datachannel.IDataChannel
	handler datachannel.OutputStreamDataMessageHandler
}

func (f *fakeDataChannel) RegisterOutputStreamHandler(h datachannel.OutputStreamDataMessageHandler, _ bool) {
	f.handler = h
}
func TestIncomingStreamHandlerWaitsForActualMuxInput(t *testing.T) {
	fake := &fakeDataChannel{}
	called := false
	c := &ownedChannel{IDataChannel: fake, assertLive: func() {}}
	c.RegisterOutputStreamHandler(func(log.T, message.ClientMessage) (bool, error) { called = true; return true, nil }, true)
	ready, err := fake.handler(closedLog{}, message.ClientMessage{})
	if ready || err != nil || called {
		t.Fatal("uninitialized stream handler invoked")
	}
	c.streamsReady.Store(true)
	ready, err = fake.handler(closedLog{}, message.ClientMessage{})
	if !ready || err != nil || !called {
		t.Fatal("initialized handler not invoked")
	}
}

type fakeSocket struct {
	net.Conn
	sent                        int
	writeDeadline, readDeadline time.Time
}

func (s *fakeSocket) Write(raw []byte) (int, error)      { s.sent++; return len(raw), nil }
func (s *fakeSocket) SetWriteDeadline(v time.Time) error { s.writeDeadline = v; return nil }
func (s *fakeSocket) SetReadDeadline(v time.Time) error  { s.readDeadline = v; return nil }
func (s *fakeSocket) SetDeadline(v time.Time) error {
	s.writeDeadline = v
	s.readDeadline = v
	return nil
}
func TestActualSocketChecksOriginalCutoffBelowLibraryLocks(t *testing.T) {
	expired := false
	original := time.Now().Add(time.Second)
	sock := &fakeSocket{}
	connection := &deadlineConnection{Conn: sock, assertLive: func() {
		if expired {
			panic("public fixed expired marker")
		}
	}, deadline: func() time.Time { return original }}
	connection.SetWriteDeadline(original.Add(time.Hour))
	if !sock.writeDeadline.Equal(original) {
		t.Fatal("library extended original socket deadline")
	}
	connection.Write([]byte("public token sentinel"))
	if sock.sent != 1 || !sock.writeDeadline.Equal(original) {
		t.Fatal("actual socket boundary differs")
	}
	expired = true
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expired actual socket write admitted")
			}
		}()
		connection.Write([]byte("public token sentinel"))
	}()
	if sock.sent != 1 {
		t.Fatal("actual socket released bytes after cutoff")
	}
}

func TestSocketDeadlinePreservesFractionalOriginalUTCCutoff(t *testing.T) {
	sampled := time.Unix(1234, 500000999)
	cutoff := int64(1234501)
	deadline := originalSocketDeadline(sampled, sampled.Add(time.Second), cutoff)
	if !deadline.Equal(time.UnixMilli(cutoff)) || deadline.After(time.UnixMilli(cutoff)) {
		t.Fatal("fractional UTC authority extended")
	}
	projected := sampled.Add(time.UnixMilli(cutoff).Sub(sampled))
	if !projected.Equal(time.UnixMilli(cutoff)) {
		t.Fatal("initial monotonic projection extended UTC")
	}
	earlier := sampled.Add(time.Microsecond)
	if !originalSocketDeadline(sampled, earlier, cutoff).Equal(earlier) {
		t.Fatal("earlier monotonic cutoff ignored")
	}
}
