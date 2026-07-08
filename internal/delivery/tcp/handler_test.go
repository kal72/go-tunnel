package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	domainSetting "gotunnel/internal/domain/setting"
	domainUser "gotunnel/internal/domain/user"
	mockRegistry "gotunnel/internal/domain/tunnel/mocks"
	"gotunnel/internal/shared/protocol"
	"gotunnel/internal/shared/ratelimit"
	mockSetting "gotunnel/internal/usecase/setting/mocks"
	mockTunnel "gotunnel/internal/usecase/tunnel/mocks"
	mockUser "gotunnel/internal/usecase/user/mocks"

	"github.com/google/uuid"
	"github.com/hashicorp/yamux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

type mockHijacker struct {
	http.ResponseWriter
	conn net.Conn
	err  error
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	rw := bufio.NewReadWriter(bufio.NewReader(m.conn), bufio.NewWriter(m.conn))
	return m.conn, rw, nil
}

func makeYamuxPair() (*yamux.Session, *yamux.Session, func()) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	var srvSess *yamux.Session
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			srvSess, _ = yamux.Server(conn, nil)
		}
		close(done)
	}()
	clientConn, _ := net.Dial("tcp", ln.Addr().String())
	clientSess, _ := yamux.Client(clientConn, nil)
	<-done
	cleanup := func() {
		if clientSess != nil {
			_ = clientSess.Close()
		}
		if srvSess != nil {
			_ = srvSess.Close()
		}
		_ = ln.Close()
	}
	return clientSess, srvSess, cleanup
}

func TestNewServerJWT(t *testing.T) {
	mockReg := new(mockRegistry.MockHostRegistry)
	mockTun := new(mockTunnel.MockTunnelUsecase)
	mockAuth := new(mockUser.MockAuthUsecase)
	mockSet := new(mockSetting.MockSettingUsecase)

	srv, err := NewServerJWT("secret", mockReg, "dashboard.example.com", "*.example.com", mockTun, mockAuth, mockSet)
	assert.NoError(t, err)
	assert.NotNil(t, srv)
	assert.Equal(t, "dashboard.example.com", srv.dashboardDomain)
}

func TestCanonicalHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"example.com", "example.com"},
		{"EXAMPLE.COM:8080", "example.com"},
		{"  Sub.Domain.Com:443  ", "sub.domain.com"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, canonicalHost(tt.input))
	}
}

func TestCopyHeader(t *testing.T) {
	src := http.Header{}
	src.Add("X-Test", "value1")
	src.Add("X-Test", "value2")
	dst := http.Header{}

	copyHeader(dst, src)
	assert.Equal(t, []string{"value1", "value2"}, dst["X-Test"])
}

func TestVerifyAuthToken(t *testing.T) {
	mockAuth := new(mockUser.MockAuthUsecase)
	srv := &Server{authUsecase: mockAuth}

	mockAuth.On("VerifyToken", mock.Anything, "bad-token").Return(nil, errors.New("invalid"))
	u, err := srv.verifyAuthToken("bad-token")
	assert.Error(t, err)
	assert.Nil(t, u)

	expectedUser := &domainUser.User{Username: "john", Role: 0}
	mockAuth.On("VerifyToken", mock.Anything, "good-token").Return(expectedUser, nil)
	u, err = srv.verifyAuthToken("good-token")
	assert.NoError(t, err)
	assert.Equal(t, expectedUser, u)
}

func TestSessionForHost_and_ModeForHost(t *testing.T) {
	srv := &Server{hostToSes: map[string]*TunnelSession{}}

	assert.Nil(t, srv.sessionForHost("app.example.com"))
	assert.Nil(t, srv.sessionForHost("localhost"))

	ts1 := &TunnelSession{
		Modes: map[string]string{"app.example.com": "tcp", "*.example.com": "http"},
	}
	srv.hostToSes["app.example.com"] = ts1
	srv.hostToSes["*.example.com"] = ts1

	assert.Equal(t, ts1, srv.sessionForHost("app.example.com"))
	assert.Equal(t, ts1, srv.sessionForHost("sub.example.com"))
	assert.Nil(t, srv.sessionForHost("other.org"))

	var nilTS *TunnelSession
	assert.Equal(t, "http", nilTS.modeForHost("app.example.com"))

	tsNoModes := &TunnelSession{}
	assert.Equal(t, "http", tsNoModes.modeForHost("app.example.com"))

	assert.Equal(t, "tcp", ts1.modeForHost("app.example.com"))
	assert.Equal(t, "http", ts1.modeForHost("sub.example.com"))
	assert.Equal(t, "http", ts1.modeForHost("unknown.org"))
}

func TestActiveTunnelsForUser(t *testing.T) {
	sess1, srv1, clean1 := makeYamuxPair()
	defer clean1()
	sess2, srv2, clean2 := makeYamuxPair()
	defer clean2()
	_ = srv1
	_ = srv2

	srv := &Server{
		hostToSes: map[string]*TunnelSession{
			"h1.com": {Username: "john", Session: sess1},
			"h2.com": {Username: "john", Session: sess1}, // duplicate session same user
			"h3.com": {Username: "john", Session: sess2},
			"h4.com": {Username: "alice", Session: sess2},
		},
	}

	assert.Equal(t, 2, srv.activeTunnelsForUser("john"))
	assert.Equal(t, 1, srv.activeTunnelsForUser("alice"))
	assert.Equal(t, 0, srv.activeTunnelsForUser("bob"))
}

func TestUpdateState(t *testing.T) {
	srvNil := &Server{logger: zap.NewNop()}
	srvNil.updateState(&TunnelSession{}) // should not panic

	mockTun := new(mockTunnel.MockTunnelUsecase)
	srv := &Server{logger: zap.NewNop(), tunnelUsecase: mockTun}

	mockTun.On("RegisterTunnel", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	srv.updateState(&TunnelSession{Hostnames: map[string]struct{}{"h1.com": {}}})

	mockTun.On("RegisterTunnel", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("redis err")).Once()
	srv.updateState(&TunnelSession{})
}

func TestGetRateLimitConfig(t *testing.T) {
	srvNil := &Server{}
	cfg := srvNil.getRateLimitConfig(context.Background())
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 100, cfg.Rate)

	mockSet := new(mockSetting.MockSettingUsecase)
	expectedCfg := domainSetting.RateLimitConfig{Enabled: false, Rate: 50, Burst: 10}
	mockSet.On("GetRateLimitConfig", mock.Anything).Return(expectedCfg).Maybe()

	srv := &Server{settingUsecase: mockSet}
	c1 := srv.getRateLimitConfig(context.Background())
	assert.Equal(t, expectedCfg, c1)

	// Second call immediately uses cache
	c2 := srv.getRateLimitConfig(context.Background())
	assert.Equal(t, expectedCfg, c2)

	// Concurrent test to cover double-check lock (line 87)
	mockSetSleep := new(mockSetting.MockSettingUsecase)
	mockSetSleep.On("GetRateLimitConfig", mock.Anything).Run(func(args mock.Arguments) {
		time.Sleep(10 * time.Millisecond)
	}).Return(expectedCfg).Maybe()

	for iter := 0; iter < 5; iter++ {
		srv2 := &Server{settingUsecase: mockSetSleep}
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_ = srv2.getRateLimitConfig(context.Background())
			}()
		}
		close(start)
		wg.Wait()
	}
}

func makeTestTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  key,
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func TestListenTunnelTLS(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	lnErr, err := srv.ListenTunnelTLS("invalid-ip:999999", nil)
	assert.Error(t, err)
	assert.Nil(t, lnErr)

	tlsCfg := makeTestTLSConfig()
	ln, err := srv.ListenTunnelTLS("127.0.0.1:0", tlsCfg)
	assert.NoError(t, err)
	assert.NotNil(t, ln)

	// Dial TLS so accept loop runs
	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		_ = client.Close()
	}
	time.Sleep(50 * time.Millisecond)
	_ = ln.Close()
}

func TestCleanup(t *testing.T) {
	mockReg := new(mockRegistry.MockHostRegistry)
	mockTun := new(mockTunnel.MockTunnelUsecase)

	srv := &Server{
		logger:        zap.NewNop(),
		hostRegistry:  mockReg,
		tunnelUsecase: mockTun,
		hostToSes:     map[string]*TunnelSession{},
	}

	ts := &TunnelSession{
		Username:  "john",
		Role:      0,
		Hostnames: map[string]struct{}{"h1.com": {}, "h2.com": {}},
		Modes:     map[string]string{"h1.com": "http"},
	}

	otherTS := &TunnelSession{}
	srv.hostToSes["h1.com"] = ts
	srv.hostToSes["h2.com"] = otherTS

	mockReg.On("Unregister", "h1.com").Return(true).Once()
	mockTun.On("RemoveActiveDomain", mock.Anything, "h1.com").Return(nil).Once()
	mockTun.On("UnregisterTunnel", mock.Anything, mock.Anything).Return(nil).Once()
	mockTun.On("DeleteRateLimitSetting", mock.Anything, "john").Return(nil).Once()

	srv.cleanup(ts)

	_, existsH1 := srv.hostToSes["h1.com"]
	assert.False(t, existsH1)
	assert.Equal(t, otherTS, srv.hostToSes["h2.com"])
	mockReg.AssertExpectations(t)
	mockTun.AssertExpectations(t)
}

func TestCleanup_RemainingUserSessions(t *testing.T) {
	mockTun := new(mockTunnel.MockTunnelUsecase)
	srv := &Server{
		logger:        zap.NewNop(),
		tunnelUsecase: mockTun,
		hostToSes:     map[string]*TunnelSession{},
	}

	ts1 := &TunnelSession{Username: "john", Role: 0, Hostnames: map[string]struct{}{}}
	ts2 := &TunnelSession{Username: "john", Role: 0, Hostnames: map[string]struct{}{}}
	srv.hostToSes["other.com"] = ts2

	mockTun.On("UnregisterTunnel", mock.Anything, mock.Anything).Return(nil).Once()
	srv.cleanup(ts1)
	mockTun.AssertExpectations(t)
}

func TestServeHTTP_NoTunnel_Or_NoSession(t *testing.T) {
	srv := &Server{hostToSes: map[string]*TunnelSession{}}

	req := httptest.NewRequest(http.MethodGet, "http://missing.com/", http.NoBody)
	req.Host = "missing.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code)

	srv.hostToSes["nil-sess.com"] = &TunnelSession{Session: nil}
	req2 := httptest.NewRequest(http.MethodGet, "http://nil-sess.com/", http.NoBody)
	req2.Host = "nil-sess.com"
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusBadGateway, rec2.Code)
}

func TestServeHTTP_OpenStreamError(t *testing.T) {
	agentSess, srvSess, clean := makeYamuxPair()
	defer clean()
	_ = agentSess.Close()
	_ = srvSess.Close() // close server session directly so OpenStream immediately fails

	srv := &Server{
		hostToSes: map[string]*TunnelSession{
			"closed.com": {Session: srvSess},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://closed.com/", http.NoBody)
	req.Host = "closed.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

func TestServeHTTP_HTTPMode_Success(t *testing.T) {
	agentSess, srvSess, clean := makeYamuxPair()
	defer clean()

	mockTun := new(mockTunnel.MockTunnelUsecase)
	mockTun.On("PublishInspectEvent", mock.Anything, "app.com", mock.Anything).Return(nil).Maybe()

	srv := &Server{
		logger:        zap.NewNop(),
		tunnelUsecase: mockTun,
		hostToSes: map[string]*TunnelSession{
			"app.com": {Session: srvSess, Modes: map[string]string{"app.com": "http"}},
		},
	}

	go func() {
		stream, err := agentSess.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = protocol.ReadDataHeader(stream)
		_, _ = http.ReadRequest(bufio.NewReader(stream))

		respStr := "HTTP/1.1 200 OK\r\nX-Custom: test-val\r\nContent-Length: 5\r\n\r\nworld"
		_, _ = stream.Write([]byte(respStr))
	}()

	req := httptest.NewRequest(http.MethodGet, "http://app.com/hello", http.NoBody)
	req.Host = "app.com"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test-val", rec.Header().Get("X-Custom"))
	assert.Equal(t, "world", rec.Body.String())
	time.Sleep(50 * time.Millisecond)
}

func TestServeHTTP_TCPMode(t *testing.T) {
	agentSess, srvSess, clean := makeYamuxPair()
	defer clean()
	_ = agentSess

	srv := &Server{
		logger: zap.NewNop(),
		hostToSes: map[string]*TunnelSession{
			"tcp.com": {Session: srvSess, Modes: map[string]string{"tcp.com": "tcp"}},
		},
	}

	// 1. Hijacking not supported
	req := httptest.NewRequest(http.MethodGet, "http://tcp.com/", http.NoBody)
	req.Host = "tcp.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	// 2. Hijack returns error
	recHijackErr := &mockHijacker{ResponseWriter: httptest.NewRecorder(), err: errors.New("hijack err")}
	srv.ServeHTTP(recHijackErr, req)

	// 3. Hijack success over real TCP pipe with clean yamux session
	agentSess2, srvSess2, clean2 := makeYamuxPair()
	defer clean2()
	srv.hostToSes["tcp.com"].Session = srvSess2

	clientLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer clientLn.Close()
	var serverConn net.Conn
	doneConn := make(chan struct{})
	go func() {
		serverConn, _ = clientLn.Accept()
		close(doneConn)
	}()
	clientConn, _ := net.Dial("tcp", clientLn.Addr().String())
	defer clientConn.Close()
	<-doneConn
	defer serverConn.Close()

	recHijackOK := &mockHijacker{ResponseWriter: httptest.NewRecorder(), conn: serverConn}

	go func() {
		stream, err := agentSess2.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		_, _ = protocol.ReadDataHeader(stream)
		buf := make([]byte, 4)
		_, _ = io.ReadFull(stream, buf)
		_, _ = stream.Write([]byte("pong"))
	}()

	go func() {
		srv.ServeHTTP(recHijackOK, req)
	}()

	_, _ = clientConn.Write([]byte("ping"))
	respBuf := make([]byte, 4)
	_, _ = io.ReadFull(clientConn, respBuf)
	assert.Equal(t, "pong", string(respBuf))

	_ = clientConn.Close()
}

func TestHandleClientConn_ErrorsAndSuccess(t *testing.T) {
	// Case 1: Immediately closed conn
	c1, s1 := net.Pipe()
	_ = c1.Close()
	srv := &Server{logger: zap.NewNop()}
	srv.handleClientConn(s1)
	_ = s1.Close()

	runWithAgent := func(fn func(ctrl *yamux.Stream)) {
		agentSess, srvSess, clean := makeYamuxPair()
		defer clean()
		_ = agentSess
		_ = srvSess

		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()

		done := make(chan struct{})
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				srv.handleClientConn(conn)
			}
			close(done)
		}()

		clientConn, _ := net.Dial("tcp", ln.Addr().String())
		clientSess, _ := yamux.Client(clientConn, nil)
		defer clientSess.Close()

		ctrl, err := clientSess.OpenStream()
		if err == nil {
			fn(ctrl)
			_ = ctrl.Close()
		}
		_ = clientConn.Close()
		<-done
	}

	// Case 2: Send non-register message
	runWithAgent(func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{"type": "pong"})
	})

	// Case 3: Auth failed
	mockAuth := new(mockUser.MockAuthUsecase)
	mockAuth.On("VerifyToken", mock.Anything, "bad-token").Return(nil, errors.New("bad")).Once()
	srv.authUsecase = mockAuth
	runWithAgent(func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{"type": protocol.MsgTypeRegister, "auth_token": "bad-token"})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.Equal(t, protocol.MsgTypeAck, ack["type"])
		assert.False(t, ack["ok"].(bool))
	})

	// Case 4: Max active tunnels reached
	testUser := &domainUser.User{ID: uuid.New(), Username: "john", Role: 0}
	mockAuth.On("VerifyToken", mock.Anything, "good-token").Return(testUser, nil)
	mockSet := new(mockSetting.MockSettingUsecase)
	mockSet.On("GetMaxTunnelsPerUser", mock.Anything, 5).Return(0).Once()
	srv.settingUsecase = mockSet
	runWithAgent(func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{"type": protocol.MsgTypeRegister, "auth_token": "good-token"})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.False(t, ack["ok"].(bool))
	})

	// Case 5: No routes
	mockSet.On("GetMaxTunnelsPerUser", mock.Anything, 5).Return(10)
	runWithAgent(func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{"type": protocol.MsgTypeRegister, "auth_token": "good-token", "routes": map[string]any{}})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.False(t, ack["ok"].(bool))
	})

	// Case 6: Domain not authorized
	mockTun := new(mockTunnel.MockTunnelUsecase)
	mockTun.On("IsDomainAllowed", mock.Anything, "unauth.com", testUser.ID, testUser.Role).Return(false, nil).Once()
	srv.tunnelUsecase = mockTun
	runWithAgent(func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"unauth.com": true},
		})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.False(t, ack["ok"].(bool))
	})

	// Case 7: Success Registration
	mockTun.On("IsDomainAllowed", mock.Anything, "valid.com", testUser.ID, testUser.Role).Return(true, nil).Once()
	mockTun.On("SetActiveDomain", mock.Anything, "valid.com", mock.Anything).Return(nil).Once()
	mockTun.On("RegisterTunnel", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockTun.On("RemoveActiveDomain", mock.Anything, "valid.com").Return(nil).Maybe()
	mockTun.On("UnregisterTunnel", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockTun.On("DeleteRateLimitSetting", mock.Anything, "john").Return(nil).Maybe()
	mockSet.On("GetSetting", mock.Anything, "rate_limit_enabled:john").Return("true", nil).Once()
	mockTun.On("SetRateLimitSetting", mock.Anything, "john", "true").Return(nil).Once()

	mockReg := new(mockRegistry.MockHostRegistry)
	mockReg.On("Register", "valid.com").Return(true).Once()
	mockReg.On("Unregister", "valid.com").Return(true).Maybe()
	srv.hostRegistry = mockReg
	srv.hostToSes = map[string]*TunnelSession{}

	runWithAgent(func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"valid.com": true},
			"modes":      map[string]any{"valid.com": "http"},
		})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.True(t, ack["ok"].(bool))
	})
	time.Sleep(50 * time.Millisecond)
}

func TestServeHTTP_AdditionalBranches(t *testing.T) {
	t.Run("EmptyHost", func(t *testing.T) {
		agentSess, srvSess, clean := makeYamuxPair()
		defer clean()
		_ = agentSess

		srv := &Server{
			logger:    zap.NewNop(),
			hostToSes: map[string]*TunnelSession{"": {Session: srvSess}},
		}
		req := httptest.NewRequest(http.MethodGet, "http://localhost/", http.NoBody)
		req.Host = ""
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadGateway, rec.Code)
	})

	t.Run("RateLimit_User1", func(t *testing.T) {
		agentSess, srvSess, clean := makeYamuxPair()
		defer clean()

		mockTun := new(mockTunnel.MockTunnelUsecase)
		mockSet := new(mockSetting.MockSettingUsecase)
		mockSet.On("GetRateLimitConfig", mock.Anything).Return(domainSetting.RateLimitConfig{Enabled: true, Rate: 100, Burst: 10}).Maybe()
		mockTun.On("GetRateLimitSetting", mock.Anything, "user1").Return("", errors.New("err")).Once()
		mockSet.On("GetSetting", mock.Anything, "rate_limit_enabled:user1").Return("true", nil).Once()

		srv := &Server{
			logger:         zap.NewNop(),
			tunnelUsecase:  mockTun,
			settingUsecase: mockSet,
			limiter:        ratelimit.NewLimiter(),
			hostToSes: map[string]*TunnelSession{
				"user1.com": {Session: srvSess, Role: 0, Username: "user1", Modes: map[string]string{"user1.com": "http"}},
			},
		}

		go func() {
			stream, err := agentSess.AcceptStream()
			if err == nil {
				_, _ = protocol.ReadDataHeader(stream)
				_, _ = stream.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
				_ = stream.Close()
			}
		}()

		req := httptest.NewRequest(http.MethodGet, "http://user1.com/", http.NoBody)
		req.Host = "user1.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
	})

	t.Run("RateLimit_User2_NoTunnelUsecase", func(t *testing.T) {
		agentSess, srvSess, clean := makeYamuxPair()
		defer clean()

		mockSet := new(mockSetting.MockSettingUsecase)
		mockSet.On("GetRateLimitConfig", mock.Anything).Return(domainSetting.RateLimitConfig{Enabled: true, Rate: 100, Burst: 10}).Maybe()
		mockSet.On("GetSetting", mock.Anything, "rate_limit_enabled:user2").Return("true", nil).Once()

		srvNoTun := &Server{
			logger:         zap.NewNop(),
			settingUsecase: mockSet,
			limiter:        ratelimit.NewLimiter(),
			hostToSes: map[string]*TunnelSession{
				"user2.com": {Session: srvSess, Role: 0, Username: "user2", Modes: map[string]string{"user2.com": "http"}},
			},
		}

		go func() {
			stream, err := agentSess.AcceptStream()
			if err == nil {
				_, _ = protocol.ReadDataHeader(stream)
				_, _ = stream.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
				_ = stream.Close()
			}
		}()

		req := httptest.NewRequest(http.MethodGet, "http://user2.com/", http.NoBody)
		req.Host = "user2.com"
		rec := httptest.NewRecorder()
		srvNoTun.ServeHTTP(rec, req)
	})

	t.Run("PublishInspectEventPanic", func(t *testing.T) {
		agentSess, srvSess, clean := makeYamuxPair()
		defer clean()

		mockTun := new(mockTunnel.MockTunnelUsecase)
		mockSet := new(mockSetting.MockSettingUsecase)
		mockSet.On("GetRateLimitConfig", mock.Anything).Return(domainSetting.RateLimitConfig{Enabled: false, Rate: 100, Burst: 10}).Maybe()
		mockTun.On("PublishInspectEvent", mock.Anything, "panic.com", mock.Anything).Run(func(args mock.Arguments) {
			panic("intentional panic for test")
		}).Return(nil).Once()

		srv := &Server{
			logger:         zap.NewNop(),
			tunnelUsecase:  mockTun,
			settingUsecase: mockSet,
			hostToSes: map[string]*TunnelSession{
				"panic.com": {Session: srvSess, Modes: map[string]string{"panic.com": "http"}},
			},
		}

		go func() {
			stream, err := agentSess.AcceptStream()
			if err == nil {
				_, _ = protocol.ReadDataHeader(stream)
				_, _ = http.ReadRequest(bufio.NewReader(stream))
				_, _ = stream.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
				_ = stream.Close()
			}
		}()

		req := httptest.NewRequest(http.MethodGet, "http://panic.com/", http.NoBody)
		req.Host = "panic.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
	})

	t.Run("BadResp", func(t *testing.T) {
		agentSess, srvSess, clean := makeYamuxPair()
		defer clean()

		mockSet := new(mockSetting.MockSettingUsecase)
		mockSet.On("GetRateLimitConfig", mock.Anything).Return(domainSetting.RateLimitConfig{Enabled: false, Rate: 100, Burst: 10}).Maybe()

		srv := &Server{
			logger:         zap.NewNop(),
			settingUsecase: mockSet,
			hostToSes: map[string]*TunnelSession{
				"badresp.com": {Session: srvSess, Modes: map[string]string{"badresp.com": "http"}},
			},
		}

		go func() {
			stream, err := agentSess.AcceptStream()
			if err == nil {
				_, _ = protocol.ReadDataHeader(stream)
				_, _ = stream.Write([]byte("INVALID HTTP RESPONSE\r\n\r\n"))
				_ = stream.Close()
			}
		}()

		req := httptest.NewRequest(http.MethodGet, "http://badresp.com/", http.NoBody)
		req.Host = "badresp.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadGateway, rec.Code)
	})
}

func TestHandleClientConn_AdditionalBranches(t *testing.T) {
	runWithAgent := func(srv *Server, fn func(ctrl *yamux.Stream)) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()

		done := make(chan struct{})
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				srv.handleClientConn(conn)
			}
			close(done)
		}()

		clientConn, _ := net.Dial("tcp", ln.Addr().String())
		clientSess, _ := yamux.Client(clientConn, nil)
		defer clientSess.Close()

		ctrl, err := clientSess.OpenStream()
		if err == nil {
			fn(ctrl)
			_ = ctrl.Close()
		}
		_ = clientConn.Close()
		<-done
	}

	mockAuth := new(mockUser.MockAuthUsecase)
	testUser := &domainUser.User{ID: uuid.New(), Username: "john", Role: 0}
	mockAuth.On("VerifyToken", mock.Anything, "good-token").Return(testUser, nil).Maybe()

	mockSet := new(mockSetting.MockSettingUsecase)
	mockSet.On("GetMaxTunnelsPerUser", mock.Anything, 5).Return(10).Maybe()
	mockSet.On("GetSetting", mock.Anything, "rate_limit_enabled:john").Return("true", nil).Maybe()

	// 1. Dashboard domain automatic allow
	srvDash := &Server{
		logger:          zap.NewNop(),
		authUsecase:     mockAuth,
		settingUsecase:  mockSet,
		dashboardDomain: "dash.com",
		hostToSes:       map[string]*TunnelSession{},
	}
	runWithAgent(srvDash, func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"dash.com": true},
		})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.True(t, ack["ok"].(bool))
	})

	// 2. Conflict: no authorization store (tunnelUsecase is nil)
	srvNoStore := &Server{
		logger:         zap.NewNop(),
		authUsecase:    mockAuth,
		settingUsecase: mockSet,
		hostToSes:      map[string]*TunnelSession{},
	}
	runWithAgent(srvNoStore, func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"some.com": true},
		})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.False(t, ack["ok"].(bool))
		assert.Contains(t, ack["error"].(string), "no authorization store")
	})

	// 3. Conflict: already active locally in hostToSes
	mockTun := new(mockTunnel.MockTunnelUsecase)
	mockTun.On("SetRateLimitSetting", mock.Anything, "john", "true").Return(nil).Maybe()
	mockTun.On("IsDomainAllowed", mock.Anything, "active.com", mock.Anything, mock.Anything).Return(true, nil).Maybe()
	srvLocalConflict := &Server{
		logger:         zap.NewNop(),
		authUsecase:    mockAuth,
		settingUsecase: mockSet,
		tunnelUsecase:  mockTun,
		hostToSes:      map[string]*TunnelSession{"active.com": {}},
	}
	runWithAgent(srvLocalConflict, func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"active.com": true},
		})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.False(t, ack["ok"].(bool))
	})

	// 4. Conflict: hostRegistry.Register returns false
	mockReg := new(mockRegistry.MockHostRegistry)
	mockReg.On("Register", "regfail.com").Return(false).Once()
	srvRegFail := &Server{
		logger:         zap.NewNop(),
		authUsecase:    mockAuth,
		settingUsecase: mockSet,
		tunnelUsecase:  mockTun,
		hostRegistry:   mockReg,
		hostToSes:      map[string]*TunnelSession{},
	}
	mockTun.On("IsDomainAllowed", mock.Anything, "regfail.com", mock.Anything, mock.Anything).Return(true, nil).Maybe()
	runWithAgent(srvRegFail, func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"regfail.com": true},
		})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.False(t, ack["ok"].(bool))
	})

	// 5. Conflict: SetActiveDomain returns error on second domain -> rollback addedHosts
	mockReg2 := new(mockRegistry.MockHostRegistry)
	mockReg2.On("Register", mock.Anything).Return(true).Maybe()
	mockReg2.On("Unregister", mock.Anything).Return(true).Maybe()

	mockTun5 := new(mockTunnel.MockTunnelUsecase)
	mockTun5.On("SetRateLimitSetting", mock.Anything, "john", "true").Return(nil).Maybe()
	mockTun5.On("IsDomainAllowed", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil).Maybe()
	var activeCallCount int
	mockTun5.On("SetActiveDomain", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		activeCallCount++
	}).Return(func(ctx context.Context, domain string, sessionID string) error {
		if activeCallCount > 1 {
			return errors.New("redis lock")
		}
		return nil
	}).Maybe()
	mockTun5.On("RemoveActiveDomain", mock.Anything, mock.Anything).Return(nil).Maybe()

	srvRollback := &Server{
		logger:         zap.NewNop(),
		authUsecase:    mockAuth,
		settingUsecase: mockSet,
		tunnelUsecase:  mockTun5,
		hostRegistry:   mockReg2,
		hostToSes:      map[string]*TunnelSession{},
	}
	runWithAgent(srvRollback, func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"good1.com": true, "bad1.com": true},
		})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.False(t, ack["ok"].(bool))
	})

	// 6. Heartbeat loop branches (fast ticker)
	mockTun.On("IsDomainAllowed", mock.Anything, "hb.com", mock.Anything, mock.Anything).Return(true, nil).Maybe()
	mockTun.On("SetActiveDomain", mock.Anything, "hb.com", mock.Anything).Return(nil).Maybe()
	mockTun.On("RegisterTunnel", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	mockTun.On("RemoveActiveDomain", mock.Anything, "hb.com").Return(nil).Maybe()
	mockTun.On("UnregisterTunnel", mock.Anything, mock.Anything).Return(nil).Maybe()

	srvHb := &Server{
		logger:            zap.NewNop(),
		authUsecase:       mockAuth,
		settingUsecase:    mockSet,
		tunnelUsecase:     mockTun,
		heartbeatInterval: 15 * time.Millisecond,
		hostToSes:         map[string]*TunnelSession{},
	}
	runWithAgent(srvHb, func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"hb.com": true},
		})
		ack, _ := protocol.ReadJSON(ctrl)
		assert.True(t, ack["ok"].(bool))

		// Read ping from server and reply pong
		ping, err := protocol.ReadJSON(ctrl)
		if err == nil && ping["type"] == protocol.MsgTypePing {
			_ = protocol.SendJSON(ctrl, protocol.PongMessage{Type: protocol.MsgTypePong, Ts: protocol.NowMillis()})
		}
		// Read second ping and reply invalid message type
		ping2, err := protocol.ReadJSON(ctrl)
		if err == nil && ping2["type"] == protocol.MsgTypePing {
			_ = protocol.SendJSON(ctrl, map[string]any{"type": "invalid_msg"})
		}
		time.Sleep(30 * time.Millisecond)
	})
}

func TestHandleClientConn_EdgeErrors(t *testing.T) {
	runWithAgent := func(srv *Server, fn func(ctrl *yamux.Stream)) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()

		done := make(chan struct{})
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				srv.handleClientConn(conn)
			}
			close(done)
		}()

		clientConn, _ := net.Dial("tcp", ln.Addr().String())
		clientSess, _ := yamux.Client(clientConn, nil)
		defer clientSess.Close()

		ctrl, err := clientSess.OpenStream()
		if err == nil {
			fn(ctrl)
			_ = ctrl.Close()
		}
		_ = clientConn.Close()
		<-done
	}

	mockAuth := new(mockUser.MockAuthUsecase)
	testUser := &domainUser.User{ID: uuid.New(), Username: "john", Role: 0}
	mockAuth.On("VerifyToken", mock.Anything, "good-token").Return(testUser, nil).Maybe()
	mockSet := new(mockSetting.MockSettingUsecase)
	mockSet.On("GetMaxTunnelsPerUser", mock.Anything, 5).Return(10).Maybe()
	mockSet.On("GetSetting", mock.Anything, "rate_limit_enabled:john").Return("true", nil).Maybe()

	// 1. Nil conn and Invalid JSON on register stream
	srv1 := &Server{logger: zap.NewNop(), authUsecase: mockAuth, settingUsecase: mockSet, hostToSes: map[string]*TunnelSession{}}
	runWithAgent(srv1, func(ctrl *yamux.Stream) {
		_, _ = ctrl.Write([]byte("NOT JSON\r\n"))
	})

	// 2. Heartbeat SendJSON error (client closes ctrl after register ack)
	srv2 := &Server{
		logger:            zap.NewNop(),
		authUsecase:       mockAuth,
		settingUsecase:    mockSet,
		dashboardDomain:   "dash.com",
		heartbeatInterval: 10 * time.Millisecond,
		hostToSes:         map[string]*TunnelSession{},
	}
	runWithAgent(srv2, func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"dash.com": true},
		})
		_, _ = protocol.ReadJSON(ctrl)
		_ = ctrl.Session().Close() // Close session immediately so server SendJSON ping fails
		time.Sleep(30 * time.Millisecond)
	})

	// 3. Heartbeat ReadJSON error (client reads ping but sends garbage/closes)
	srv3 := &Server{
		logger:            zap.NewNop(),
		authUsecase:       mockAuth,
		settingUsecase:    mockSet,
		dashboardDomain:   "dash2.com",
		heartbeatInterval: 10 * time.Millisecond,
		hostToSes:         map[string]*TunnelSession{},
	}
	runWithAgent(srv3, func(ctrl *yamux.Stream) {
		_ = protocol.SendJSON(ctrl, map[string]any{
			"type":       protocol.MsgTypeRegister,
			"auth_token": "good-token",
			"routes":     map[string]any{"dash2.com": true},
		})
		_, _ = protocol.ReadJSON(ctrl) // ack
		// Wait for ping then write garbage
		ping, err := protocol.ReadJSON(ctrl)
		if err == nil && ping["type"] == protocol.MsgTypePing {
			_, _ = ctrl.Write([]byte("GARBAGE PONG\r\n"))
		}
		time.Sleep(30 * time.Millisecond)
	})
}

func TestListenTunnelTLS_HandshakeError(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	tlsCfg := makeTestTLSConfig()
	ln, err := srv.ListenTunnelTLS("127.0.0.1:0", tlsCfg)
	assert.NoError(t, err)

	// Connect raw TCP without TLS handshake
	c, err := net.Dial("tcp", ln.Addr().String())
	if err == nil {
		_, _ = c.Write([]byte("NOT A TLS CLIENT HANDSHAKE"))
		_ = c.Close()
	}
	time.Sleep(50 * time.Millisecond)
	_ = ln.Close()
}

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) { return 0, errors.New("read body error") }
func (errReader) Close() error                     { return nil }

type mockListener struct {
	count int
}

func (m *mockListener) Accept() (net.Conn, error) {
	if m.count == 0 {
		m.count++
		return nil, errors.New("temp network error")
	}
	return nil, net.ErrClosed
}
func (m *mockListener) Close() error   { return nil }
func (m *mockListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestServeListener_AcceptError(t *testing.T) {
	srv := &Server{logger: zap.NewNop()}
	srv.serveListener(&mockListener{})
}

func TestServeHTTP_RateLimitSettingAndWriteError(t *testing.T) {
	t.Run("TunnelUsecase_GetRateLimitSetting_True", func(t *testing.T) {
		agentSess, srvSess, clean := makeYamuxPair()
		defer clean()

		mockTun := new(mockTunnel.MockTunnelUsecase)
		mockSet := new(mockSetting.MockSettingUsecase)
		mockSet.On("GetRateLimitConfig", mock.Anything).Return(domainSetting.RateLimitConfig{Enabled: true, Rate: 100, Burst: 10}).Maybe()
		mockTun.On("GetRateLimitSetting", mock.Anything, "user3").Return("true", nil).Once()

		srv := &Server{
			logger:         zap.NewNop(),
			tunnelUsecase:  mockTun,
			settingUsecase: mockSet,
			limiter:        ratelimit.NewLimiter(),
			hostToSes: map[string]*TunnelSession{
				"user3.com": {Session: srvSess, Role: 0, Username: "user3", Modes: map[string]string{"user3.com": "http"}},
			},
		}

		go func() {
			stream, err := agentSess.AcceptStream()
			if err == nil {
				_, _ = protocol.ReadDataHeader(stream)
				_, _ = stream.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
				_ = stream.Close()
			}
		}()

		req := httptest.NewRequest(http.MethodGet, "http://user3.com/", http.NoBody)
		req.Host = "user3.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
	})

	t.Run("WriteRequestFailed", func(t *testing.T) {
		agentSess, srvSess, clean := makeYamuxPair()
		defer clean()

		mockSet := new(mockSetting.MockSettingUsecase)
		mockSet.On("GetRateLimitConfig", mock.Anything).Return(domainSetting.RateLimitConfig{Enabled: false, Rate: 100, Burst: 10}).Maybe()

		srv := &Server{
			logger:         zap.NewNop(),
			settingUsecase: mockSet,
			hostToSes: map[string]*TunnelSession{
				"writefail.com": {Session: srvSess, Modes: map[string]string{"writefail.com": "http"}},
			},
		}

		go func() {
			_, _ = agentSess.AcceptStream()
		}()

		req := httptest.NewRequest(http.MethodPost, "http://writefail.com/", errReader{})
		req.ContentLength = 100
		req.Host = "writefail.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadGateway, rec.Code)
	})
}

func TestServeHTTP_MinecraftProxy_ProxyProtocol(t *testing.T) {
	agentSess, srvSess, clean := makeYamuxPair()
	defer clean()

	mockSet := new(mockSetting.MockSettingUsecase)
	mockSet.On("GetRateLimitConfig", mock.Anything).Return(domainSetting.RateLimitConfig{Enabled: false, Rate: 100, Burst: 10}).Maybe()

	srv := &Server{
		logger:         zap.NewNop(),
		settingUsecase: mockSet,
		hostToSes: map[string]*TunnelSession{
			"mcproxy.com": {Session: srvSess, Modes: map[string]string{"mcproxy.com": "minecraft-proxy"}},
		},
	}

	receivedCh := make(chan string, 1)
	go func() {
		stream, err := agentSess.AcceptStream()
		if err == nil {
			hostname, _ := protocol.ReadDataHeader(stream)
			buf := make([]byte, 1024)
			n, _ := stream.Read(buf)
			_ = stream.Close()
			receivedCh <- hostname + "|" + string(buf[:n])
		}
	}()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = io.Copy(io.Discard, clientConn)
	}()

	rec := &mockHijacker{
		ResponseWriter: httptest.NewRecorder(),
		conn:           serverConn,
	}

	req := httptest.NewRequest(http.MethodConnect, "http://mcproxy.com/", http.NoBody)
	req.Host = "mcproxy.com"
	req.Header.Set("X-Real-IP", "198.51.100.25")
	req.Header.Set("X-Real-Port", "54321")

	go func() {
		srv.ServeHTTP(rec, req)
	}()

	select {
	case res := <-receivedCh:
		parts := strings.SplitN(res, "|", 2)
		assert.Equal(t, "mcproxy.com", parts[0])
		assert.Contains(t, parts[1], "PROXY TCP4 198.51.100.25 127.0.0.1 54321 25565\r\n")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stream data")
	}
}
