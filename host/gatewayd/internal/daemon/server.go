package daemon

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/trafficpolicy"
)

// daemonVersion is stamped at build time with
// -ldflags "-X shakerproxy.dev/shakerproxy/host/gatewayd/internal/daemon.daemonVersion=<version>".
var daemonVersion = "0.1.0-dev"

const (
	// requestReadTimeout bounds peer authentication and reading the single
	// request line. Method work gets its own budget once the request is read.
	requestReadTimeout = 5 * time.Second
	// responseGrace keeps the connection open slightly longer than the
	// client's own budget so the daemon never closes first.
	responseGrace = 5 * time.Second
)

type Server struct {
	store      *StateStore
	logger     *slog.Logger
	startedAt  time.Time
	activation *NetworkActivation
	captures   *capture.Manager
	imports    *capture.ImportManager
	recorder   *LabRecorder
	configLock *configlock.Manager
	traffic    *TrafficPolicyManager
	vpn        *VPNManager
	wifi       *WiFiMonitor
	// vpnRecorder records the VPN interface beside the lab recording.
	vpnRecorder *LabRecorder

	// Connection budgets; zero values select requestReadTimeout and
	// gatewayprotocol.MethodTimeout plus responseGrace. Tests shorten them.
	readTimeout  time.Duration
	methodBudget func(method string) time.Duration
	// dispatcher is s.dispatch unless a test replaces it.
	dispatcher func(context.Context, gatewayprotocol.Request) (any, *gatewayprotocol.RPCError)
}

func NewServer(store *StateStore, logger *slog.Logger) *Server {
	return &Server{store: store, logger: logger, startedAt: time.Now().UTC()}
}

func NewServerWithNetworkActivation(store *StateStore, logger *slog.Logger, activation *NetworkActivation) *Server {
	server := NewServer(store, logger)
	server.activation = activation
	return server
}

func NewServerWithHostServices(store *StateStore, logger *slog.Logger, activation *NetworkActivation, captures *capture.Manager) *Server {
	server := NewServerWithNetworkActivation(store, logger, activation)
	server.captures = captures
	if activation != nil {
		server.configLock = activation.ConfigLock
	}
	if captures != nil {
		server.recorder = &LabRecorder{Store: store, Captures: captures, Source: server.captureSource, LabRevision: labRecordingRevision, NewCaptureAllowed: server.newCaptureAllowed, ConfigLock: server.configLock, Logger: logger}
		server.imports = &capture.ImportManager{Store: captures.Store, TempRoot: filepath.Join(captures.Store.Root, ".imports")}
	}
	return server
}

// RecordLabTraffic keeps lab traffic recorded for the daemon's lifetime (see
// LabRecorder); it returns at once when capture is unavailable.
func (s *Server) RecordLabTraffic(ctx context.Context) {
	if s.vpnRecorder != nil {
		go s.vpnRecorder.Run(ctx)
	}
	if s.recorder != nil {
		s.recorder.Run(ctx)
	}
}

// SetVPNManager enables the VPN requests and records the VPN interface
// whenever VPN mode is up. Call it before RecordLabTraffic.
func (s *Server) SetVPNManager(manager *VPNManager) {
	s.vpn = manager
	if manager != nil && s.captures != nil {
		s.vpnRecorder = &LabRecorder{Store: s.store, Captures: s.captures, NewCaptureAllowed: s.newCaptureAllowed, ConfigLock: s.configLock, Logger: s.logger, VPN: manager.TrafficSegment}
	}
}

// VPNChanged is called when the VPN segment appears, changes or goes away.
func (s *Server) VPNChanged() {
	if s.vpnRecorder != nil {
		s.vpnRecorder.Wake()
	}
}

// newCaptureAllowed reports whether CPU, memory and capture disk space allow
// a new capture.
func (s *Server) newCaptureAllowed() bool {
	diskPath := filepath.Dir(s.store.path)
	if s.captures != nil && s.captures.Store.Root != "" {
		diskPath = s.captures.Store.Root
	}
	return inspectResourcePressure(diskPath, time.Now().UTC()).NewCaptureAllowed
}

// wakesLabRecorder lists the requests after which the lab recording may need
// to start, stop or restart.
func wakesLabRecorder(method string) bool {
	switch method {
	case "ConfirmNetworkPlan", "RollbackNetworkPlan", "RevertNetworkPlan", "SetOperatingMode",
		"EnableEmergencyBypass", "DisableEmergencyBypass", "StartCapture", "StopCapture":
		return true
	}
	return false
}

func (s *Server) SetConfigurationLock(manager *configlock.Manager) {
	s.configLock = manager
	if s.recorder != nil {
		s.recorder.ConfigLock = manager
	}
	if s.vpnRecorder != nil {
		s.vpnRecorder.ConfigLock = manager
	}
}

func (s *Server) SetTrafficPolicyManager(manager *TrafficPolicyManager) { s.traffic = manager }

// SetWiFiMonitor enables the Wi-Fi visibility methods.
func (s *Server) SetWiFiMonitor(monitor *WiFiMonitor) { s.wifi = monitor }

func (s *Server) Serve(ctx context.Context, socketPath string) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		return err
	}
	if err := removeSocket(socketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	// The listener must not unlink the path on Close: by then another daemon
	// may own it. releaseSocket removes it only if it is still ours.
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	owned, err := os.Lstat(socketPath)
	if err != nil {
		listener.Close()
		return err
	}
	defer releaseSocket(socketPath, owned)
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

// removeSocket clears a socket left behind by a daemon that exited
// without cleanup. A socket that still accepts connections belongs to a live
// daemon and is never removed; any non-socket path is refused.
func removeSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %s", path)
	}
	probe, dialErr := net.DialTimeout("unix", path, time.Second)
	if dialErr == nil {
		probe.Close()
		return fmt.Errorf("another gateway daemon is already serving %s; stop it first (systemctl stop shakerproxy-gatewayd)", path)
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) {
		return fmt.Errorf("socket path %s changed while checking it; retry", path)
	}
	return os.Remove(path)
}

// releaseSocket removes the socket at shutdown only when the path still refers
// to the socket this daemon created.
func releaseSocket(path string, owned os.FileInfo) {
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(owned, current) {
		return
	}
	_ = os.Remove(path)
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	readTimeout := s.readTimeout
	if readTimeout <= 0 {
		readTimeout = requestReadTimeout
	}
	if err := conn.SetDeadline(time.Now().Add(readTimeout)); err != nil {
		return
	}
	uid, pid, err := peerIdentity(conn)
	if err != nil {
		s.logger.Warn("peer authentication failed", "error", err)
		return
	}
	reader := bufio.NewReader(io.LimitReader(conn, gatewayprotocol.MaxRequestBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return
	}
	var req gatewayprotocol.Request
	if err := gatewayprotocol.DecodeStrict(strings.NewReader(string(line)), &req, gatewayprotocol.MaxRequestBytes); err != nil {
		if writeErr := s.writeResponse(conn, gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, Error: &gatewayprotocol.RPCError{Code: -32700, Message: "invalid request"}}); writeErr != nil {
			s.logger.Warn("invalid privileged request response was not delivered", "uid", uid, "pid", pid, "error", writeErr)
		}
		return
	}
	// The request is fully read. Give the method its own budget for dispatch
	// and response delivery instead of the short read timeout, so slow host
	// operations (connectivity probe, PCAP rewrite) can answer their callers.
	budget := gatewayprotocol.MethodTimeout(req.Method) + responseGrace
	if s.methodBudget != nil {
		budget = s.methodBudget(req.Method)
	}
	if err := conn.SetDeadline(time.Now().Add(budget)); err != nil {
		return
	}
	dispatch := s.dispatch
	if s.dispatcher != nil {
		dispatch = s.dispatcher
	}
	planHash, changedObjects := s.auditDetails(req, nil)
	result, rpcErr := dispatch(ctx, req)
	if resultHash, resultObjects := s.auditDetails(req, result); resultHash != "" || len(resultObjects) != 0 {
		planHash, changedObjects = resultHash, resultObjects
	}
	writeErr := s.writeResponse(conn, gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: req.ID, Result: result, Error: rpcErr})
	attributes := []any{"uid", uid, "pid", pid, "method", req.Method, "request_id", req.ID, "success", rpcErr == nil, "delivered", writeErr == nil}
	if planHash != "" {
		attributes = append(attributes, "plan_hash", planHash)
	}
	if len(changedObjects) != 0 {
		attributes = append(attributes, "changed_objects", changedObjects)
	}
	if writeErr != nil {
		// The operation outcome above is still accurate; only the caller did
		// not receive it (it disconnected or exceeded its budget).
		attributes = append(attributes, "delivery_error", writeErr.Error())
		s.logger.Warn("privileged request", attributes...)
		return
	}
	s.logger.Info("privileged request", attributes...)
}

func (s *Server) writeResponse(w io.Writer, response gatewayprotocol.Response) error {
	return json.NewEncoder(w).Encode(response)
}

func (s *Server) dispatch(ctx context.Context, req gatewayprotocol.Request) (any, *gatewayprotocol.RPCError) {
	if req.JSONRPC != gatewayprotocol.JSONRPCVersion || req.ID == "" {
		return nil, &gatewayprotocol.RPCError{Code: -32600, Message: "jsonrpc 2.0 and a non-empty id are required"}
	}
	guard, lockErr := s.acquireConfigurationLock(ctx, req)
	if lockErr != nil {
		return nil, lockErr
	}
	if guard != nil {
		defer func() {
			if err := guard.Release(); err != nil {
				s.logger.Error("release appliance configuration lock", "method", req.Method, "error", err)
			}
		}()
	}
	if s.recorder != nil && wakesLabRecorder(req.Method) {
		defer s.recorder.Wake()
	}
	if s.vpnRecorder != nil && wakesLabRecorder(req.Method) {
		defer s.vpnRecorder.Wake()
	}
	decodeEmpty := func() *gatewayprotocol.RPCError {
		var params gatewayprotocol.EmptyParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		return nil
	}
	switch req.Method {
	case "GetManagedState":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		// Status must stay readable during incidents: a failing subsystem
		// degrades the answer with a warning instead of failing it wholesale.
		var warnings, degraded []string
		networkUnproven := false
		if s.activation != nil {
			if err := s.activation.Reconcile(); err != nil && !errors.Is(err, configlock.ErrBusy) {
				s.logger.Error("network watchdog outcome reconciliation failed", "error", err)
				networkUnproven = true
				degraded = append(degraded, gatewayprotocol.DegradedNetworkReconcile)
				warnings = append(warnings, "Network watchdog outcome could not be reconciled, so the network state shown may be stale. Run `sudo shakerproxy doctor` and check `shakerproxy logs gatewayd`.")
			}
		}
		state := s.store.Get()
		status := gatewayprotocol.Status{APIVersion: gatewayprotocol.Version, DaemonVersion: daemonVersion, OperatingMode: state.OperatingMode, EmergencyBypass: state.EmergencyBypass, NetworkActivation: s.activation != nil, CaptureAvailable: s.captures != nil, TrafficPolicyAvailable: s.traffic != nil, StartedAt: s.startedAt.Format(time.RFC3339Nano)}
		if s.configLock != nil {
			if lockStatus, lockStatusErr := s.configLock.Inspect(); lockStatusErr == nil {
				status.ConfigurationLock = &lockStatus
			} else {
				degraded = append(degraded, gatewayprotocol.DegradedConfigurationLock)
				warnings = append(warnings, "Configuration lock state is unavailable.")
			}
		}
		if s.captures != nil {
			captures, captureErr := s.captures.List(ctx)
			if captureErr != nil {
				s.logger.Error("capture status is unavailable", "error", captureErr)
				degraded = append(degraded, gatewayprotocol.DegradedCaptureList)
				warnings = append(warnings, "Capture status is unavailable, so a running capture may not be shown. Run `shakerproxy capture list` for details.")
			}
			for _, item := range captures {
				if item.Active {
					status.ActiveCaptureID = item.Session.ID
					break
				}
			}
		}
		if s.recorder != nil {
			status.LabRecording = s.recorder.Status()
		}
		status.Warnings, status.Degraded = warnings, degraded
		if staged := state.StagedNetworkPlan; staged != nil {
			status.StagedNetworkPlan = &networkplan.StageSummary{ApplyID: staged.ApplyID, PlanHash: staged.PlanHash, StagedAt: staged.StagedAt, ExpiresAt: staged.ExpiresAt, Status: staged.Status}
			if staged.Transaction != nil {
				status.StagedNetworkPlan.ConfirmBy = staged.Transaction.ConfirmBy
			}
		}
		// An unreconciled watchdog outcome may have rolled the plan back, so
		// the lab scope is only published when the state is proven. A staged
		// candidate does not hide the confirmed plan the host is running.
		if active := state.activeNetworkPlan(); active != nil && !networkUnproven {
			summary := &networkplan.StageSummary{ApplyID: active.ApplyID, PlanHash: active.PlanHash, StagedAt: active.StagedAt, ExpiresAt: active.ExpiresAt, Status: active.Status}
			switch {
			case state.StagedNetworkPlan == nil:
				status.StagedNetworkPlan = summary // no candidate: the running plan is the plan
			case active != state.StagedNetworkPlan:
				status.ConfirmedNetworkPlan = summary
			}
			if lab, ok := networkplan.LabInterface(active.Plan); ok {
				status.LabInterface = lab.CurrentName
				status.LabVLANID = cloneVLANID(lab.VLANID)
				status.LabScopePlanHash = active.PlanHash
			}
			setLabIPv6Status(&status, active.Plan)
		}
		return status, nil
	case "InspectHost":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		inspection, err := inspectHost(ctx)
		if err != nil {
			s.logger.Error("host inspection failed", "error", err)
			return nil, &gatewayprotocol.RPCError{Code: -32000, Message: "host inspection failed"}
		}
		return inspection, nil
	case "GetDiagnostics":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		return s.inspectDiagnostics(ctx), nil
	case "GetNeighbors":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		table, err := s.neighborTable(ctx)
		if err != nil {
			s.logger.Warn("IPv6 neighbor inspection failed", "error", err)
			return nil, &gatewayprotocol.RPCError{Code: -32080, Message: "IPv6 neighbor table is unavailable"}
		}
		return table, nil
	case "GetIPv4Neighbors":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		table, err := s.ipv4NeighborTable(ctx)
		if err != nil {
			s.logger.Warn("IPv4 neighbor inspection failed", "error", err)
			return nil, &gatewayprotocol.RPCError{Code: -32080, Message: "IPv4 neighbor table is unavailable"}
		}
		return table, nil
	case "GetServicePortPlan":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		plan, err := inspectServicePortPlan(ctx)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32010, Message: "service port ownership is unavailable"}
		}
		return plan, nil
	case "ProbeConnectivity":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		probeContext, cancel := context.WithTimeout(ctx, 7*time.Second)
		defer cancel()
		return probeConnectivity(probeContext), nil
	case "GetWiFiMonitor":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		if s.wifi == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "Wi-Fi visibility is unavailable in this daemon profile"}
		}
		return s.wifi.Status(ctx), nil
	case "SetWiFiMonitor":
		if s.wifi == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "Wi-Fi visibility is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.SetWiFiMonitorParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.Settings.Validate() != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		status, err := s.wifi.Set(ctx, params)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32090, Message: err.Error()}
		}
		return status, nil
	case "GetTrafficPolicy":
		if s.traffic == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32070, Message: "traffic policy is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		document, err := s.traffic.PolicyStore.Load()
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32071, Message: "traffic policy is unavailable"}
		}
		return document, nil
	case "GetTrafficResolverCatalog":
		if s.traffic == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32070, Message: "traffic policy is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		return trafficpolicy.BuiltinCatalog(), nil
	case "GetLabOnboarding":
		if s.traffic == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32070, Message: "traffic policy is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		return s.traffic.LabOnboarding(), nil
	case "PreviewTrafficPolicy":
		if s.traffic == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32070, Message: "traffic policy is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.PreviewTrafficPolicyParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		preview, err := s.traffic.preview(params.Policy)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32072, Message: err.Error()}
		}
		return preview, nil
	case "ApplyTrafficPolicy":
		if s.traffic == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32070, Message: "traffic policy is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.ApplyTrafficPolicyParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.ExpectedRevision == 0 {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		document, err := s.traffic.Apply(ctx, params.Policy, params.ExpectedRevision)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32073, Message: err.Error()}
		}
		return document, nil
	case "RollbackTrafficPolicy":
		if s.traffic == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32070, Message: "traffic policy is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.RollbackTrafficPolicyParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.ExpectedRevision == 0 {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		document, err := s.traffic.Rollback(ctx, params.ExpectedRevision)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32074, Message: err.Error()}
		}
		return document, nil
	case "ValidateNetworkPlan":
		var params gatewayprotocol.ValidateNetworkPlanParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		validation, _, err := s.validateNetworkPlan(ctx, params.Plan)
		if err != nil {
			s.logger.Error("network plan host inspection failed", "error", err)
			return nil, &gatewayprotocol.RPCError{Code: -32000, Message: "host inspection failed"}
		}
		return validation, nil
	case "PreviewNetworkPlan":
		var params gatewayprotocol.PreviewNetworkPlanParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		validation, hostInspection, err := s.validateNetworkPlan(ctx, params.Plan)
		if err != nil {
			s.logger.Error("network plan preview host inspection failed", "error", err)
			return nil, &gatewayprotocol.RPCError{Code: -32000, Message: "host inspection failed"}
		}
		preview := networkplan.BuildPreviewWithValidation(params.Plan, validation, time.Now())
		bindHostInspection(&preview, hostInspection)
		return preview, nil
	case "StageNetworkPlan":
		var params gatewayprotocol.StageNetworkPlanParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		if !validIdempotencyKey(params.IdempotencyKey) || params.StageTTLSeconds < 60 || params.StageTTLSeconds > 900 {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "idempotency key or stage TTL is invalid"}
		}
		validation, hostInspection, err := s.validateNetworkPlan(ctx, params.Plan)
		if err != nil {
			s.logger.Error("network plan staging host inspection failed", "error", err)
			return nil, &gatewayprotocol.RPCError{Code: -32000, Message: "host inspection failed"}
		}
		if !validation.Valid {
			return nil, &gatewayprotocol.RPCError{Code: -32020, Message: "network plan is invalid for the current host"}
		}
		if params.ExpectedPlanHash != validation.PlanHash {
			return nil, &gatewayprotocol.RPCError{Code: -32021, Message: "network plan hash changed; preview again"}
		}
		preview := networkplan.BuildPreviewWithValidation(params.Plan, validation, time.Now())
		bindHostInspection(&preview, hostInspection)
		staged, err := s.store.StageNetworkPlan(params.Plan, preview, params.IdempotencyKey, time.Now(), time.Duration(params.StageTTLSeconds)*time.Second)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32022, Message: err.Error()}
		}
		return staged, nil
	case "RollbackNetworkPlan":
		var params gatewayprotocol.RollbackNetworkPlanParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.ApplyID == "" {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		if err := s.store.RollbackStagedNetworkPlan(params.ApplyID); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32023, Message: err.Error()}
		}
		return map[string]any{"apply_id": params.ApplyID, "status": "ROLLED_BACK_BEFORE_APPLY"}, nil
	case "RevertNetworkPlan":
		if s.activation == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32030, Message: "network activation is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		state, err := s.activation.Revert(ctx)
		if s.traffic != nil {
			// Drop lab-scoped policy rules now rather than at the next tick.
			if reconcileErr := s.traffic.ReconcileNow(ctx); reconcileErr != nil {
				s.logger.Warn("traffic policy reconcile after network revert failed", "error", reconcileErr)
			}
		}
		if err != nil {
			s.logger.Error("network revert failed", "error", err)
			return nil, &gatewayprotocol.RPCError{Code: -32036, Message: boundedActivationFailure(err)}
		}
		s.logger.Info("network plan reverted; the host network is restored and ShakerProxy is in setup mode")
		return map[string]any{"operating_mode": state.OperatingMode, "emergency_bypass": state.EmergencyBypass}, nil
	case "CommitNetworkPlan":
		if s.activation == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32030, Message: "network activation is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.CommitNetworkPlanParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		if err := s.preflightNetworkCommit(ctx, params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32035, Message: err.Error()}
		}
		result, err := s.activation.Commit(ctx, params)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32031, Message: err.Error()}
		}
		return result, nil
	case "SignalNetworkHealth":
		if s.activation == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32030, Message: "network activation is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.SignalNetworkHealthParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		if err := s.activation.Signal(params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32032, Message: "management health signal was rejected"}
		}
		return map[string]any{"apply_id": params.ApplyID, "status": "MANAGEMENT_HEALTH_SIGNALLED"}, nil
	case "ConfirmNetworkPlan":
		if s.activation == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32030, Message: "network activation is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.ConfirmNetworkPlanParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.activation.Confirm(ctx, params)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32033, Message: err.Error()}
		}
		return result, nil
	case "StartCapture":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.StartCaptureParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.Request.Automatic {
			// Only gatewayd starts the automatic lab recording.
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		if !s.newCaptureAllowed() {
			return nil, &gatewayprotocol.RPCError{Code: -32044, Message: "new capture is blocked by critical CPU, memory, or disk pressure"}
		}
		source, policyRevision, err := s.captureSource(ctx)
		if err == nil && params.Request.CoverageLab {
			source, err = coverageCaptureSource(ctx)
		}
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32041, Message: err.Error()}
		}
		result, err := s.captures.Start(ctx, params.Request, source, s.store.Get().OperatingMode, policyRevision)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32042, Message: err.Error()}
		}
		return result, nil
	case "StopCapture":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.StopCaptureParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || !capture.ValidSessionID(params.SessionID) {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		// Stopping the automatic lab recording turns it off; otherwise it
		// would start again seconds later.
		if session, err := s.captures.Store.ReadSession(params.SessionID); err == nil && session.Request.Automatic {
			if err := s.store.SetLabRecording(false); err != nil {
				return nil, &gatewayprotocol.RPCError{Code: -32043, Message: "could not turn off automatic lab recording: " + err.Error()}
			}
		}
		result, err := s.captures.Stop(ctx, params.SessionID)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32043, Message: err.Error()}
		}
		return result, nil
	case "SetLabRecording":
		if s.recorder == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.SetLabRecordingParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		if err := s.store.SetLabRecording(params.Enabled); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32042, Message: "could not save the lab recording setting: " + err.Error()}
		}
		s.logger.Info("automatic lab recording setting changed", "enabled", params.Enabled)
		return s.recorder.Tick(ctx), nil
	case "GetCaptureStats":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.GetCaptureStatsParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || !capture.ValidSessionID(params.SessionID) {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.Get(ctx, params.SessionID)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32044, Message: err.Error()}
		}
		return result, nil
	case "ListCaptures":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		result, err := s.captures.List(ctx)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32044, Message: err.Error()}
		}
		return result, nil
	case "SetCaptureEvidenceHold":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.SetCaptureEvidenceHoldParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.Request.Validate() != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.SetEvidenceHold(params.Request)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32057, Message: err.Error()}
		}
		return result, nil
	case "PreviewCaptureDeletion":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.PreviewCaptureDeletionParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || !capture.ValidSessionID(params.SessionID) {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.PreviewDeletion(ctx, params.SessionID)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32046, Message: err.Error()}
		}
		return result, nil
	case "PreviewPCAPSelection":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.PreviewPCAPSelectionParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.Selection.Validate() != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.PreviewPCAPSelection(ctx, params.Selection)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32049, Message: err.Error()}
		}
		return result, nil
	case "RewritePCAP":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.RewritePCAPParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.Request.Validate() != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.RewritePCAP(ctx, params.Request)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32055, Message: err.Error()}
		}
		return result, nil
	case "DeletePCAPArtifact":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.DeletePCAPArtifactParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.Request.Validate() != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.DeletePCAPArtifact(ctx, params.Request)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32056, Message: err.Error()}
		}
		return result, nil
	case "PreviewCaptureDeletionUntil":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.PreviewCaptureDeletionUntilParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.PreviewDeletionUntil(ctx, params.SessionID, params.ExpiresAt)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32046, Message: err.Error()}
		}
		return result, nil
	case "DeleteCapture":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.DeleteCaptureParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || !capture.ValidSessionID(params.Request.SessionID) {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.Delete(ctx, params.Request)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32047, Message: err.Error()}
		}
		return result, nil
	case "ListCaptureDeletionJobs":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		result, err := s.captures.ListDeletionJobs()
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32048, Message: err.Error()}
		}
		return result, nil
	case "PreviewCaptureRetention":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.PreviewCaptureRetentionParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.Policy.Validate() != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.PreviewRetention(ctx, params.Policy)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32049, Message: err.Error()}
		}
		return result, nil
	case "GetCaptureRetentionPolicy":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		result, err := s.captures.GetRetentionPolicy()
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32050, Message: err.Error()}
		}
		return result, nil
	case "ApplyCaptureRetentionPolicy":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.ApplyCaptureRetentionPolicyParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.ApplyRetentionPolicy(ctx, params.Request)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32051, Message: err.Error()}
		}
		return result, nil
	case "StartCaptureRetentionRun":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.StartCaptureRetentionRunParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.PlanRetentionRun(ctx, params.Request)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32052, Message: err.Error()}
		}
		return result, nil
	case "RecordCaptureRetentionItemOutcome":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.RecordCaptureRetentionItemOutcomeParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.RecordRetentionItemOutcome(params.Request)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32055, Message: err.Error()}
		}
		return result, nil
	case "RunCaptureRetentionSchedulerOnce":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		status, run, err := s.captures.RunRetentionSchedulerOnce(ctx)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32056, Message: err.Error()}
		}
		return capture.RetentionSchedulerTick{Status: status, Run: run}, nil
	case "ListCaptureRetentionRuns":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		result, err := s.captures.ListRetentionRuns()
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32053, Message: err.Error()}
		}
		return result, nil
	case "GetCaptureRetentionSchedulerStatus":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		result, err := s.captures.RetentionSchedulerStatus()
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32054, Message: err.Error()}
		}
		return result, nil
	case "ReadCaptureFlow":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.ReadCaptureFlowParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || params.Request.Validate() != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.ReadFlow(ctx, params.Request)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32058, Message: err.Error()}
		}
		return result, nil
	case "ReadCaptureArtifact":
		if s.captures == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.ReadCaptureArtifactParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || !capture.ValidSessionID(params.SessionID) || params.Length < 1 || params.Length > capture.MaxArtifactChunkBytes || params.Offset < 0 {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.captures.ReadArtifactChunk(ctx, params.SessionID, params.FileName, params.Offset, params.Length)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32045, Message: err.Error()}
		}
		return result, nil
	case "BeginCaptureImport":
		if s.imports == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.BeginCaptureImportParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		sessionID, err := s.imports.Begin(params.Name, params.Description, params.Administrator, "", daemonVersion)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32046, Message: err.Error()}
		}
		return gatewayprotocol.BeginCaptureImportResult{SessionID: sessionID}, nil
	case "AppendCaptureImport":
		if s.imports == nil {
			return nil, &gatewayprotocol.RPCError{Code: -32040, Message: "capture is unavailable in this daemon profile"}
		}
		var params gatewayprotocol.AppendCaptureImportParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil || len(params.Data) > capture.ImportChunkBytes || params.Offset < 0 {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		result, err := s.imports.Append(params.SessionID, params.Offset, params.Data, params.EOF)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32046, Message: err.Error()}
		}
		if params.EOF {
			return gatewayprotocol.AppendCaptureImportResult{Done: true, Result: &result}, nil
		}
		return gatewayprotocol.AppendCaptureImportResult{Done: false}, nil
	case "SetOperatingMode":
		var params gatewayprotocol.SetOperatingModeParams
		if err := gatewayprotocol.DecodeParams(req.Params, &params); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32602, Message: "invalid parameters"}
		}
		if params.Mode != gatewayprotocol.ModeSetupSafe && params.Mode != gatewayprotocol.ModeEmergency {
			return nil, &gatewayprotocol.RPCError{Code: -32010, Message: "requested mode is unavailable in this build"}
		}
		bypass := params.Mode == gatewayprotocol.ModeEmergency
		if err := s.store.Set(params.Mode, bypass); err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32000, Message: "state update failed"}
		}
		if s.traffic != nil {
			if err := s.traffic.EnableEmergencyBypass(ctx); err != nil {
				return nil, &gatewayprotocol.RPCError{Code: -32011, Message: "operating-mode firewall cleanup failed"}
			}
		}
		return map[string]any{"operating_mode": params.Mode, "emergency_bypass": bypass}, nil
	case "GetVPN", "SetVPN", "AddVPNPeer", "SetVPNPeerDevice", "RevokeVPNPeer":
		return s.dispatchVPN(ctx, req)
	case "EnableEmergencyBypass":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		state, err := s.store.SetEmergencyBypass(true)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32000, Message: "bypass update failed"}
		}
		if s.traffic != nil {
			if err := s.traffic.EnableEmergencyBypass(ctx); err != nil {
				return nil, &gatewayprotocol.RPCError{Code: -32011, Message: "emergency bypass firewall cleanup failed"}
			}
		}
		return map[string]any{"operating_mode": state.OperatingMode, "emergency_bypass": state.EmergencyBypass}, nil
	case "DisableEmergencyBypass":
		if err := decodeEmpty(); err != nil {
			return nil, err
		}
		state, err := s.store.SetEmergencyBypass(false)
		if err != nil {
			return nil, &gatewayprotocol.RPCError{Code: -32000, Message: "bypass update failed"}
		}
		if s.traffic != nil {
			if err := s.traffic.ReconcileNow(ctx); err != nil {
				return nil, &gatewayprotocol.RPCError{Code: -32012, Message: "traffic policy restore failed; client traffic remains fail-open"}
			}
		}
		return map[string]any{"operating_mode": state.OperatingMode, "emergency_bypass": state.EmergencyBypass}, nil
	default:
		return nil, &gatewayprotocol.RPCError{Code: -32601, Message: "method not found"}
	}
}

func (s *Server) acquireConfigurationLock(ctx context.Context, request gatewayprotocol.Request) (*configlock.Guard, *gatewayprotocol.RPCError) {
	category, mutating := hostMutationCategory(request.Method)
	if !mutating || s.configLock == nil {
		return nil, nil
	}
	digest := sha256.Sum256([]byte(request.ID))
	lockContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	guard, err := s.configLock.Acquire(lockContext, configlock.Request{
		OperationID: fmt.Sprintf("rpc-%x", digest[:12]),
		Category:    category,
		Actor:       "gatewayd",
	})
	if err != nil {
		message := "another appliance configuration mutation is active"
		var busy *configlock.BusyError
		if errors.As(err, &busy) && busy.Current != nil {
			message = fmt.Sprintf("appliance configuration is locked by %s operation %s", busy.Current.Category, busy.Current.OperationID)
		}
		return nil, &gatewayprotocol.RPCError{Code: -32060, Message: message}
	}
	return guard, nil
}

func hostMutationCategory(method string) (configlock.Category, bool) {
	switch method {
	case "StageNetworkPlan", "RollbackNetworkPlan", "ConfirmNetworkPlan", "SetOperatingMode", "EnableEmergencyBypass", "DisableEmergencyBypass":
		return configlock.CategoryNetwork, true
	case "StartCapture", "StopCapture", "SetWiFiMonitor":
		return configlock.CategoryCapture, true
	case "SetCaptureEvidenceHold", "ApplyCaptureRetentionPolicy":
		return configlock.CategoryRetention, true
	case "ApplyTrafficPolicy", "RollbackTrafficPolicy":
		return configlock.CategoryDNS, true
	case "SetVPN", "AddVPNPeer", "SetVPNPeerDevice", "RevokeVPNPeer":
		return configlock.CategoryNetwork, true
	default:
		return "", false
	}
}

func cloneVLANID(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func maskedIPv4CIDR(value string) string {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return ""
	}
	return prefix.Masked().String()
}

func (s *Server) captureSource(ctx context.Context) (capture.Source, string, error) {
	state := s.store.Get()
	active := state.activeNetworkPlan()
	if state.EmergencyBypass || state.OperatingMode != gatewayprotocol.ModeRouted || active == nil {
		return capture.Source{}, "", errors.New("capture requires a confirmed routed network plan and emergency bypass disabled")
	}
	plannedValue, ok := labCaptureInterface(active.Plan)
	if !ok {
		return capture.Source{}, "", errors.New("confirmed network plan has no lab ingress interface")
	}
	planned := &plannedValue
	host, err := inspectHost(ctx)
	if err != nil {
		return capture.Source{}, "", errors.New("capture interface inspection failed")
	}
	for _, observed := range host.Interfaces {
		if labIngressMatches(*planned, observed) {
			if observed.OperState != "up" || observed.Carrier != "1" {
				return capture.Source{}, "", errors.New("lab ingress interface is not operational")
			}
			source := capture.Source{InterfaceName: observed.Name, InterfaceStableID: observed.StableID}
			if plan := active.Plan; plan.Topology == networkplan.TopologySingleArm {
				source.SingleArmGateway, source.SingleArmLabCIDR = labGatewayIPv4(plan), maskedIPv4CIDR(plan.IPv4.LabCIDR)
			}
			if name, stableID, ok := bridgeAccessPointSource(active.Plan); ok {
				source.AccessPointName, source.AccessPointStableID = name, stableID
			}
			return source, labRecordingRevisionFor(*active, source.AccessPointName != ""), nil
		}
	}
	return capture.Source{}, "", errors.New("confirmed lab ingress interface identity is no longer present")
}

// bridgeAccessPointSource returns the inline bridge's Wi-Fi access point for
// the lab recording when it is up and is the adapter the plan names. It
// reads only that interface from sysfs, so the lab recorder can ask on every
// check.
var bridgeAccessPointSource = func(plan networkplan.Plan) (name, stableID string, ok bool) {
	ap, ok := networkplan.BridgeAccessPoint(plan)
	if !ok {
		return "", "", false
	}
	iface, err := net.InterfaceByName(ap.CurrentName)
	if err != nil {
		return "", "", false
	}
	details := interfaceDetails(iface.Name, iface.HardwareAddr.String())
	if details.StableID != ap.StableID || details.OperState != "up" || details.Carrier != "1" {
		return "", "", false
	}
	return iface.Name, details.StableID, true
}

// accessPointRevisionSuffix marks a lab recording that includes the inline
// bridge's access point.
const accessPointRevisionSuffix = "+wifi"

// labRecordingRevision names what the lab recording should record: the
// plan, and whether the inline bridge's access point is up to be recorded
// beside the device port. When the access point comes up after the
// recording started (hostapd starts after the bridge) or goes away, the
// revision changes and the lab recorder restarts the recording to match.
func labRecordingRevision(plan networkplan.StagedPlan) string {
	_, _, recorded := bridgeAccessPointSource(plan.Plan)
	return labRecordingRevisionFor(plan, recorded)
}

func labRecordingRevisionFor(plan networkplan.StagedPlan, accessPoint bool) string {
	if accessPoint {
		return plan.PlanHash + accessPointRevisionSuffix
	}
	return plan.PlanHash
}

// labCaptureInterface is the interface the lab recording records. An inline
// bridge is recorded on its device port, where frames are as they were on
// the wire: on the bridge itself br_netfilter has already rewritten a
// redirected DNS query's destination to ShakerProxy's own address.
func labCaptureInterface(plan networkplan.Plan) (networkplan.Interface, bool) {
	if _, device, bridged := networkplan.BridgePorts(plan); bridged {
		return device, true
	}
	return networkplan.LabInterface(plan)
}

// coverageLabBridge is the virtual test lab's client bridge
// (host/testlab), the only interface a coverage capture may record.
const coverageLabBridge = "lgtest-client"

// coverageCaptureSource records the virtual test lab's client bridge for the
// visibility coverage check, so its probes cross the production capture and
// analyzer path. The caller has already required a confirmed routed lab.
func coverageCaptureSource(ctx context.Context) (capture.Source, error) {
	host, err := inspectHost(ctx)
	if err != nil {
		return capture.Source{}, errors.New("capture interface inspection failed")
	}
	return coverageSourceFrom(host)
}

func coverageSourceFrom(host gatewayprotocol.HostInspection) (capture.Source, error) {
	for _, observed := range host.Interfaces {
		if observed.Name == coverageLabBridge && observed.OperState != "down" {
			return capture.Source{InterfaceName: observed.Name, InterfaceStableID: observed.StableID}, nil
		}
	}
	return capture.Source{}, errors.New("the virtual test lab is not prepared; run the visibility coverage check from ShakerProxy")
}

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func inspectHost(ctx context.Context) (gatewayprotocol.HostInspection, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return gatewayprotocol.HostInspection{}, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return gatewayprotocol.HostInspection{}, err
	}
	result := gatewayprotocol.HostInspection{Hostname: hostname, OperatingSystem: runtime.GOOS, Architecture: runtime.GOARCH, Kernel: kernelRelease(), Firewall: firewall.DefaultInspector().Inspect(ctx), NetworkConfig: inspectNetworkConfiguration()}
	defaultIPv4, defaultIPv6, _ := diagnosticDefaultRouteInterfaces()
	wireless := newWirelessInspector()
	for _, iface := range interfaces {
		details := interfaceDetails(iface.Name, iface.HardwareAddr.String())
		item := gatewayprotocol.Interface{Name: iface.Name, StableID: details.StableID, HardwareAddr: iface.HardwareAddr.String(), Driver: details.Driver, DevicePath: details.DevicePath, OperState: details.OperState, Carrier: details.Carrier, SpeedMbps: details.SpeedMbps, MTU: iface.MTU, DefaultIPv4: defaultIPv4[iface.Name], DefaultIPv6: defaultIPv6[iface.Name]}
		item.Wireless, item.APSupported, item.WirelessBands = wireless.inspect(ctx, iface.Name)
		for _, flag := range []struct {
			value net.Flags
			name  string
		}{{net.FlagUp, "up"}, {net.FlagBroadcast, "broadcast"}, {net.FlagLoopback, "loopback"}, {net.FlagPointToPoint, "point_to_point"}, {net.FlagMulticast, "multicast"}} {
			if iface.Flags&flag.value != 0 {
				item.Flags = append(item.Flags, flag.name)
			}
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			item.Addresses = append(item.Addresses, address.String())
		}
		result.Interfaces = append(result.Interfaces, item)
	}
	interfaceAddresses := make(map[string][]string, len(result.Interfaces))
	for _, iface := range result.Interfaces {
		interfaceAddresses[iface.Name] = iface.Addresses
	}
	result.ActiveSSH, err = activeSSHSessions(ctx, interfaceAddresses)
	if err != nil {
		return gatewayprotocol.HostInspection{}, err
	}
	return result, nil
}

func (s *Server) validateNetworkPlan(ctx context.Context, plan networkplan.Plan) (networkplan.ValidationResult, gatewayprotocol.HostInspection, error) {
	host, err := inspectHost(ctx)
	if err != nil {
		return networkplan.ValidationResult{}, gatewayprotocol.HostInspection{}, err
	}
	observed := make([]networkplan.ObservedInterface, 0, len(host.Interfaces))
	for _, iface := range host.Interfaces {
		observed = append(observed, networkplan.ObservedInterface{CurrentName: iface.Name, StableID: iface.StableID, Addresses: iface.Addresses, DefaultIPv4: iface.DefaultIPv4, DefaultIPv6: iface.DefaultIPv6, CloudInitManaged: host.NetworkConfig.CloudInitManaged})
	}
	result := networkplan.ValidateWithObservedSSH(plan, observed, host.ActiveSSH)
	result = networkplan.ValidateWiFiHost(result, plan, wifiHostEvidence(ctx, plan, host, hostapdInstalled, networkManagerActive))
	return networkplan.ValidateNetworkManagerHost(result, plan, networkManagerEvidence(ctx)), host, nil
}

func inspectNetworkConfiguration() gatewayprotocol.NetworkConfiguration {
	result := gatewayprotocol.NetworkConfiguration{Owner: "unknown", NetplanFiles: []string{}}
	entries, err := os.ReadDir("/etc/netplan")
	if err != nil {
		return result
	}
	for _, entry := range entries {
		name := entry.Name()
		if len(result.NetplanFiles) >= 64 || len(name) > 255 || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}
		result.NetplanFiles = append(result.NetplanFiles, name)
		if strings.Contains(strings.ToLower(name), "cloud-init") {
			result.CloudInitManaged = true
		}
	}
	sort.Strings(result.NetplanFiles)
	if result.CloudInitManaged {
		result.Owner = "cloud-init"
	} else if len(result.NetplanFiles) > 0 {
		result.Owner = "netplan"
	}
	return result
}

func (s *Server) preflightNetworkCommit(ctx context.Context, params gatewayprotocol.CommitNetworkPlanParams) error {
	state := s.store.Get()
	staged := state.StagedNetworkPlan
	if staged == nil || staged.ApplyID != params.ApplyID || staged.PlanHash != params.PlanHash {
		return errors.New("network commit does not match the staged plan")
	}
	validation, host, err := s.validateNetworkPlan(ctx, staged.Plan)
	if err != nil {
		return errors.New("network commit host inspection failed")
	}
	if !validation.Valid || validation.PlanHash != staged.PlanHash {
		return errors.New("network plan is no longer valid for the current host; preview and stage again")
	}
	if !equalActiveSSH(staged.Preview.ActiveSSH, host.ActiveSSH) || !reflect.DeepEqual(staged.Preview.FirewallEnvironment, host.Firewall) {
		return errors.New("network plan host evidence changed; preview and stage again")
	}
	return nil
}

func equalActiveSSH(left, right []networkplan.ActiveSSHSession) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func bindHostInspection(preview *networkplan.Preview, inspection gatewayprotocol.HostInspection) {
	preview.FirewallEnvironment = inspection.Firewall
	preview.ActiveSSH = append([]networkplan.ActiveSSHSession(nil), inspection.ActiveSSH...)
	if inspection.Firewall.SelectedBackend != "" {
		preview.FirewallBackend = inspection.Firewall.SelectedBackend
	} else {
		preview.FirewallBackend = "unavailable"
	}
	if !inspection.Firewall.ApplyReady {
		preview.Impact = append(preview.Impact, "Host apply remains blocked by firewall coexistence preflight")
	}
	networkplan.BindIPv6HostEvidence(preview)
	if len(inspection.ActiveSSH) != 0 {
		preview.Impact = append(preview.Impact, "Active SSH path is bound to the observed source, destination, and interface")
	}
}

func (s *Server) auditDetails(req gatewayprotocol.Request, result any) (string, []string) {
	switch value := result.(type) {
	case networkplan.ValidationResult:
		return value.PlanHash, nil
	case networkplan.Preview:
		return value.Validation.PlanHash, value.ChangedObjects
	case networkplan.StagedPlan:
		return value.PlanHash, value.Preview.ChangedObjects
	case gatewayprotocol.CommitNetworkPlanResult:
		return value.PlanHash, s.changedObjectsFor(value.ApplyID)
	case capture.View:
		return value.Session.PolicyRevision, captureAuditObjects(value.Session.ID)
	case capture.EvidenceHold:
		caseID := value.CaseID
		if caseID == "" && len(value.History) > 0 {
			caseID = value.History[len(value.History)-1].CaseID
		}
		return "", append(captureAuditObjects(value.SessionID), fmt.Sprintf("case %s evidence hold revision %d", caseID, value.Revision))
	case capture.ArtifactChunk:
		return "", append(captureAuditObjects(value.SessionID), "capture export "+value.FileName)
	case capture.DeletionPreview:
		return value.PreviewSHA256, append(captureAuditObjects(value.SessionID), "capture deletion preview")
	case capture.DeletionJob:
		return value.PreviewSHA256, append(captureAuditObjects(value.SessionID), "capture deletion job "+value.ID)
	case capture.RetentionPreview:
		return value.PreviewSHA256, []string{fmt.Sprintf("capture retention preview (%d selected, %d locked)", len(value.Selected), len(value.BlockedByRetentionLock))}
	case capture.RetentionPolicy:
		return value.PreviewSHA256, []string{fmt.Sprintf("capture retention policy revision %d", value.Revision)}
	case capture.RetentionRun:
		return value.PreviewSHA256, []string{fmt.Sprintf("capture retention run %s (%d deleted, %d failed)", value.ID, value.DeletedSessions, value.FailedSessions)}
	case capture.RetentionSchedulerTick:
		if value.Run != nil {
			return value.Run.PreviewSHA256, []string{fmt.Sprintf("automatic capture retention run %s planned", value.Run.ID)}
		}
		return "", []string{"automatic capture retention scheduler check"}
	case gatewayprotocol.TrafficPolicyPreview:
		return value.Digest, value.ChangedObjects
	case trafficpolicy.Document:
		return value.Digest, []string{"traffic policy state", fmt.Sprintf("traffic policy revision %d", value.Policy.Revision)}
	}
	var applyID, planHash string
	switch req.Method {
	case "CommitNetworkPlan":
		var params gatewayprotocol.CommitNetworkPlanParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil {
			applyID, planHash = params.ApplyID, params.PlanHash
		}
	case "SignalNetworkHealth":
		var params gatewayprotocol.SignalNetworkHealthParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil {
			applyID, planHash = params.ApplyID, params.PlanHash
		}
	case "ConfirmNetworkPlan":
		var params gatewayprotocol.ConfirmNetworkPlanParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil {
			applyID, planHash = params.ApplyID, params.PlanHash
		}
	case "RollbackNetworkPlan":
		var params gatewayprotocol.RollbackNetworkPlanParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil {
			applyID = params.ApplyID
		}
	case "ReadCaptureArtifact":
		var params gatewayprotocol.ReadCaptureArtifactParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil && capture.ValidSessionID(params.SessionID) {
			return "", append(captureAuditObjects(params.SessionID), "capture export "+params.FileName)
		}
	case "ReadCaptureFlow":
		var params gatewayprotocol.ReadCaptureFlowParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil && params.Request.Validate() == nil {
			return "", append(captureAuditObjects(params.Request.SessionID), "capture flow "+params.Request.Client+" -> "+params.Request.Server)
		}
	case "PreviewCaptureDeletion":
		var params gatewayprotocol.PreviewCaptureDeletionParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil && capture.ValidSessionID(params.SessionID) {
			return "", append(captureAuditObjects(params.SessionID), "capture deletion preview")
		}
	case "SetCaptureEvidenceHold":
		var params gatewayprotocol.SetCaptureEvidenceHoldParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil && params.Request.Validate() == nil {
			return "", append(captureAuditObjects(params.Request.SessionID), "case "+params.Request.CaseID+" evidence hold")
		}
	case "PreviewPCAPSelection":
		return "", []string{"shared PCAP packet-selection preview"}
	case "RewritePCAP":
		var params gatewayprotocol.RewritePCAPParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil && params.Request.Validate() == nil {
			return params.Request.OriginalSHA256, append(captureAuditObjects(params.Request.SessionID), "capture artifact "+params.Request.FileName, "PCAP rewrite "+params.Request.ID)
		}
	case "DeletePCAPArtifact":
		var params gatewayprotocol.DeletePCAPArtifactParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil && params.Request.Validate() == nil {
			return params.Request.OriginalSHA256, append(captureAuditObjects(params.Request.SessionID), "capture artifact "+params.Request.FileName, "PCAP artifact deletion "+params.Request.ID)
		}
	case "PreviewCaptureDeletionUntil":
		var params gatewayprotocol.PreviewCaptureDeletionUntilParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil && capture.ValidSessionID(params.SessionID) {
			return "", append(captureAuditObjects(params.SessionID), "capture retention deletion preview")
		}
	case "DeleteCapture":
		var params gatewayprotocol.DeleteCaptureParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil && capture.ValidSessionID(params.Request.SessionID) {
			return params.Request.PreviewSHA256, append(captureAuditObjects(params.Request.SessionID), "capture deletion request")
		}
	case "PreviewCaptureRetention":
		return "", []string{"capture retention preview"}
	case "ApplyCaptureRetentionPolicy":
		var params gatewayprotocol.ApplyCaptureRetentionPolicyParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil {
			return params.Request.PreviewSHA256, []string{"capture retention policy"}
		}
	case "StartCaptureRetentionRun":
		var params gatewayprotocol.StartCaptureRetentionRunParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil {
			return params.Request.PreviewSHA256, []string{"capture retention run"}
		}
	case "RecordCaptureRetentionItemOutcome":
		var params gatewayprotocol.RecordCaptureRetentionItemOutcomeParams
		if gatewayprotocol.DecodeParams(req.Params, &params) == nil {
			objects := []string{"capture retention run " + params.Request.RunID, "capture session " + params.Request.SessionID}
			if params.Request.CoordinatedDeletionJobID != "" {
				objects = append(objects, "coordinated deletion "+params.Request.CoordinatedDeletionJobID)
			}
			return "", objects
		}
	case "RunCaptureRetentionSchedulerOnce":
		return "", []string{"automatic capture retention scheduler check"}
	}
	if applyID != "" {
		state := s.store.Get().StagedNetworkPlan
		if state != nil && state.ApplyID == applyID {
			if planHash == "" {
				planHash = state.PlanHash
			}
			return planHash, state.Preview.ChangedObjects
		}
	}
	return planHash, nil
}

func captureAuditObjects(id string) []string {
	if !capture.ValidSessionID(id) {
		return nil
	}
	return []string{
		"capture session " + id,
		"shakerproxy-capture@" + strings.TrimPrefix(id, "capture-") + ".service",
		filepath.Join(capture.DefaultRoot, id),
	}
}

func (s *Server) changedObjectsFor(applyID string) []string {
	staged := s.store.Get().StagedNetworkPlan
	if staged == nil || staged.ApplyID != applyID {
		return nil
	}
	return staged.Preview.ChangedObjects
}
