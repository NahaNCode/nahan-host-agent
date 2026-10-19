package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ProbeAttempt struct {
	Method     string    `json:"method"`
	Port       int       `json:"port"`
	StartedAt  time.Time `json:"startedAt"`
	DurationMS int64     `json:"durationMs"`
	Outcome    string    `json:"outcome"`
}
type ProbeEvidence struct {
	ID             string            `json:"id"`
	CheckedAt      time.Time         `json:"checkedAt"`
	DurationMS     int64             `json:"durationMs"`
	BudgetExpired  bool              `json:"budgetExpired"`
	BootID         string            `json:"bootId"`
	AgentPID       int               `json:"agentPid"`
	AgentStartedAt time.Time         `json:"agentStartedAt"`
	Attempts       []ProbeAttempt    `json:"attempts"`
	Counters       map[string]uint64 `json:"counters,omitempty"`
}

var agentStartedAt = time.Now().UTC()

type probeSelection struct {
	signature string
	recorded  time.Time
}

// At most 12 evidence records/minute/agent, with sparse successful baselines.
func (c *Client) selectProbe(r *Receipt) {
	if r.Probe == nil {
		return
	}
	now := r.Probe.CheckedAt
	if c.probeSelection == nil {
		c.probeSelection = map[string]probeSelection{}
	}
	if len(c.probeSelection) > 256 {
		c.probeSelection = map[string]probeSelection{}
	}
	parts := []string{strconv.FormatBool(r.PeerAlive), strconv.FormatBool(r.Probe.BudgetExpired), r.Probe.BootID}
	for _, a := range r.Probe.Attempts {
		parts = append(parts, a.Method, strconv.Itoa(a.Port), a.Outcome)
	}
	signature := strings.Join(parts, ":")
	previous, seen := c.probeSelection[r.ID]
	interval := 5 * time.Minute
	if !r.PeerAlive {
		interval = time.Minute
	}
	if seen && signature == previous.signature && now.Sub(previous.recorded) < interval {
		r.Probe = nil
		return
	}
	if c.probeWindow.IsZero() || now.Sub(c.probeWindow) >= time.Minute {
		c.probeWindow = now
		c.probeCount = 0
	}
	if c.probeCount >= 12 {
		r.Probe = nil
		return
	}
	c.probeCount++
	c.probeSelection[r.ID] = probeSelection{signature, now}
}

// Classifications never include raw commands, configuration, or credentials.
func probeError(ctx context.Context, err error) string {
	if err == nil {
		return "ok"
	}
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "cycle_deadline"
		}
		return "cycle_canceled"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(err, syscall.ENETUNREACH) {
		return "network_unreachable"
	}
	if errors.Is(err, syscall.EHOSTUNREACH) {
		return "host_unreachable"
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return "permission_denied"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	return "probe_failed"
}

func (n Network) ProbeDetailed(ctx context.Context, t Tunnel) (bool, string, int, *ProbeEvidence) {
	start := time.Now().UTC()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return false, "none", 0, nil
	}
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	e := &ProbeEvidence{ID: hex.EncodeToString(id[:]), CheckedAt: start, BootID: strings.TrimSpace(string(boot)), AgentPID: os.Getpid(), AgentStartedAt: agentStartedAt, Attempts: []ProbeAttempt{}}
	finish := func(alive bool, method string, port int) (bool, string, int, *ProbeEvidence) {
		e.DurationMS = time.Since(start).Milliseconds()
		e.BudgetExpired = ctx.Err() != nil
		e.Counters = map[string]uint64{}
		if Validate(t) == nil {
			for _, key := range []string{"rx_packets", "tx_packets", "rx_dropped", "tx_dropped", "rx_errors", "tx_errors"} {
				data, err := os.ReadFile(filepath.Join("/sys/class/net", t.Name(), "statistics", key))
				if err == nil {
					if value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
						e.Counters[key] = value
					}
				}
			}
		}
		return alive, method, port, e
	}
	if Validate(t) != nil {
		return finish(false, "none", 0)
	}
	for _, port := range t.PeerTCPPorts {
		if ctx.Err() != nil {
			break
		}
		attempt := time.Now().UTC()
		var err error
		if p, ok := n.Runner.(interface {
			ProbeTCPError(context.Context, Tunnel, int) error
		}); ok {
			err = p.ProbeTCPError(ctx, t, port)
		} else if p, ok := n.Runner.(interface {
			ProbeTCP(context.Context, Tunnel, int) bool
		}); ok {
			if !p.ProbeTCP(ctx, t, port) {
				err = errors.New("probe failed")
			}
		} else {
			break
		}
		e.Attempts = append(e.Attempts, ProbeAttempt{"tcp", port, attempt, time.Since(attempt).Milliseconds(), probeError(ctx, err)})
		if err == nil {
			return finish(true, "tcp", port)
		}
	}
	if ctx.Err() == nil {
		attempt := time.Now().UTC()
		_, err := n.Runner.Run(ctx, "ping", "-n", "-c", "2", "-W", "2", "-I", t.Name(), t.Peer)
		e.Attempts = append(e.Attempts, ProbeAttempt{"icmp", 0, attempt, time.Since(attempt).Milliseconds(), probeError(ctx, err)})
		if err == nil {
			return finish(true, "icmp", 0)
		}
	}
	return finish(false, "none", 0)
}

// Keep evidence even when posting the heartbeat fails. Two bounded private files.
func (c *Client) recordProbe(r Receipt) error {
	if r.Probe == nil {
		return nil
	}
	path := c.Config.StateFile + ".probes.jsonl"
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("unsafe probe journal")
		}
		if info.Size() > 1<<20 {
			if err := os.Rename(path, path+".previous"); err != nil {
				return err
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(data) > 4096 {
		return errors.New("probe evidence too large")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
