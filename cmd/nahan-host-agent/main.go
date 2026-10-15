package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/NahaNCode/nahan-host-agent/internal/agent"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	path := flag.String("config", "/etc/nahan-host-agent/config.json", "Enrollment package")
	check := flag.Bool("check-enrollment", false, "verify enrollment only; no state or network changes")
	checkRoute := flag.Int("check-route", 0, "with --check-enrollment: 1 or 2 verifies a specific private endpoint")
	flag.Parse()
	b, e := os.ReadFile(*path)
	if e != nil {
		log.Fatal("configuration unavailable")
	}
	var cfg agent.Config
	if json.Unmarshal(b, &cfg) != nil {
		log.Fatal("invalid configuration")
	}
	c, e := agent.New(cfg)
	if e != nil {
		log.Fatal(e)
	}
	if *check {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		m, e := c.CheckEnrollment(ctx, *checkRoute)
		if e != nil {
			log.Fatal(e)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"revision": m.Revision, "managedLinks": len(m.Tunnels), "endpointSetVersion": agent.EndpointSetVersion})
		log.Print("enrollment verified; no host settings changed")
		return
	}
	if e = os.MkdirAll(filepath.Dir(cfg.StateFile), 0700); e != nil {
		log.Fatal("state directory unavailable")
	}
	lock, e := os.OpenFile(cfg.StateFile+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		log.Fatal("state lock unavailable")
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		log.Fatal("another agent is using this state")
	}
	if e = c.Load(); e != nil {
		log.Fatal("state unavailable; refusing network changes")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	closePlacement, e := c.StartPlacement(ctx)
	if e != nil {
		log.Print("local placement reporting unavailable")
	} else {
		defer closePlacement()
	}
	for {
		tick, cancel := context.WithTimeout(ctx, 45*time.Second)
		e = c.Tick(tick)
		cancel()
		if e != nil {
			log.Print(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
}
