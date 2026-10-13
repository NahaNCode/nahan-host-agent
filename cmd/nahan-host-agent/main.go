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
