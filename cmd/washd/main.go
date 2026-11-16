// Command washd is the persistent per-user shell manager: it owns the
// user's wosh sessions, links to wash-web and verifies passkeys itself.
// Normally started with `wash up` (or the systemd user unit from
// `wash service install`).
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"wash/internal/manager"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("washd", version)
		return
	}
	manager.Version = version
	log.SetFlags(log.LstdFlags)
	m, err := manager.New()
	if err != nil {
		log.Fatal(err)
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)
	go func() {
		<-sigs
		m.Stop()
	}()
	log.Printf("washd %s starting (pid %d)", version, os.Getpid())
	if err := m.Run(); err != nil {
		log.Fatal(err)
	}
	log.Printf("washd stopped (sessions keep running)")
}
