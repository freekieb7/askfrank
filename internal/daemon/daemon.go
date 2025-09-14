package daemon

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DaemonFunc represents the work a daemon does.
type DaemonFunc func(ctx context.Context, name string) error

// DaemonManager supervises multiple daemons.
type DaemonManager struct {
	daemons map[string]DaemonFunc
	wg      sync.WaitGroup
}

// NewDaemonManager creates a new manager.
func NewDaemonManager() *DaemonManager {
	return &DaemonManager{
		daemons: make(map[string]DaemonFunc),
	}
}

// Add registers a daemon by name.
func (m *DaemonManager) Add(name string, fn DaemonFunc) {
	m.daemons[name] = fn
}

// Start runs all daemons and restarts them if they crash.
func (m *DaemonManager) Start(ctx context.Context) {
	for name, fn := range m.daemons {
		m.wg.Add(1)
		go m.runDaemon(ctx, name, fn)
	}
}

// Wait blocks until all daemons have stopped.
func (m *DaemonManager) Wait() {
	m.wg.Wait()
}

// runDaemon supervises a single daemon, restarting on error.
func (m *DaemonManager) runDaemon(ctx context.Context, name string, fn DaemonFunc) {
	defer m.wg.Done()

	for {
		select {
		case <-ctx.Done():
			fmt.Println(name, "received shutdown signal")
			return
		default:
			// Run daemon
			err := fn(ctx, name)
			if err != nil {
				fmt.Println(name, "crashed with error:", err, "— restarting in 2s")
				time.Sleep(2 * time.Second)
				continue
			}
			// Daemon exited cleanly
			fmt.Println(name, "exited cleanly")
			return
		}
	}
}

//
// Example daemons
//

func daemonA(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("daemonA shutting down...")
			return nil
		case t := <-ticker.C:
			fmt.Println("daemonA tick:", t)
			// simulate crash
			if t.Second()%10 == 0 {
				return fmt.Errorf("simulated failure at %v", t)
			}
		}
	}
}

func daemonB(ctx context.Context) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("daemonB shutting down...")
			return nil
		case t := <-ticker.C:
			fmt.Println("daemonB tick:", t)
		}
	}
}
