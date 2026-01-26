package proxy

import (
	"context"

	"mcpeserverproxy/internal/config"
)

type combinedListener struct {
	listeners []Listener
}

func newCombinedListener(listeners ...Listener) *combinedListener {
	combined := make([]Listener, 0, len(listeners))
	for _, l := range listeners {
		if l != nil {
			combined = append(combined, l)
		}
	}
	return &combinedListener{listeners: combined}
}

func (c *combinedListener) Start() error {
	for i, l := range c.listeners {
		if err := l.Start(); err != nil {
			for j := 0; j < i; j++ {
				_ = c.listeners[j].Stop()
			}
			return err
		}
	}
	return nil
}

func (c *combinedListener) Listen(ctx context.Context) error {
	if len(c.listeners) == 0 {
		return nil
	}

	errCh := make(chan error, len(c.listeners))
	for _, l := range c.listeners {
		go func(listener Listener) {
			errCh <- listener.Listen(ctx)
		}(l)
	}

	var firstErr error
	for i := 0; i < len(c.listeners); i++ {
		err := <-errCh
		if err != nil && err != context.Canceled && firstErr == nil {
			firstErr = err
			for _, l := range c.listeners {
				_ = l.Stop()
			}
		}
	}
	return firstErr
}

func (c *combinedListener) Stop() error {
	for _, l := range c.listeners {
		_ = l.Stop()
	}
	return nil
}

func (c *combinedListener) UpdateConfig(cfg *config.ServerConfig) {
	for _, l := range c.listeners {
		if updater, ok := l.(interface{ UpdateConfig(*config.ServerConfig) }); ok {
			updater.UpdateConfig(cfg)
		}
	}
}
