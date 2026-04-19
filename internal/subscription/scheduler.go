package subscription

import (
	"context"
	"fmt"
	"strings"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
)

const (
	defaultAutoUpdateCheckInterval  = time.Minute
	defaultAutoUpdateRequestTimeout = 90 * time.Second
)

type subscriptionUpdater interface {
	UpdateSubscription(ctx context.Context, sub *config.ProxySubscription) (*UpdateResult, error)
}

type Scheduler struct {
	configMgr          *config.ProxySubscriptionConfigManager
	updater            subscriptionUpdater
	activeSessionCount func() int
	afterUpdate        func(sub *config.ProxySubscription, result *UpdateResult)
	now                func() time.Time
	checkInterval      time.Duration
	requestTimeout     time.Duration
}

func NewScheduler(configMgr *config.ProxySubscriptionConfigManager, updater subscriptionUpdater, activeSessionCount func() int) *Scheduler {
	return &Scheduler{
		configMgr:          configMgr,
		updater:            updater,
		activeSessionCount: activeSessionCount,
		now:                time.Now,
		checkInterval:      defaultAutoUpdateCheckInterval,
		requestTimeout:     defaultAutoUpdateRequestTimeout,
	}
}

func (s *Scheduler) SetAfterUpdateHook(callback func(sub *config.ProxySubscription, result *UpdateResult)) {
	if s == nil {
		return
	}
	s.afterUpdate = callback
}

func (s *Scheduler) Start(ctx context.Context) {
	if s == nil || s.configMgr == nil || s.updater == nil {
		return
	}
	go s.loop(ctx)
}

func (s *Scheduler) loop(ctx context.Context) {
	ticker := time.NewTicker(s.intervalOrDefault())
	defer ticker.Stop()

	s.runOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

func (s *Scheduler) runOnce(ctx context.Context) {
	now := s.nowFunc()()
	due := make([]*config.ProxySubscription, 0)
	for _, sub := range s.configMgr.GetAllSubscriptions() {
		if ready, reason, err := subscriptionAutoUpdateDue(sub, now); err != nil {
			logger.Warn("Subscription auto update skipped for %q: %v", sub.Name, err)
		} else if ready {
			logger.Debug("Subscription auto update due: %s (%s)", sub.Name, reason)
			due = append(due, sub)
		}
	}
	if len(due) == 0 {
		return
	}
	if s.activeSessionCount != nil && s.activeSessionCount() > 0 {
		logger.Debug("Subscription auto update deferred: %d subscription(s) due but active sessions > 0", len(due))
		return
	}
	for _, sub := range due {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.updateOne(ctx, sub, now)
	}
}

func (s *Scheduler) updateOne(ctx context.Context, sub *config.ProxySubscription, attemptAt time.Time) {
	if sub == nil {
		return
	}
	sub.AutoUpdateLastAttemptAt = attemptAt
	if err := s.configMgr.UpdateSubscription(sub.ID, sub); err != nil {
		logger.Warn("Subscription auto update failed to persist attempt for %q: %v", sub.Name, err)
		return
	}

	updateCtx, cancel := context.WithTimeout(ctx, s.timeoutOrDefault())
	defer cancel()

	result, err := s.updater.UpdateSubscription(updateCtx, sub)
	if err != nil {
		sub.LastError = err.Error()
		if persistErr := s.configMgr.UpdateSubscription(sub.ID, sub); persistErr != nil {
			logger.Warn("Subscription auto update failed to persist error for %q: %v", sub.Name, persistErr)
		}
		logger.Warn("Subscription auto update failed: %s: %v", sub.Name, err)
		return
	}

	sub.LastUpdatedAt = attemptAt
	sub.LastNodeCount = result.NodeCount
	sub.LastAdded = result.AddedCount
	sub.LastUpdated = result.UpdatedCount
	sub.LastRemoved = result.RemovedCount
	sub.LastSubscriptionUploadBytes = result.SubscriptionUploadBytes
	sub.LastSubscriptionDownloadBytes = result.SubscriptionDownloadBytes
	sub.LastSubscriptionTotalBytes = result.SubscriptionTotalBytes
	if result.SubscriptionExpireAt != nil {
		sub.LastSubscriptionExpireAt = result.SubscriptionExpireAt.UTC()
	} else {
		sub.LastSubscriptionExpireAt = time.Time{}
	}
	sub.LastError = ""
	if err := s.configMgr.UpdateSubscription(sub.ID, sub); err != nil {
		logger.Warn("Subscription auto update failed to persist result for %q: %v", sub.Name, err)
		return
	}
	logger.Info("Subscription auto update complete: %s (+%d ~%d -%d, total=%d)", sub.Name, result.AddedCount, result.UpdatedCount, result.RemovedCount, result.NodeCount)
	if s.afterUpdate != nil {
		s.afterUpdate(sub.Clone(), result)
	}
}

func subscriptionAutoUpdateDue(sub *config.ProxySubscription, now time.Time) (bool, string, error) {
	if sub == nil || !sub.Enabled || !sub.IsAutoUpdateEnabled() {
		return false, "", nil
	}
	switch sub.GetAutoUpdateMode() {
	case config.ProxySubscriptionAutoUpdateModeDaily:
		hour, minute, err := parseAutoUpdateClock(sub.GetAutoUpdateTime())
		if err != nil {
			return false, "", err
		}
		scheduledAt := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
		if now.Before(scheduledAt) {
			return false, "", nil
		}
		if !sub.AutoUpdateLastAttemptAt.Before(scheduledAt) {
			return false, "", nil
		}
		return true, fmt.Sprintf("daily@%s", sub.GetAutoUpdateTime()), nil
	case config.ProxySubscriptionAutoUpdateModeInterval:
		intervalDays := sub.GetAutoUpdateIntervalDays()
		lastAttemptAt := sub.AutoUpdateLastAttemptAt
		if lastAttemptAt.IsZero() {
			return false, "", nil
		}
		nextDueAt := lastAttemptAt.Add(time.Duration(intervalDays) * 24 * time.Hour)
		if now.Before(nextDueAt) {
			return false, "", nil
		}
		return true, fmt.Sprintf("interval/%dd", intervalDays), nil
	default:
		return false, "", fmt.Errorf("unsupported auto update mode: %s", sub.AutoUpdateMode)
	}
}

func parseAutoUpdateClock(value string) (int, int, error) {
	parsed, err := time.Parse("15:04", strings.TrimSpace(value))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid auto update time %q", value)
	}
	return parsed.Hour(), parsed.Minute(), nil
}

func (s *Scheduler) nowFunc() func() time.Time {
	if s != nil && s.now != nil {
		return s.now
	}
	return time.Now
}

func (s *Scheduler) intervalOrDefault() time.Duration {
	if s != nil && s.checkInterval > 0 {
		return s.checkInterval
	}
	return defaultAutoUpdateCheckInterval
}

func (s *Scheduler) timeoutOrDefault() time.Duration {
	if s != nil && s.requestTimeout > 0 {
		return s.requestTimeout
	}
	return defaultAutoUpdateRequestTimeout
}
