package heartbeat

import (
	"context"
	"sync"
	"time"

	"github.com/palomachain/pigeon/internal/liblog"
	"github.com/sirupsen/logrus"
)

const (
	cMaxCacheRefreshAttempts      int           = 3
	cCacheRefreshIntervalInBlocks int64         = 20
	cDefaultBlockSpeed            time.Duration = time.Millisecond * 1620
)

type keepAliveCache struct {
	retryFalloff        time.Duration
	locker              sync.Locker
	estimatedBlockSpeed time.Duration
	lastBlockHeight     int64
	lastRefresh         time.Time
	lastAliveUntil      int64
	queryBTL            AliveUntilHeightQuery
	queryBH             CurrentHeightQuery
	invalidated         bool
}

func (c *keepAliveCache) get(ctx context.Context) (int64, error) {
	logger := liblog.WithContext(ctx).WithField("component", "cache")
	if c.isStale() {
		logger.WithFields(logrus.Fields{
			"estimatedBlockSpeed": c.estimatedBlockSpeed,
			"lastBlockHeight":     c.lastBlockHeight,
			"lastRefresh":         c.lastRefresh,
			"lastAliveUntil":      c.lastAliveUntil,
		}).Debug("cache is stale")
		err := linearFalloffRetry(ctx, c.locker, "cache refresh", cMaxCacheRefreshAttempts, c.retryFalloff, c.refresh)
		logger.WithFields(logrus.Fields{
			"estimatedBlockSpeed": c.estimatedBlockSpeed,
			"lastBlockHeight":     c.lastBlockHeight,
			"lastRefresh":         c.lastRefresh,
			"lastAliveUntil":      c.lastAliveUntil,
		}).WithError(err).Debug("cache refreshed")
		if err != nil {
			return 0, err
		}
	}

	return c.lastAliveUntil, nil
}

func (c *keepAliveCache) invalidate() {
	c.invalidated = true
}

func (c *keepAliveCache) refresh(ctx context.Context, _ sync.Locker) error {
	logger := liblog.WithContext(ctx).WithField("component", "cache")
	logger.Debug("refreshing cache")

	abh, err := c.queryBTL(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to query alive until height")
		return err
	}

	bh, err := c.queryBH(ctx)
	if err != nil {
		logger.WithError(err).Error("failed to query current height")
		return err
	}

	c.estimatedBlockSpeed = c.estimateBlockSpeed(bh, time.Now().UTC())
	c.lastAliveUntil = abh
	c.lastBlockHeight = bh
	c.lastRefresh = time.Now().UTC()
	c.invalidated = false

	logger.Debug("done refreshing cache")
	return nil
}

func (c *keepAliveCache) isStale() bool {
	if c.invalidated ||
		c.estimatedBlockSpeed == 0 ||
		c.lastBlockHeight == 0 ||
		c.lastRefresh.IsZero() {
		return true
	}

	elapsedMs := time.Now().UTC().Sub(c.lastRefresh).Milliseconds()
	estimatedElapsedBlocks := elapsedMs / c.estimatedBlockSpeed.Milliseconds()

	return estimatedElapsedBlocks >= cCacheRefreshIntervalInBlocks
}

func (c *keepAliveCache) estimateBlockSpeed(bh int64, t time.Time) time.Duration {
	if c.lastBlockHeight == 0 || bh == 0 || t.IsZero() {
		// During the first run, we have no historic data to
		// compare to, so we set a rough estimate.
		return cDefaultBlockSpeed
	}

	if t.Before(c.lastRefresh) {
		return cDefaultBlockSpeed
	}

	blockDiff := bh - c.lastBlockHeight
	timeDiff := t.Sub(c.lastRefresh)
	bpms := timeDiff.Milliseconds() / int64(blockDiff)
	return time.Duration(bpms) * time.Millisecond
}

func (c *keepAliveCache) estimateBlockHeight(t time.Time) int64 {
	if c.estimatedBlockSpeed == 0 || c.lastRefresh.IsZero() || t.IsZero() {
		return c.lastBlockHeight
	}

	if t.Before(c.lastRefresh) {
		return c.lastBlockHeight
	}

	timeDiff := t.Sub(c.lastRefresh)
	blockDiff := timeDiff.Milliseconds() / c.estimatedBlockSpeed.Milliseconds()
	return c.lastBlockHeight + blockDiff
}