// Package ratelimit implements a Redis-backed sliding-window rate
// limiter keyed by (tenant_id, subject_id). It is the backstop against
// bulk-extraction attacks that would otherwise rely solely on the
// ML-based risk scoring layer to catch abuse.
//
// Two independent windows are enforced per caller:
//
//	requests_per_minute  — short-burst protection
//	requests_per_hour    — slow-and-low extraction protection
//
// Each window lives in its own Redis sorted set. The critical section
// (check both windows, deny if either is full, otherwise ZADD both) runs
// inside a single Lua script so the check-and-add is atomic on the Redis
// side. Concurrent requests for the same caller therefore cannot all
// observe "below limit" simultaneously — exactly as many as `limit`
// are accepted per window.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Decision is the outcome of a single Allow call.
type Decision struct {
	// Allowed is true when neither window was exceeded.
	Allowed bool
	// RetryAfter is the duration the caller should wait before retrying.
	// Zero when Allowed is true.
	RetryAfter time.Duration
	// LimitMinute / LimitHour are the configured tier limits.
	LimitMinute int
	LimitHour   int
	// RemainingMinute / RemainingHour are how many more requests the
	// caller has inside the current window (never negative).
	RemainingMinute int64
	RemainingHour   int64
	// ResetMinute / ResetHour are unix epoch seconds at which the oldest
	// in-window entry will fall out.
	ResetMinute int64
	ResetHour   int64
	// Reason identifies which window tripped ("minute" or "hour"). Empty
	// when Allowed is true.
	Reason string
	// LastDay is the number of requests this (tenant, subject) pair has
	// made in the past 24 hours. Always populated — even on deny — so the
	// OPA Tier 1 policy can apply daily-volume thresholds without the
	// Redis layer needing to enforce them directly (dayLimit is always 0).
	LastDay int64
}

// Limiter is a Redis-backed sliding-window rate limiter.
type Limiter struct {
	redis  *redis.Client
	logger *zap.Logger
	// now is injectable for tests; production callers leave it nil.
	now func() time.Time
	// seq makes sorted-set members unique even when the injected
	// clock ticks coarsely (tests often freeze time).
	seq atomic.Uint64
}

// allowScript is the atomic check-and-add for minute, hour, and day
// windows. Arguments:
//
//	KEYS[1] = minute window key
//	KEYS[2] = hour window key
//	KEYS[3] = day window key
//	ARGV[1] = now (nanoseconds)
//	ARGV[2] = minute cutoff (nanoseconds)
//	ARGV[3] = hour cutoff (nanoseconds)
//	ARGV[4] = day cutoff (nanoseconds)
//	ARGV[5] = minute limit (0 disables enforcement)
//	ARGV[6] = hour limit (0 disables enforcement)
//	ARGV[7] = member (unique per call)
//	ARGV[8] = minute TTL seconds
//	ARGV[9] = hour TTL seconds
//	ARGV[10] = day TTL seconds
//
// The day window is always recorded but never enforced here (day limit is
// always passed as 0). OPA Tier 1 rules apply the daily threshold.
//
// Returns:
//
//	{ allowed, reason, min_count, hour_count, day_count, min_oldest, hour_oldest }
//
// where allowed ∈ {0,1}, reason ∈ {"", "minute", "hour"}, and
// *_oldest values are nanoseconds (0 when empty).
var allowScript = redis.NewScript(`
local min_key   = KEYS[1]
local hour_key  = KEYS[2]
local day_key   = KEYS[3]
local now       = tonumber(ARGV[1])
local min_cut   = tonumber(ARGV[2])
local hour_cut  = tonumber(ARGV[3])
local day_cut   = tonumber(ARGV[4])
local min_lim   = tonumber(ARGV[5])
local hour_lim  = tonumber(ARGV[6])
local member    = ARGV[7]
local min_ttl   = tonumber(ARGV[8])
local hour_ttl  = tonumber(ARGV[9])
local day_ttl   = tonumber(ARGV[10])

-- Evict expired entries from all three windows.
redis.call("ZREMRANGEBYSCORE", min_key,  "-inf", "(" .. min_cut)
redis.call("ZREMRANGEBYSCORE", hour_key, "-inf", "(" .. hour_cut)
redis.call("ZREMRANGEBYSCORE", day_key,  "-inf", "(" .. day_cut)

local min_count  = redis.call("ZCARD", min_key)
local hour_count = redis.call("ZCARD", hour_key)
local day_count  = redis.call("ZCARD", day_key)

local function oldest(key)
  local r = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
  if #r >= 2 then return tonumber(r[2]) else return 0 end
end

local min_oldest  = oldest(min_key)
local hour_oldest = oldest(hour_key)

if min_lim > 0 and min_count >= min_lim then
  return {0, "minute", min_count, hour_count, day_count, min_oldest, hour_oldest}
end
if hour_lim > 0 and hour_count >= hour_lim then
  return {0, "hour", min_count, hour_count, day_count, min_oldest, hour_oldest}
end

redis.call("ZADD", min_key,  now, member)
redis.call("ZADD", hour_key, now, member)
redis.call("ZADD", day_key,  now, member)
redis.call("EXPIRE", min_key,  min_ttl)
redis.call("EXPIRE", hour_key, hour_ttl)
redis.call("EXPIRE", day_key,  day_ttl)

-- Reflect the post-increment counts so the caller's headers are correct.
min_count  = min_count  + 1
hour_count = hour_count + 1
day_count  = day_count  + 1

return {1, "", min_count, hour_count, day_count, min_oldest, hour_oldest}
`)

// New constructs a Limiter talking to the Redis at addr. It does NOT
// contact Redis — call Ping for that.
func New(addr string, logger *zap.Logger) *Limiter {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: "",
		DB:       0,
	})
	return &Limiter{redis: rdb, logger: logger}
}

// NewWithClient wraps an existing Redis client. Used primarily by tests
// that inject a miniredis-backed client.
func NewWithClient(client *redis.Client, logger *zap.Logger) *Limiter {
	return &Limiter{redis: client, logger: logger}
}

// Ping verifies connectivity. Mirrors cache.RevocationCache.Ping so
// cmd/proxy/main.go can apply the same "conditional on REDIS_ADDR"
// wiring.
func (l *Limiter) Ping(ctx context.Context) error {
	return l.redis.Ping(ctx).Err()
}

// Close releases the Redis client.
func (l *Limiter) Close() error {
	if l.redis == nil {
		return nil
	}
	return l.redis.Close()
}

func (l *Limiter) timeNow() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// Allow checks whether the (tenantID, subjectID) caller may make one
// more request under the minute/hour limits. It returns a Decision with
// the headers the middleware needs to surface to the client.
//
// A limit of 0 or less on either tier disables that tier for this call.
func (l *Limiter) Allow(ctx context.Context, tenantID, subjectID string, minLimit, hourLimit int) (Decision, error) {
	if tenantID == "" || subjectID == "" {
		return Decision{}, errors.New("ratelimit: tenantID and subjectID required")
	}

	now := l.timeNow()
	nowNanos := now.UnixNano()
	minWindow := time.Minute
	hourWindow := time.Hour
	minCut := now.Add(-minWindow).UnixNano()
	hourCut := now.Add(-hourWindow).UnixNano()

	minKey := keyFor(tenantID, subjectID, "min")
	hourKey := keyFor(tenantID, subjectID, "hour")

	// Unique member so ZADD is never a no-op even when the clock is
	// frozen (tests) or coarse (Windows).
	member := fmt.Sprintf("%d-%d", nowNanos, l.seq.Add(1))

	dayWindow := 24 * time.Hour
	dayKey := keyFor(tenantID, subjectID, "day")
	dayCut := now.Add(-dayWindow).UnixNano()

	raw, err := allowScript.Run(ctx, l.redis,
		[]string{minKey, hourKey, dayKey},
		nowNanos,
		minCut,
		hourCut,
		dayCut,
		minLimit,
		hourLimit,
		member,
		int((minWindow + 5*time.Second).Seconds()),
		int((hourWindow + 5*time.Second).Seconds()),
		int((dayWindow + 5*time.Second).Seconds()),
	).Result()
	if err != nil {
		return Decision{}, fmt.Errorf("ratelimit: eval: %w", err)
	}

	result, err := parseScriptResult(raw)
	if err != nil {
		return Decision{}, err
	}

	d := Decision{
		Allowed:         result.allowed,
		LimitMinute:     minLimit,
		LimitHour:       hourLimit,
		RemainingMinute: remaining(minLimit, result.minCount),
		RemainingHour:   remaining(hourLimit, result.hourCount),
		ResetMinute:     resetAt(result.minOldest, minWindow, now),
		ResetHour:       resetAt(result.hourOldest, hourWindow, now),
		Reason:          result.reason,
		LastDay:         result.dayCount,
	}
	if !result.allowed {
		switch result.reason {
		case "minute":
			d.RetryAfter = retryAfter(result.minOldest, minWindow, now)
		case "hour":
			d.RetryAfter = retryAfter(result.hourOldest, hourWindow, now)
		default:
			d.RetryAfter = time.Second
		}
	}
	return d, nil
}

type scriptResult struct {
	allowed    bool
	reason     string
	minCount   int64
	hourCount  int64
	dayCount   int64
	minOldest  int64
	hourOldest int64
}

func parseScriptResult(raw any) (scriptResult, error) {
	arr, ok := raw.([]any)
	if !ok {
		return scriptResult{}, fmt.Errorf("ratelimit: script returned %T, want []any", raw)
	}
	if len(arr) != 7 {
		return scriptResult{}, fmt.Errorf("ratelimit: script returned %d elements, want 7", len(arr))
	}
	allowedI, _ := toInt64(arr[0])
	reason, _ := arr[1].(string)
	minCount, _ := toInt64(arr[2])
	hourCount, _ := toInt64(arr[3])
	dayCount, _ := toInt64(arr[4])
	minOldest, _ := toInt64(arr[5])
	hourOldest, _ := toInt64(arr[6])
	return scriptResult{
		allowed:    allowedI == 1,
		reason:     reason,
		minCount:   minCount,
		hourCount:  hourCount,
		dayCount:   dayCount,
		minOldest:  minOldest,
		hourOldest: hourOldest,
	}, nil
}

// toInt64 coerces the variety of Redis return shapes (int64, string,
// float64) into a single int64. Redis scripting returns integers as
// int64 via go-redis, but Lua's tonumber can produce strings in some
// edge cases so we accept both.
func toInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func keyFor(tenantID, subjectID, window string) string {
	return fmt.Sprintf("ratelimit:%s:%s:%s", tenantID, subjectID, window)
}

func remaining(limit int, count int64) int64 {
	if limit <= 0 {
		return 0
	}
	r := int64(limit) - count
	if r < 0 {
		return 0
	}
	return r
}

// resetAt returns the unix-seconds timestamp at which the oldest
// in-window entry will fall out. If the window is empty, reset is "now"
// (effectively: no wait required).
func resetAt(oldestNanos int64, window time.Duration, now time.Time) int64 {
	if oldestNanos == 0 {
		return now.Unix()
	}
	return time.Unix(0, oldestNanos).Add(window).Unix()
}

// retryAfter rounds up the time until the oldest in-window entry falls
// out, with a floor of 1 second so clients actually back off.
func retryAfter(oldestNanos int64, window time.Duration, now time.Time) time.Duration {
	if oldestNanos == 0 {
		return time.Second
	}
	wait := time.Unix(0, oldestNanos).Add(window).Sub(now)
	if wait < time.Second {
		return time.Second
	}
	return wait.Round(time.Second)
}
