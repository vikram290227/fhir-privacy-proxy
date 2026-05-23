package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// newTestLimiter boots an in-memory miniredis server and returns a
// Limiter configured against it, plus a pointer to a mutable "now" the
// test can advance to drive window expiration deterministically.
func newTestLimiter(t *testing.T) (*Limiter, *miniredis.Miniredis, *atomic.Int64, func()) {
	t.Helper()
	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	limiter := NewWithClient(client, zap.NewNop())

	var nowNanos atomic.Int64
	nowNanos.Store(time.Now().UnixNano())
	limiter.now = func() time.Time {
		return time.Unix(0, nowNanos.Load())
	}

	cleanup := func() {
		_ = client.Close()
	}
	return limiter, mr, &nowNanos, cleanup
}

// -----------------------------------------------------------------------
// Window behaviour
// -----------------------------------------------------------------------

// TestMinuteWindowBlocksAfterLimit drives the limiter up to the
// per-minute limit, then confirms the next call trips with reason
// "minute" and a RetryAfter >= 1s.
func TestMinuteWindowBlocksAfterLimit(t *testing.T) {
	limiter, _, _, cleanup := newTestLimiter(t)
	defer cleanup()

	ctx := context.Background()
	const minLimit = 5
	const hourLimit = 1000

	for i := 0; i < minLimit; i++ {
		d, err := limiter.Allow(ctx, "hospital-a", "nurse1", minLimit, hourLimit)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
		if !d.Allowed {
			t.Fatalf("call %d: expected allowed, got denied (%s)", i+1, d.Reason)
		}
		wantRemaining := int64(minLimit - (i + 1))
		if d.RemainingMinute != wantRemaining {
			t.Fatalf("call %d: remaining=%d want=%d", i+1, d.RemainingMinute, wantRemaining)
		}
	}

	d, err := limiter.Allow(ctx, "hospital-a", "nurse1", minLimit, hourLimit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Fatalf("expected deny after %d requests, got allowed", minLimit)
	}
	if d.Reason != "minute" {
		t.Fatalf("wrong reason: got %q want %q", d.Reason, "minute")
	}
	if d.RetryAfter < time.Second {
		t.Fatalf("RetryAfter floor violated: %v", d.RetryAfter)
	}
	if d.RemainingMinute != 0 {
		t.Fatalf("remaining_minute on deny: got %d want 0", d.RemainingMinute)
	}
}

// TestHourWindowCatchesSlowLow confirms that a caller whose per-minute
// rate is below the minute cap but whose cumulative hour rate is above
// the hour cap is still rejected — this is the slow-and-low extraction
// scenario the backstop is meant to catch.
func TestHourWindowCatchesSlowLow(t *testing.T) {
	limiter, _, now, cleanup := newTestLimiter(t)
	defer cleanup()

	ctx := context.Background()
	// Minute limit is deliberately high so the slow pacing never
	// trips it — the only legitimate reason to deny in this test is
	// the hour cap.
	const minLimit = 1000
	const hourLimit = 20

	// Space each call 65s apart: every minute window has at most 1
	// entry so the minute tier never trips, but after `hourLimit`
	// calls all of them are still inside the 1h window.
	const step = 65 * time.Second
	for i := 0; i < hourLimit; i++ {
		d, err := limiter.Allow(ctx, "hospital-b", "attacker", minLimit, hourLimit)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
		if !d.Allowed {
			t.Fatalf("call %d: expected allow (slow pace), got deny (%s)", i+1, d.Reason)
		}
		now.Store(now.Load() + int64(step))
	}

	d, err := limiter.Allow(ctx, "hospital-b", "attacker", minLimit, hourLimit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Fatalf("expected hour-window deny after %d calls, got allowed", hourLimit)
	}
	if d.Reason != "hour" {
		t.Fatalf("wrong reason: got %q want %q", d.Reason, "hour")
	}
}

// TestLimitRecoversAfterWindow verifies that after exceeding the minute
// limit, advancing the clock past the window frees the caller up.
func TestLimitRecoversAfterWindow(t *testing.T) {
	limiter, _, now, cleanup := newTestLimiter(t)
	defer cleanup()

	ctx := context.Background()
	const minLimit = 3
	const hourLimit = 100

	for i := 0; i < minLimit; i++ {
		if _, err := limiter.Allow(ctx, "hospital-a", "doctor1", minLimit, hourLimit); err != nil {
			t.Fatalf("warmup call %d: %v", i+1, err)
		}
	}
	// Next call should deny.
	d, _ := limiter.Allow(ctx, "hospital-a", "doctor1", minLimit, hourLimit)
	if d.Allowed {
		t.Fatalf("expected deny at warmup+1, got allowed")
	}

	// Advance past the minute window. The sorted set will also
	// expire by TTL on the server side, but our snapshot uses the
	// injected clock to compute the cutoff, so this is enough.
	now.Store(now.Load() + int64(65*time.Second))

	d, err := limiter.Allow(ctx, "hospital-a", "doctor1", minLimit, hourLimit)
	if err != nil {
		t.Fatalf("after-window call: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("expected recovery after window, got deny (%s)", d.Reason)
	}
}

// TestTenantIsolation asserts the limiter keys include tenant + subject
// so hospital-a's budget cannot be exhausted by hospital-b traffic and
// vice versa.
func TestTenantIsolation(t *testing.T) {
	limiter, _, _, cleanup := newTestLimiter(t)
	defer cleanup()

	ctx := context.Background()
	const minLimit = 2
	const hourLimit = 100

	for i := 0; i < minLimit; i++ {
		if _, err := limiter.Allow(ctx, "hospital-a", "nurse1", minLimit, hourLimit); err != nil {
			t.Fatalf("hospital-a call %d: %v", i+1, err)
		}
	}
	// hospital-a should now be at limit...
	da, _ := limiter.Allow(ctx, "hospital-a", "nurse1", minLimit, hourLimit)
	if da.Allowed {
		t.Fatalf("hospital-a should be rate-limited")
	}

	// ...but hospital-b with same subject name has its own bucket.
	db, err := limiter.Allow(ctx, "hospital-b", "nurse1", minLimit, hourLimit)
	if err != nil {
		t.Fatalf("hospital-b call: %v", err)
	}
	if !db.Allowed {
		t.Fatalf("hospital-b must not inherit hospital-a's counter")
	}
}

// TestSubjectIsolation is the intra-tenant equivalent: two distinct
// subjects in the same tenant must have independent budgets.
func TestSubjectIsolation(t *testing.T) {
	limiter, _, _, cleanup := newTestLimiter(t)
	defer cleanup()

	ctx := context.Background()
	const minLimit = 2
	const hourLimit = 100

	for i := 0; i < minLimit; i++ {
		if _, err := limiter.Allow(ctx, "hospital-a", "nurse1", minLimit, hourLimit); err != nil {
			t.Fatalf("nurse1 call %d: %v", i+1, err)
		}
	}
	d, _ := limiter.Allow(ctx, "hospital-a", "nurse1", minLimit, hourLimit)
	if d.Allowed {
		t.Fatalf("nurse1 should be rate-limited")
	}

	// nurse2 starts fresh.
	d, err := limiter.Allow(ctx, "hospital-a", "nurse2", minLimit, hourLimit)
	if err != nil {
		t.Fatalf("nurse2 call: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("nurse2 must not be blocked by nurse1's counter")
	}
}

// TestConcurrentRequestsRespectLimit hammers the limiter with more
// goroutines than the limit and checks that at most `minLimit` of them
// are accepted. Because go-redis auto-pools connections and miniredis
// serializes commands, this is a good proxy for the real race.
func TestConcurrentRequestsRespectLimit(t *testing.T) {
	limiter, _, _, cleanup := newTestLimiter(t)
	defer cleanup()

	ctx := context.Background()
	const minLimit = 20
	const hourLimit = 1000
	const workers = 50

	var allowed atomic.Int32
	var denied atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := limiter.Allow(ctx, "hospital-a", "burst", minLimit, hourLimit)
			if err != nil {
				t.Errorf("concurrent Allow: %v", err)
				return
			}
			if d.Allowed {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()

	total := allowed.Load() + denied.Load()
	if total != workers {
		t.Fatalf("accounting mismatch: allowed=%d denied=%d want sum=%d", allowed.Load(), denied.Load(), workers)
	}
	// Between a strict sliding window and concurrent request
	// serialization, the guaranteed invariant is: at most minLimit
	// within the window. Going under the limit is fine — what we
	// must never do is allow MORE than the limit.
	if allowed.Load() > int32(minLimit) {
		t.Fatalf("allowed=%d exceeds limit=%d under concurrency", allowed.Load(), minLimit)
	}
	if denied.Load() == 0 {
		t.Fatalf("expected at least some deny with %d workers vs limit=%d", workers, minLimit)
	}
}

// TestZeroLimitMeansDisabled confirms the escape hatch: a limit of 0
// on a tier disables that tier, so operators can e.g. disable the hour
// budget while keeping the minute budget.
func TestZeroLimitMeansDisabled(t *testing.T) {
	limiter, _, _, cleanup := newTestLimiter(t)
	defer cleanup()

	ctx := context.Background()
	// Zero minute limit, positive hour limit — 100 rapid-fire calls
	// must all be allowed (none deny on minute) but the hour budget
	// still tracks.
	for i := 0; i < 100; i++ {
		d, err := limiter.Allow(ctx, "hospital-a", "svc", 0, 200)
		if err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
		if !d.Allowed {
			t.Fatalf("call %d: unexpected deny (%s) with disabled minute tier", i+1, d.Reason)
		}
	}
}

// TestHeadersContainLimits spot-checks the response metadata that the
// middleware relies on to set X-RateLimit-* headers.
func TestHeadersContainLimits(t *testing.T) {
	limiter, _, _, cleanup := newTestLimiter(t)
	defer cleanup()

	ctx := context.Background()
	d, err := limiter.Allow(ctx, "hospital-a", "nurse1", 60, 1000)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if d.LimitMinute != 60 || d.LimitHour != 1000 {
		t.Fatalf("limits not echoed: %+v", d)
	}
	if d.RemainingMinute != 59 {
		t.Fatalf("remaining minute: got %d want 59", d.RemainingMinute)
	}
	if d.RemainingHour != 999 {
		t.Fatalf("remaining hour: got %d want 999", d.RemainingHour)
	}
	if d.ResetMinute == 0 || d.ResetHour == 0 {
		t.Fatalf("reset timestamps not populated: %+v", d)
	}
}

func TestNew_And_Ping_And_Close(t *testing.T) {
	mr := miniredis.RunT(t)

	l := New(mr.Addr(), zap.NewNop())
	if l == nil {
		t.Fatal("expected non-nil Limiter from New")
	}
	if err := l.Ping(context.Background()); err != nil {
		t.Errorf("Ping to miniredis: %v", err)
	}
	// Call Allow to exercise the default timeNow() → time.Now() branch
	d, err := l.Allow(context.Background(), "tenant", "subject", 100, 1000)
	if err != nil {
		t.Errorf("Allow: %v", err)
	}
	if !d.Allowed {
		t.Error("expected allowed for first request")
	}
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestClose_NilRedis(t *testing.T) {
	l := &Limiter{}
	if err := l.Close(); err != nil {
		t.Errorf("Close nil redis: %v", err)
	}
}

func TestToInt64(t *testing.T) {
	cases := []struct {
		in   any
		want int64
		ok   bool
	}{
		{int64(42), 42, true},
		{int(7), 7, true},
		{float64(3.0), 3, true},
		{"99", 99, true},
		{"bad", 0, false},
		{nil, 0, false},
	}
	for _, c := range cases {
		got, ok := toInt64(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("toInt64(%v) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Unix(1000, 0)
	// zero oldest → floor of 1s
	if d := retryAfter(0, time.Minute, now); d != time.Second {
		t.Errorf("zero oldest: got %v want 1s", d)
	}
	// oldest so recent that remaining < 1s → floor
	nearPast := now.Add(-59 * time.Second).UnixNano()
	if d := retryAfter(nearPast, time.Minute, now); d < time.Second {
		t.Errorf("near-floor: got %v, want >= 1s", d)
	}
	// oldest far enough that wait > 1s
	oldPast := now.Add(-30 * time.Second).UnixNano()
	if d := retryAfter(oldPast, time.Minute, now); d <= time.Second {
		t.Errorf("normal case: got %v, want > 1s", d)
	}
}

// TestMissingTenantOrSubject validates the input guard.
func TestMissingTenantOrSubject(t *testing.T) {
	limiter, _, _, cleanup := newTestLimiter(t)
	defer cleanup()

	ctx := context.Background()
	if _, err := limiter.Allow(ctx, "", "nurse1", 60, 1000); err == nil {
		t.Fatalf("expected error with empty tenantID")
	}
	if _, err := limiter.Allow(ctx, "hospital-a", "", 60, 1000); err == nil {
		t.Fatalf("expected error with empty subjectID")
	}
}
