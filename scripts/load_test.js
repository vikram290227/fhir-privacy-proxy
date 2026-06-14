/**
 * load_test.js — k6 load test for the FHIR privacy proxy redaction pipeline.
 *
 * Measures p50/p95/p99 end-to-end latency for Patient/$everything requests
 * with redaction active vs. disabled, so the delta attributable to the
 * redaction engine is isolated and visible.
 *
 * Prerequisites:
 *   - k6 installed: brew install k6  (or https://k6.io/docs/get-started/installation)
 *   - Proxy running with HAPI upstream: make up
 *   - Valid bearer token: export BENCH_TOKEN=$(./scripts/get_token.sh)
 *   - A test patient ID: export BENCH_PATIENT_ID=patient-123
 *
 * Usage:
 *   # Redaction ENABLED (default)
 *   k6 run scripts/load_test.js
 *
 *   # Redaction DISABLED (baseline for delta measurement)
 *   REDACTION_ENABLED=false k6 run scripts/load_test.js
 *
 * Output: k6 summary with http_req_duration percentiles (p50/p95/p99).
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

const PROXY_BASE        = __ENV.PROXY_BASE        || 'http://localhost:8080';
const BENCH_TOKEN       = __ENV.BENCH_TOKEN       || '';
const PATIENT_ID        = __ENV.BENCH_PATIENT_ID  || 'patient-123';
const REDACTION_ENABLED = (__ENV.REDACTION_ENABLED || 'true') !== 'false';

export const options = {
  scenarios: {
    steady_load: {
      executor: 'constant-vus',
      vus: 10,
      duration: '60s',
      gracefulStop: '5s',
    },
    ramp_stress: {
      executor: 'ramping-vus',
      startVUs: 1,
      stages: [
        { duration: '20s', target: 25 },
        { duration: '40s', target: 25 },
        { duration: '20s', target: 50 },
        { duration: '30s', target: 50 },
        { duration: '10s', target: 0  },
      ],
      gracefulRampDown: '5s',
      startTime: '65s',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<3000'],
    http_req_failed:   ['rate<0.01'],
  },
  summaryTrendStats: ['min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max', 'count'],
};

const proxyDuration = new Trend('proxy_duration_ms', true);
const requestErrors = new Rate('request_errors');
const totalRequests = new Counter('total_requests');

export default function () {
  if (!BENCH_TOKEN) {
    console.error('BENCH_TOKEN not set. Export: BENCH_TOKEN=$(./scripts/get_token.sh)');
    return;
  }

  const url = `${PROXY_BASE}/fhir/r4/Patient/${PATIENT_ID}/$everything`;
  const headers = {
    'Authorization': `Bearer ${BENCH_TOKEN}`,
    'Accept':        'application/fhir+json',
  };

  // Pass X-Skip-Redaction when measuring the no-redaction baseline.
  // Proxy honours this only when ALLOW_SKIP_REDACTION=true (test-only flag).
  if (!REDACTION_ENABLED) {
    headers['X-Skip-Redaction'] = 'true';
  }

  const start = Date.now();
  const res   = http.get(url, { headers, tags: { redaction: REDACTION_ENABLED ? 'on' : 'off' } });
  proxyDuration.add(Date.now() - start);

  totalRequests.add(1);

  const ok = check(res, {
    'status 200':            (r) => r.status === 200,
    'fhir+json content':     (r) => (r.headers['Content-Type'] || '').includes('fhir+json'),
    'non-empty body':        (r) => (r.body || '').length > 0,
    'valid JSON':            (r) => { try { JSON.parse(r.body); return true; } catch { return false; } },
    'resourceType Bundle':   (r) => { try { return JSON.parse(r.body).resourceType === 'Bundle'; } catch { return false; } },
  });

  if (!ok || res.status !== 200) {
    requestErrors.add(1);
    console.warn(`Failed: status=${res.status} body=${(res.body || '').slice(0, 200)}`);
  }

  sleep(0.1);
}

export function handleSummary(data) {
  const p50  = data.metrics.http_req_duration?.values?.['p(50)']  ?? 'n/a';
  const p95  = data.metrics.http_req_duration?.values?.['p(95)']  ?? 'n/a';
  const p99  = data.metrics.http_req_duration?.values?.['p(99)']  ?? 'n/a';
  const errs = data.metrics.request_errors?.values?.rate          ?? 0;

  console.log('\n=== Load test summary ===');
  console.log(`Redaction : ${REDACTION_ENABLED ? 'ENABLED' : 'DISABLED'}`);
  console.log(`p50       : ${typeof p50 === 'number' ? p50.toFixed(1) : p50} ms`);
  console.log(`p95       : ${typeof p95 === 'number' ? p95.toFixed(1) : p95} ms`);
  console.log(`p99       : ${typeof p99 === 'number' ? p99.toFixed(1) : p99} ms`);
  console.log(`Error rate: ${(errs * 100).toFixed(2)}%`);
  console.log('\nRe-run with REDACTION_ENABLED=false for the baseline delta.');

  return {
    stdout: '',
    'load_test_summary.json': JSON.stringify(data, null, 2),
  };
}
