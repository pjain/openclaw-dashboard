/*
 * Dashboard data loader
 * - Caching with per-source TTL
 * - Retry with exponential backoff
 * - Graceful degradation on partial failures
 */

class DashboardData {
  constructor(options = {}) {
    this.options = {
      tasksUrl: '/api/tasks',
      cronUrl: '/api/cron',
      healthUrl: '/api/health',
      costsUrl: '/api/costs',
      cacheTtlMs: {
        tasks: 30_000,
        cron: 30_000,
        health: 15_000,
        costs: 15 * 60_000,
      },
      retries: 3,
      initialBackoffMs: 350,
      backoffFactor: 2,
      maxBackoffMs: 4_000,
      requestTimeoutMs: 12_000,
      ...options,
    };

    this.cache = new Map();
    this.inFlight = new Map();
  }

  _now() {
    return Date.now();
  }

  _getCache(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (this._now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    return entry.value;
  }

  _setCache(key, value, ttlMs) {
    this.cache.set(key, {
      value,
      expiresAt: this._now() + ttlMs,
    });
  }

  async _sleep(ms) {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  async _withRetry(fn, label = 'request') {
    let attempt = 0;
    let backoff = this.options.initialBackoffMs;
    let lastError;

    while (attempt < this.options.retries) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        attempt += 1;
        if (attempt >= this.options.retries) break;

        const jitter = Math.floor(Math.random() * 120);
        await this._sleep(Math.min(backoff + jitter, this.options.maxBackoffMs));
        backoff = Math.min(backoff * this.options.backoffFactor, this.options.maxBackoffMs);
      }
    }

    const wrapped = new Error(`${label} failed after ${this.options.retries} attempts`);
    wrapped.cause = lastError;
    throw wrapped;
  }

  async _fetchJson(url, opts = {}, label = 'fetch') {
    return this._withRetry(async () => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.options.requestTimeoutMs);

      try {
        const res = await fetch(url, {
          headers: { 'Accept': 'application/json', ...(opts.headers || {}) },
          ...opts,
          signal: opts.signal || controller.signal,
        });
        if (!res.ok) {
          throw new Error(`${label}: HTTP ${res.status}`);
        }
        return res.json();
      } finally {
        clearTimeout(timeout);
      }
    }, label);
  }

  async _cached(key, ttlMs, loader, fallbackValue) {
    const cached = this._getCache(key);
    if (cached !== null) return cached;

    if (this.inFlight.has(key)) {
      return this.inFlight.get(key);
    }

    const pending = (async () => {
      try {
        const value = await loader();
        this._setCache(key, value, ttlMs);
        return value;
      } catch (error) {
        // Graceful degradation: return stale cache if available
        const stale = this.cache.get(key)?.value;
        if (stale !== undefined) return stale;
        if (fallbackValue !== undefined) return fallbackValue;
        throw error;
      } finally {
        this.inFlight.delete(key);
      }
    })();

    this.inFlight.set(key, pending);
    return pending;
  }

  async fetchTasks() {
    return this._cached(
      'tasks',
      this.options.cacheTtlMs.tasks,
      () => this._fetchJson(this.options.tasksUrl, {}, 'tasks'),
      { tasks: [], error: 'tasks unavailable' }
    );
  }

  async fetchCronJobs() {
    const payload = await this._cached(
      'cron',
      this.options.cacheTtlMs.cron,
      () => this._fetchJson(this.options.cronUrl, {}, 'cron jobs'),
      { jobs: [], error: 'cron unavailable' }
    );

    const now = this._now();
    const jobs = Array.isArray(payload.jobs) ? payload.jobs : [];
    return {
      ...payload,
      jobs: jobs.map((job) => ({
        ...job,
        temporalState: this.getCronTemporalState(job, now),
      })),
    };
  }

  async fetchHealthMetrics() {
    return this._cached(
      'health',
      this.options.cacheTtlMs.health,
      () => this._fetchJson(this.options.healthUrl, {}, 'health metrics'),
      { ok: false, error: 'health metrics unavailable' }
    );
  }

  async _fetchProviderCost(name, url) {
    try {
      const data = await this._fetchJson(url, {}, `${name} costs`);
      return {
        available: true,
        ok: true,
        provider: name,
        ...data,
      };
    } catch (error) {
      return {
        available: false,
        ok: false,
        provider: name,
        error: error?.message || `${name} unavailable`,
      };
    }
  }

  async fetchCosts() {
    return this._cached(
      'costs',
      this.options.cacheTtlMs.costs,
      async () => {
        // Preferred: aggregated endpoint
        try {
          return await this._fetchJson(this.options.costsUrl, {}, 'cost data');
        } catch (_ignored) {
          // Fallback: provider endpoints (OpenAI/Anthropic first)
          const [openai, anthropic, gemini, openrouter] = await Promise.all([
            this._fetchProviderCost('openai', `${this.options.costsUrl}/openai`),
            this._fetchProviderCost('anthropic', `${this.options.costsUrl}/anthropic`),
            this._fetchProviderCost('gemini', `${this.options.costsUrl}/gemini`),
            this._fetchProviderCost('openrouter', `${this.options.costsUrl}/openrouter`),
          ]);

          return {
            ok: openai.ok || anthropic.ok || gemini.ok || openrouter.ok,
            providers: { openai, anthropic, gemini, openrouter },
            generatedAt: new Date().toISOString(),
          };
        }
      },
      {
        ok: false,
        providers: {
          openai: { available: false },
          anthropic: { available: false },
          gemini: { available: false },
          openrouter: { available: false },
        },
        error: 'cost data unavailable',
      }
    );
  }

  // Temporal model from architecture doc
  getCronTemporalState(job, now = Date.now()) {
    const state = job?.state || {};
    const enabled = job?.enabled !== false;
    const nextRun = Number(state.nextRunAtMs || 0);
    const lastRun = Number(state.lastRunAtMs || 0);
    const lastStatus = state.lastStatus || state.lastRunStatus || 'unknown';
    const consecutiveErrors = Number(state.consecutiveErrors || 0);

    if (!enabled) {
      return { phase: 'disabled', displayStatus: 'disabled' };
    }

    if (state.runningAtMs) {
      return {
        phase: 'running',
        displayStatus: 'running',
        runningForMs: Math.max(now - Number(state.runningAtMs), 0),
      };
    }

    if (!nextRun && !lastRun) {
      return { phase: 'unknown', displayStatus: 'unknown' };
    }

    if (consecutiveErrors > 0 || lastStatus === 'error') {
      return {
        phase: 'degraded',
        displayStatus: 'needs-attention',
        consecutiveErrors,
        lastRunAgoMs: lastRun ? Math.max(now - lastRun, 0) : null,
      };
    }

    if (nextRun && now < nextRun && lastRun && lastRun < now) {
      return {
        phase: 'between-runs',
        displayStatus: 'healthy',
        nextRunInMs: Math.max(nextRun - now, 0),
        lastRunAgoMs: Math.max(now - lastRun, 0),
      };
    }

    if (nextRun && Math.abs(now - nextRun) < 60_000) {
      return { phase: 'imminent', displayStatus: 'running-soon' };
    }

    if (nextRun && now > nextRun && lastRun < nextRun) {
      return {
        phase: 'overdue',
        displayStatus: 'overdue',
        overdueByMs: now - nextRun,
      };
    }

    return { phase: 'scheduled', displayStatus: 'healthy' };
  }

  async fetchAll() {
    const [tasks, cron, health, costs] = await Promise.allSettled([
      this.fetchTasks(),
      this.fetchCronJobs(),
      this.fetchHealthMetrics(),
      this.fetchCosts(),
    ]);

    const unwrap = (r, fallback) => (r.status === 'fulfilled' ? r.value : fallback);

    return {
      tasks: unwrap(tasks, { tasks: [], error: 'tasks unavailable' }),
      cron: unwrap(cron, { jobs: [], error: 'cron unavailable' }),
      health: unwrap(health, { ok: false, error: 'health unavailable' }),
      costs: unwrap(costs, { ok: false, error: 'costs unavailable' }),
      generatedAt: new Date().toISOString(),
    };
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { DashboardData };
}
if (typeof window !== 'undefined') {
  window.DashboardData = DashboardData;
}
