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
      tasksFallbackUrls: ['/tasks/data.json'],
      cronUrl: '/api/crons',
      cronFallbackUrls: ['/api/cron'],
      healthUrl: '/api/health-history',
      healthFallbackUrls: ['/api/health'],
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

  async _fetchJsonAny(urls = [], opts = {}, label = 'fetch') {
    const tried = [];
    for (const url of urls) {
      if (!url) continue;
      try {
        return await this._fetchJson(url, opts, `${label} (${url})`);
      } catch (error) {
        tried.push(`${url}: ${error?.message || 'failed'}`);
      }
    }

    throw new Error(`${label} failed on all endpoints: ${tried.join('; ')}`);
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
      async () => {
        const payload = await this._fetchJsonAny(
          [this.options.tasksUrl, ...(this.options.tasksFallbackUrls || [])],
          {},
          'tasks'
        );

        if (Array.isArray(payload?.tasks)) return payload;
        if (Array.isArray(payload)) return { tasks: payload };
        return { tasks: [], ...payload };
      },
      { tasks: [], error: 'tasks unavailable' }
    );
  }

  async fetchCronJobs() {
    const payload = await this._cached(
      'cron',
      this.options.cacheTtlMs.cron,
      () => this._fetchJsonAny([this.options.cronUrl, ...(this.options.cronFallbackUrls || [])], {}, 'cron jobs'),
      { jobs: [], error: 'cron unavailable' }
    );

    const now = this._now();
    const jobs = Array.isArray(payload?.jobs) ? payload.jobs : (Array.isArray(payload) ? payload : []);
    return {
      ...(Array.isArray(payload) ? {} : payload),
      jobs: jobs.map((job) => ({
        ...job,
        temporalState: this.getCronTemporalState(job, now),
      })),
    };
  }

  _parsePercent(str) {
    const m = String(str || '').match(/(\d+(?:\.\d+)?)%/);
    return m ? Number(m[1]) : null;
  }

  _safeRequire(name) {
    try {
      // eslint-disable-next-line global-require, import/no-dynamic-require
      return require(name);
    } catch (_error) {
      return null;
    }
  }

  _safeExec(command) {
    try {
      const cp = this._safeRequire('child_process');
      if (!cp?.execSync) return '';
      return String(cp.execSync(command, { stdio: ['ignore', 'pipe', 'ignore'] }) || '').trim();
    } catch (_error) {
      return '';
    }
  }

  _parseVmStatMemory(vmStatRaw) {
    const text = String(vmStatRaw || '');
    if (!text) return null;

    const pageSizeMatch = text.match(/page size of\s+(\d+)\s+bytes/i);
    const pageSize = Number(pageSizeMatch?.[1] || 4096);

    const readPages = (labelRegex) => {
      const m = text.match(labelRegex);
      if (!m) return 0;
      return Number(String(m[1]).replace(/\./g, '').trim()) || 0;
    };

    const freePages = readPages(/Pages free:\s*([\d.]+)/i);
    const speculativePages = readPages(/Pages speculative:\s*([\d.]+)/i);
    const activePages = readPages(/Pages active:\s*([\d.]+)/i);
    const inactivePages = readPages(/Pages inactive:\s*([\d.]+)/i);
    const wiredPages = readPages(/Pages wired down:\s*([\d.]+)/i);
    const compressedPages = readPages(/Pages occupied by compressor:\s*([\d.]+)/i);

    const totalPages = freePages + speculativePages + activePages + inactivePages + wiredPages + compressedPages;
    if (!totalPages) return null;

    const freeBytes = (freePages + speculativePages) * pageSize;
    const usedBytes = totalPages * pageSize - freeBytes;

    return {
      pageSize,
      raw: vmStatRaw,
      totalBytes: totalPages * pageSize,
      freeBytes,
      usedBytes,
    };
  }

  _localHealthSnapshot() {
    // Node/macOS fallback when health API is unavailable.
    const os = this._safeRequire('os');
    if (!os) return null;

    const diskRaw = this._safeExec("df -h / | tail -1");
    const cpuRaw = this._safeExec("top -l 1 | head -n 10");
    const uptimeRaw = this._safeExec('uptime');
    const vmStatRaw = this._safeExec('vm_stat');

    const diskUse = this._parsePercent(diskRaw);
    const cpuLine = cpuRaw.split('\n').find((line) => /CPU usage/i.test(line)) || '';
    const idle = this._parsePercent(cpuLine.match(/(\d+(?:\.\d+)?)%\s*idle/i)?.[0]);
    const vmMemory = this._parseVmStatMemory(vmStatRaw);

    return {
      ok: true,
      source: 'local-shell-fallback',
      disk: {
        raw: diskRaw,
        usedPercent: diskUse,
      },
      cpu: {
        raw: cpuLine,
        idlePercent: idle,
        activePercent: idle === null ? null : Math.max(0, 100 - idle),
      },
      load: {
        raw: uptimeRaw,
      },
      memory: vmMemory || {
        totalBytes: os.totalmem(),
        freeBytes: os.freemem(),
        usedBytes: os.totalmem() - os.freemem(),
      },
      collectedAt: new Date().toISOString(),
    };
  }

  async fetchHealthMetrics() {
    return this._cached(
      'health',
      this.options.cacheTtlMs.health,
      async () => {
        try {
          return await this._fetchJsonAny([this.options.healthUrl, ...(this.options.healthFallbackUrls || [])], {}, 'health metrics');
        } catch (_error) {
          const local = this._localHealthSnapshot();
          if (local) return local;
          throw _error;
        }
      },
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

  _withTemporalAliases(payload) {
    const phase = payload?.phase || 'unknown';
    return {
      ...payload,
      // Backward compatibility for older UI/tests that read `state`.
      state: phase,
      overdue: phase === 'overdue',
      imminent: phase === 'imminent',
      degraded: phase === 'degraded',
      running: phase === 'running',
    };
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
      return this._withTemporalAliases({ phase: 'disabled', displayStatus: 'disabled' });
    }

    if (state.runningAtMs) {
      return this._withTemporalAliases({
        phase: 'running',
        displayStatus: 'running',
        runningForMs: Math.max(now - Number(state.runningAtMs), 0),
      });
    }

    if (!nextRun && !lastRun) {
      return this._withTemporalAliases({ phase: 'unknown', displayStatus: 'unknown' });
    }

    if (consecutiveErrors > 0 || lastStatus === 'error') {
      return this._withTemporalAliases({
        phase: 'degraded',
        displayStatus: 'needs-attention',
        consecutiveErrors,
        lastRunAgoMs: lastRun ? Math.max(now - lastRun, 0) : null,
      });
    }

    if (nextRun && now > nextRun && lastRun < nextRun) {
      return this._withTemporalAliases({
        phase: 'overdue',
        displayStatus: 'overdue',
        overdueByMs: now - nextRun,
      });
    }

    if (nextRun && now <= nextRun && (nextRun - now) < 60_000) {
      return this._withTemporalAliases({ phase: 'imminent', displayStatus: 'running-soon' });
    }

    if (nextRun && now < nextRun && lastRun && lastRun < now) {
      return this._withTemporalAliases({
        phase: 'between-runs',
        displayStatus: 'healthy',
        nextRunInMs: Math.max(nextRun - now, 0),
        lastRunAgoMs: Math.max(now - lastRun, 0),
      });
    }

    return this._withTemporalAliases({ phase: 'scheduled', displayStatus: 'healthy' });
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
  // Support both import styles:
  //   const { DashboardData } = require('...')
  //   const DashboardData = require('...')
  module.exports = DashboardData;
  module.exports.DashboardData = DashboardData;
}
if (typeof window !== 'undefined') {
  window.DashboardData = DashboardData;
}
