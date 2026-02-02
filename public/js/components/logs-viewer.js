/**
 * Logs Viewer Component
 * Registers itself to window.Components for Alpine.js to consume
 */
window.Components = window.Components || {};

window.Components.logsViewer = () => ({
    logs: [],
    // Virtual Scrolling State
    itemHeight: 24, // Approximation (11px font * 1.625 line-height + 4px padding)
    containerHeight: 0,
    scrollTop: 0,
    buffer: 10, // Extra items to render above/below

    isAutoScroll: true,
    eventSource: null,
    searchQuery: '',
    filters: {
        INFO: true,
        WARN: true,
        ERROR: true,
        SUCCESS: true,
        DEBUG: false
    },

    // Cache filtered logs to avoid re-filtering on every scroll event
    _filteredLogsCache: null,
    _lastFilterState: null,

    get allFilteredLogs() {
        // Simple dirty check for filters/search change
        const currentFilterState = JSON.stringify({
            q: this.searchQuery,
            f: this.filters,
            len: this.logs.length // invalidate on new logs
        });

        if (this._lastFilterState === currentFilterState && this._filteredLogsCache) {
            return this._filteredLogsCache;
        }

        const query = this.searchQuery.trim();
        let result = this.logs;

        // Apply Level Filters first (faster)
        const activeLevels = Object.entries(this.filters)
            .filter(([_, active]) => active)
            .map(([level]) => level);

        // Optimization: checking Set is faster than object property access for large loops
        const activeLevelSet = new Set(activeLevels);
        result = result.filter(log => activeLevelSet.has(log.level));

        // Apply Search
        if (query) {
            let matcher;
            try {
                const regex = new RegExp(query, 'i');
                matcher = (msg) => regex.test(msg);
            } catch (e) {
                const lowerQuery = query.toLowerCase();
                matcher = (msg) => msg.toLowerCase().includes(lowerQuery);
            }
            result = result.filter(log => matcher(log.message));
        }

        this._filteredLogsCache = result;
        this._lastFilterState = currentFilterState;
        return result;
    },

    get visibleLogs() {
        if (this.containerHeight === 0) return []; // Not initialized

        const totalLogs = this.allFilteredLogs;
        const totalCount = totalLogs.length;

        // Calculate start/end indices
        const startIndex = Math.max(0, Math.floor(this.scrollTop / this.itemHeight) - this.buffer);
        const visibleCount = Math.ceil(this.containerHeight / this.itemHeight);
        const endIndex = Math.min(totalCount, startIndex + visibleCount + (this.buffer * 2));

        return totalLogs.slice(startIndex, endIndex).map((log, idx) => ({
            ...log,
            // Add absolute index for debugging or keys if needed
            index: startIndex + idx
        }));
    },

    get spacerTop() {
        const startIndex = Math.max(0, Math.floor(this.scrollTop / this.itemHeight) - this.buffer);
        return startIndex * this.itemHeight;
    },

    get spacerBottom() {
        const totalLogs = this.allFilteredLogs;
        const totalCount = totalLogs.length;
        const startIndex = Math.max(0, Math.floor(this.scrollTop / this.itemHeight) - this.buffer);
        const visibleCount = Math.ceil(this.containerHeight / this.itemHeight);
        const endIndex = Math.min(totalCount, startIndex + visibleCount + (this.buffer * 2));

        return Math.max(0, (totalCount - endIndex) * this.itemHeight);
    },

    init() {
        this.startLogStream();

        // Initialize scroll container measurements
        this.$nextTick(() => {
            const container = document.getElementById('logs-container');
            if (container) {
                // Initial check
                this.updateDimensions(container);

                // Resize observer for responsive height changes
                const ro = new ResizeObserver(() => this.updateDimensions(container));
                ro.observe(container);
            }
        });

        this.$watch('isAutoScroll', (val) => {
            if (val) this.scrollToBottom();
        });

        // When filters change, scroll to bottom if auto-scroll is on, 
        // AND ensure we reset cache
        this.$watch('searchQuery', () => {
            if (this.isAutoScroll) this.$nextTick(() => this.scrollToBottom());
        });

        // Use a debounced watcher for resizing logs if needed? 
        // For now, fixed height.
    },

    updateDimensions(container) {
        this.containerHeight = container.clientHeight;
        // If we want dynamic item height measuring, we'd do it here or in a loop

        // Auto-scroll on resize if enabled
        if (this.isAutoScroll) this.scrollToBottom();
    },

    handleScroll(e) {
        const container = e.target;
        this.scrollTop = container.scrollTop;

        // Detect user scrolling up to disable auto-scroll
        const isAtBottom = Math.abs((container.scrollHeight - container.clientHeight) - container.scrollTop) < 20;

        if (!isAtBottom && this.isAutoScroll) {
            this.isAutoScroll = false;
        } else if (isAtBottom && !this.isAutoScroll) {
            this.isAutoScroll = true;
        }
    },

    startLogStream() {
        if (this.eventSource) this.eventSource.close();

        const password = Alpine.store('global').webuiPassword;
        const url = password
            ? `/api/logs/stream?history=true&password=${encodeURIComponent(password)}`
            : '/api/logs/stream?history=true';

        this.eventSource = new EventSource(url);
        this.eventSource.onmessage = (event) => {
            try {
                const log = JSON.parse(event.data);
                this.logs.push(log);

                // Limit log buffer
                const limit = Alpine.store('settings')?.logLimit || window.AppConstants.LIMITS.DEFAULT_LOG_LIMIT;
                if (this.logs.length > limit) {
                    this.logs = this.logs.slice(-limit);
                }

                if (this.isAutoScroll) {
                    // Use requestAnimationFrame for smoother scrolling
                    requestAnimationFrame(() => this.scrollToBottom());
                }
            } catch (e) {
                if (window.UILogger) window.UILogger.debug('Log parse error:', e.message);
            }
        };

        this.eventSource.onerror = () => {
            if (window.UILogger) window.UILogger.debug('Log stream disconnected, reconnecting...');
            setTimeout(() => this.startLogStream(), 3000);
        };
    },

    scrollToBottom() {
        const container = document.getElementById('logs-container');
        if (container) {
            // Set scrollTop to a large value to force bottom
            // We use spacerBottom calculation, so scrollHeight should be accurate-ish
            // But with virtual scrolling, sometimes scrollHeight is estimated.
            // Since we use strict math for spacers, scrollHeight = total * itemHeight
            // So this works perfectly.
            container.scrollTop = container.scrollHeight;
            this.scrollTop = container.scrollTop; // Update state immediately
        }
    },

    clearLogs() {
        this.logs = [];
        this._filteredLogsCache = [];
    }
});
