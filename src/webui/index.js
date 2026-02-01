/**
 * WebUI Module - Optional web interface for account management
 *
 * This module provides a web-based UI for:
 * - Dashboard with real-time model quota visualization
 * - Account management (add via OAuth, enable/disable, refresh, remove)
 * - Live server log streaming with filtering
 * - Claude CLI configuration editor
 *
 * Usage in server.js:
 *   import { mountWebUI } from './webui/index.ts';
 *   mountWebUI(app, __dirname, accountManager);
 */

import path from 'path';
import { serveStatic } from 'hono/bun';
import { streamSSE } from 'hono/streaming';
import { getPublicConfig, saveConfig, config } from '../config.js';
import { DEFAULT_PORT, ACCOUNT_CONFIG_PATH, MAX_ACCOUNTS, DEFAULT_PRESETS } from '../constants.js';
import { readClaudeConfig, updateClaudeConfig, replaceClaudeConfig, getClaudeConfigPath, readPresets, savePreset, deletePreset } from '../utils/claude-config.js';
import { logger } from '../utils/logger.js';
import { getAuthorizationUrl, completeOAuthFlow, startCallbackServer } from '../auth/oauth.js';
import { loadAccounts, saveAccounts } from '../account-manager/storage.js';
import { getPackageVersion } from '../utils/helpers.js';

// Get package version
const packageVersion = getPackageVersion();

// OAuth state storage (state -> { server, verifier, state, timestamp })
// Maps state ID to active OAuth flow data
const pendingOAuthFlows = new Map();

/**
 * WebUI Helper Functions - Direct account manipulation
 * These functions work around AccountManager's limited API by directly
 * manipulating the accounts.json config file (non-invasive approach for PR)
 */

/**
 * Set account enabled/disabled state
 */
async function setAccountEnabled(email, enabled) {
    const { accounts, settings, activeIndex } = await loadAccounts(ACCOUNT_CONFIG_PATH);
    const account = accounts.find(a => a.email === email);
    if (!account) {
        throw new Error(`Account ${email} not found`);
    }
    account.enabled = enabled;
    await saveAccounts(ACCOUNT_CONFIG_PATH, accounts, settings, activeIndex);
    logger.info(`[WebUI] Account ${email} ${enabled ? 'enabled' : 'disabled'}`);
}

/**
 * Remove account from config
 */
async function removeAccount(email) {
    const { accounts, settings, activeIndex } = await loadAccounts(ACCOUNT_CONFIG_PATH);
    const index = accounts.findIndex(a => a.email === email);
    if (index === -1) {
        throw new Error(`Account ${email} not found`);
    }
    accounts.splice(index, 1);
    // Adjust activeIndex if needed
    const newActiveIndex = activeIndex >= accounts.length ? Math.max(0, accounts.length - 1) : activeIndex;
    await saveAccounts(ACCOUNT_CONFIG_PATH, accounts, settings, newActiveIndex);
    logger.info(`[WebUI] Account ${email} removed`);
}

/**
 * Add new account to config
 * @throws {Error} If MAX_ACCOUNTS limit is reached (for new accounts only)
 */
async function addAccount(accountData) {
    const { accounts, settings, activeIndex } = await loadAccounts(ACCOUNT_CONFIG_PATH);

    // Check if account already exists
    const existingIndex = accounts.findIndex(a => a.email === accountData.email);
    if (existingIndex !== -1) {
        // Update existing account
        accounts[existingIndex] = {
            ...accounts[existingIndex],
            ...accountData,
            enabled: true,
            isInvalid: false,
            invalidReason: null,
            addedAt: accounts[existingIndex].addedAt || new Date().toISOString()
        };
        logger.info(`[WebUI] Account ${accountData.email} updated`);
    } else {
        // Check MAX_ACCOUNTS limit before adding new account
        if (accounts.length >= MAX_ACCOUNTS) {
            throw new Error(`Maximum of ${MAX_ACCOUNTS} accounts reached. Update maxAccounts in config to increase the limit.`);
        }
        // Add new account
        accounts.push({
            ...accountData,
            enabled: true,
            isInvalid: false,
            invalidReason: null,
            modelRateLimits: {},
            lastUsed: null,
            addedAt: new Date().toISOString()
        });
        logger.info(`[WebUI] Account ${accountData.email} added`);
    }

    await saveAccounts(ACCOUNT_CONFIG_PATH, accounts, settings, activeIndex);
}

/**
 * Auth Middleware - Optional password protection for WebUI
 * Password can be set via WEBUI_PASSWORD env var or config.json
 */
function createAuthMiddleware() {
    return async (c, next) => {
        const password = config.webuiPassword;
        if (!password) {
            await next();
            return;
        }

        // Determine if this path should be protected
        const isApiRoute = c.req.path.startsWith('/api/');
        const isAuthUrl = c.req.path === '/api/auth/url';
        const isConfigGet = c.req.path === '/api/config' && c.req.method === 'GET';
        const isProtected = (isApiRoute && !isAuthUrl && !isConfigGet) || c.req.path === '/account-limits' || c.req.path === '/health';

        if (isProtected) {
            const providedPassword = c.req.header('x-webui-password') || c.req.query('password');
            if (providedPassword !== password) {
                return c.json({ status: 'error', error: 'Unauthorized: Password required' }, 401);
            }
        }
        await next();
    };
}

/**
 * Mount WebUI routes and middleware on Hono app
 * @param {import('hono').Hono} app - Hono application instance
 * @param {string} dirname - __dirname of the calling module (for static file path)
 * @param {AccountManager} accountManager - Account manager instance
 */
export function mountWebUI(app, dirname, accountManager) {
    // Apply auth middleware
    app.use('*', createAuthMiddleware());

    // Serve static files from public directory
    app.use('/*', serveStatic({ root: './public' }));

    // ==========================================
    // Account Management API
    // ==========================================

    /**
     * GET /api/accounts - List all accounts with status
     */
    app.get('/api/accounts', async (c) => {
        try {
            const status = accountManager.getStatus();
            return c.json({
                status: 'ok',
                accounts: status.accounts,
                summary: {
                    total: status.total,
                    available: status.available,
                    rateLimited: status.rateLimited,
                    invalid: status.invalid
                }
            });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/accounts/:email/refresh - Refresh specific account token
     */
    app.post('/api/accounts/:email/refresh', async (c) => {
        try {
            const email = c.req.param('email');
            accountManager.clearTokenCache(email);
            accountManager.clearProjectCache(email);
            return c.json({
                status: 'ok',
                message: `Token cache cleared for ${email}`
            });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/accounts/:email/toggle - Enable/disable account
     */
    app.post('/api/accounts/:email/toggle', async (c) => {
        try {
            const email = c.req.param('email');
            const { enabled } = await c.req.json();

            if (typeof enabled !== 'boolean') {
                return c.json({ status: 'error', error: 'enabled must be a boolean' }, 400);
            }

            await setAccountEnabled(email, enabled);

            // Reload AccountManager to pick up changes
            await accountManager.reload();

            return c.json({
                status: 'ok',
                message: `Account ${email} ${enabled ? 'enabled' : 'disabled'}`
            });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * DELETE /api/accounts/:email - Remove account
     */
    app.delete('/api/accounts/:email', async (c) => {
        try {
            const email = c.req.param('email');
            await removeAccount(email);

            // Reload AccountManager to pick up changes
            await accountManager.reload();

            return c.json({
                status: 'ok',
                message: `Account ${email} removed`
            });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * PATCH /api/accounts/:email - Update account settings (thresholds)
     */
    app.patch('/api/accounts/:email', async (c) => {
        try {
            const email = c.req.param('email');
            const { quotaThreshold, modelQuotaThresholds } = await c.req.json();

            const { accounts, settings, activeIndex } = await loadAccounts(ACCOUNT_CONFIG_PATH);
            const account = accounts.find(a => a.email === email);

            if (!account) {
                return c.json({ status: 'error', error: `Account ${email} not found` }, 404);
            }

            // Validate and update quotaThreshold (0-0.99 or null/undefined to clear)
            if (quotaThreshold !== undefined) {
                if (quotaThreshold === null) {
                    delete account.quotaThreshold;
                } else if (typeof quotaThreshold === 'number' && quotaThreshold >= 0 && quotaThreshold < 1) {
                    account.quotaThreshold = quotaThreshold;
                } else {
                    return c.json({ status: 'error', error: 'quotaThreshold must be 0-0.99 or null' }, 400);
                }
            }

            // Validate and update modelQuotaThresholds (full replacement, not merge)
            if (modelQuotaThresholds !== undefined) {
                if (modelQuotaThresholds === null || (typeof modelQuotaThresholds === 'object' && Object.keys(modelQuotaThresholds).length === 0)) {
                    // Clear all model thresholds
                    delete account.modelQuotaThresholds;
                } else if (typeof modelQuotaThresholds === 'object') {
                    // Validate all thresholds first
                    for (const [modelId, threshold] of Object.entries(modelQuotaThresholds)) {
                        if (typeof threshold !== 'number' || threshold < 0 || threshold >= 1) {
                            return c.json({
                                status: 'error',
                                error: `Invalid threshold for model ${modelId}: must be 0-0.99`
                            }, 400);
                        }
                    }
                    // Replace entire object (not merge)
                    account.modelQuotaThresholds = { ...modelQuotaThresholds };
                } else {
                    return c.json({ status: 'error', error: 'modelQuotaThresholds must be an object or null' }, 400);
                }
            }

            await saveAccounts(ACCOUNT_CONFIG_PATH, accounts, settings, activeIndex);

            // Reload AccountManager to pick up changes
            await accountManager.reload();

            logger.info(`[WebUI] Account ${email} thresholds updated`);

            return c.json({
                status: 'ok',
                message: `Account ${email} thresholds updated`,
                account: {
                    email: account.email,
                    quotaThreshold: account.quotaThreshold,
                    modelQuotaThresholds: account.modelQuotaThresholds || {}
                }
            });
        } catch (error) {
            logger.error('[WebUI] Error updating account thresholds:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/accounts/reload - Reload accounts from disk
     */
    app.post('/api/accounts/reload', async (c) => {
        try {
            // Reload AccountManager from disk
            await accountManager.reload();

            const status = accountManager.getStatus();
            return c.json({
                status: 'ok',
                message: 'Accounts reloaded from disk',
                summary: status.summary
            });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * GET /api/accounts/export - Export accounts
     */
    app.get('/api/accounts/export', async (c) => {
        try {
            const { accounts } = await loadAccounts(ACCOUNT_CONFIG_PATH);

            // Export only essential fields for portability
            const exportData = accounts
                .filter(acc => acc.source !== 'database')
                .map(acc => {
                    const essential = { email: acc.email };
                    // Use snake_case for compatibility
                    if (acc.refreshToken) {
                        essential.refresh_token = acc.refreshToken;
                    }
                    if (acc.apiKey) {
                        essential.api_key = acc.apiKey;
                    }
                    return essential;
                });

            // Return plain array for simpler format
            return c.json(exportData);
        } catch (error) {
            logger.error('[WebUI] Export accounts error:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/accounts/import - Batch import accounts
     */
    app.post('/api/accounts/import', async (c) => {
        try {
            // Support both wrapped format { accounts: [...] } and plain array [...]
            const body = await c.req.json();
            let importAccounts = body;
            if (body.accounts && Array.isArray(body.accounts)) {
                importAccounts = body.accounts;
            }

            if (!Array.isArray(importAccounts) || importAccounts.length === 0) {
                return c.json({
                    status: 'error',
                    error: 'accounts must be a non-empty array'
                }, 400);
            }

            const results = { added: [], updated: [], failed: [] };

            // Load existing accounts once before the loop
            const { accounts: existingAccounts } = await loadAccounts(ACCOUNT_CONFIG_PATH);
            const existingEmails = new Set(existingAccounts.map(a => a.email));

            for (const acc of importAccounts) {
                try {
                    // Validate required fields
                    if (!acc.email) {
                        results.failed.push({ email: acc.email || 'unknown', reason: 'Missing email' });
                        continue;
                    }

                    // Support both snake_case and camelCase
                    const refreshToken = acc.refresh_token || acc.refreshToken;
                    const apiKey = acc.api_key || acc.apiKey;

                    // Must have at least one credential
                    if (!refreshToken && !apiKey) {
                        results.failed.push({ email: acc.email, reason: 'Missing refresh_token or api_key' });
                        continue;
                    }

                    // Check if account already exists
                    const exists = existingEmails.has(acc.email);

                    // Add account
                    await addAccount({
                        email: acc.email,
                        source: apiKey ? 'manual' : 'oauth',
                        refreshToken: refreshToken,
                        apiKey: apiKey
                    });

                    if (exists) {
                        results.updated.push(acc.email);
                    } else {
                        results.added.push(acc.email);
                    }
                } catch (err) {
                    results.failed.push({ email: acc.email, reason: err.message });
                }
            }

            // Reload AccountManager
            await accountManager.reload();

            logger.info(`[WebUI] Import complete: ${results.added.length} added, ${results.updated.length} updated, ${results.failed.length} failed`);

            return c.json({
                status: 'ok',
                results,
                message: `Imported ${results.added.length + results.updated.length} accounts`
            });
        } catch (error) {
            logger.error('[WebUI] Import accounts error:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    // ==========================================
    // Configuration API
    // ==========================================

    /**
     * GET /api/config - Get server configuration
     */
    app.get('/api/config', (c) => {
        try {
            const publicConfig = getPublicConfig();
            return c.json({
                status: 'ok',
                config: publicConfig,
                version: packageVersion,
                note: 'Edit ~/.config/antigravity-proxy/config.json or use env vars to change these values'
            });
        } catch (error) {
            logger.error('[WebUI] Error getting config:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/config - Update server configuration
     */
    app.post('/api/config', async (c) => {
        try {
            const body = await c.req.json();
            const { debug, logLevel, maxRetries, retryBaseMs, retryMaxMs, persistTokenCache, defaultCooldownMs, maxWaitBeforeErrorMs, maxAccounts, globalQuotaThreshold, accountSelection, rateLimitDedupWindowMs, maxConsecutiveFailures, extendedCooldownMs, maxCapacityRetries } = body;

            // Only allow updating specific fields (security)
            const updates = {};
            if (typeof debug === 'boolean') updates.debug = debug;
            if (logLevel && ['info', 'warn', 'error', 'debug'].includes(logLevel)) {
                updates.logLevel = logLevel;
            }
            if (typeof maxRetries === 'number' && maxRetries >= 1 && maxRetries <= 20) {
                updates.maxRetries = maxRetries;
            }
            if (typeof retryBaseMs === 'number' && retryBaseMs >= 100 && retryBaseMs <= 10000) {
                updates.retryBaseMs = retryBaseMs;
            }
            if (typeof retryMaxMs === 'number' && retryMaxMs >= 1000 && retryMaxMs <= 120000) {
                updates.retryMaxMs = retryMaxMs;
            }
            if (typeof persistTokenCache === 'boolean') {
                updates.persistTokenCache = persistTokenCache;
            }
            if (typeof defaultCooldownMs === 'number' && defaultCooldownMs >= 1000 && defaultCooldownMs <= 300000) {
                updates.defaultCooldownMs = defaultCooldownMs;
            }
            if (typeof maxWaitBeforeErrorMs === 'number' && maxWaitBeforeErrorMs >= 0 && maxWaitBeforeErrorMs <= 600000) {
                updates.maxWaitBeforeErrorMs = maxWaitBeforeErrorMs;
            }
            if (typeof maxAccounts === 'number' && maxAccounts >= 1 && maxAccounts <= 100) {
                updates.maxAccounts = maxAccounts;
            }
            if (typeof globalQuotaThreshold === 'number' && globalQuotaThreshold >= 0 && globalQuotaThreshold < 1) {
                updates.globalQuotaThreshold = globalQuotaThreshold;
            }
            if (typeof rateLimitDedupWindowMs === 'number' && rateLimitDedupWindowMs >= 1000 && rateLimitDedupWindowMs <= 30000) {
                updates.rateLimitDedupWindowMs = rateLimitDedupWindowMs;
            }
            if (typeof maxConsecutiveFailures === 'number' && maxConsecutiveFailures >= 1 && maxConsecutiveFailures <= 10) {
                updates.maxConsecutiveFailures = maxConsecutiveFailures;
            }
            if (typeof extendedCooldownMs === 'number' && extendedCooldownMs >= 10000 && extendedCooldownMs <= 300000) {
                updates.extendedCooldownMs = extendedCooldownMs;
            }
            if (typeof maxCapacityRetries === 'number' && maxCapacityRetries >= 1 && maxCapacityRetries <= 10) {
                updates.maxCapacityRetries = maxCapacityRetries;
            }
            // Account selection strategy validation
            if (accountSelection && typeof accountSelection === 'object') {
                const validStrategies = ['sticky', 'round-robin', 'hybrid'];
                if (accountSelection.strategy && validStrategies.includes(accountSelection.strategy)) {
                    updates.accountSelection = {
                        ...(config.accountSelection || {}),
                        strategy: accountSelection.strategy
                    };
                }
            }

            if (Object.keys(updates).length === 0) {
                return c.json({
                    status: 'error',
                    error: 'No valid configuration updates provided'
                }, 400);
            }

            const success = saveConfig(updates);

            if (success) {
                return c.json({
                    status: 'ok',
                    message: 'Configuration saved. Restart server to apply some changes.',
                    updates: updates,
                    config: getPublicConfig()
                });
            } else {
                return c.json({
                    status: 'error',
                    error: 'Failed to save configuration file'
                }, 500);
            }
        } catch (error) {
            logger.error('[WebUI] Error updating config:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/config/password - Change WebUI password
     */
    app.post('/api/config/password', async (c) => {
        try {
            const { oldPassword, newPassword } = await c.req.json();

            // Validate input
            if (!newPassword || typeof newPassword !== 'string') {
                return c.json({
                    status: 'error',
                    error: 'New password is required'
                }, 400);
            }

            // If current password exists, verify old password
            if (config.webuiPassword && config.webuiPassword !== oldPassword) {
                return c.json({
                    status: 'error',
                    error: 'Invalid current password'
                }, 403);
            }

            // Save new password
            const success = saveConfig({ webuiPassword: newPassword });

            if (success) {
                // Update in-memory config
                config.webuiPassword = newPassword;
                return c.json({
                    status: 'ok',
                    message: 'Password changed successfully'
                });
            } else {
                throw new Error('Failed to save password to config file');
            }
        } catch (error) {
            logger.error('[WebUI] Error changing password:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * GET /api/settings - Get runtime settings
     */
    app.get('/api/settings', async (c) => {
        try {
            const settings = accountManager.getSettings ? accountManager.getSettings() : {};
            return c.json({
                status: 'ok',
                settings: {
                    ...settings,
                    port: process.env.PORT || DEFAULT_PORT
                }
            });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    // ==========================================
    // Claude CLI Configuration API
    // ==========================================

    /**
     * GET /api/claude/config - Get Claude CLI configuration
     */
    app.get('/api/claude/config', async (c) => {
        try {
            const claudeConfig = await readClaudeConfig();
            return c.json({
                status: 'ok',
                config: claudeConfig,
                path: getClaudeConfigPath()
            });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/claude/config - Update Claude CLI configuration
     */
    app.post('/api/claude/config', async (c) => {
        try {
            const updates = await c.req.json();
            if (!updates || typeof updates !== 'object') {
                return c.json({ status: 'error', error: 'Invalid config updates' }, 400);
            }

            const newConfig = await updateClaudeConfig(updates);
            return c.json({
                status: 'ok',
                config: newConfig,
                message: 'Claude configuration updated'
            });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/claude/config/restore - Restore Claude CLI to default (remove proxy settings)
     */
    app.post('/api/claude/config/restore', async (c) => {
        try {
            const claudeConfig = await readClaudeConfig();

            // Proxy-related environment variables to remove when restoring defaults
            const PROXY_ENV_VARS = [
                'ANTHROPIC_BASE_URL',
                'ANTHROPIC_AUTH_TOKEN',
                'ANTHROPIC_MODEL',
                'CLAUDE_CODE_SUBAGENT_MODEL',
                'ANTHROPIC_DEFAULT_OPUS_MODEL',
                'ANTHROPIC_DEFAULT_SONNET_MODEL',
                'ANTHROPIC_DEFAULT_HAIKU_MODEL',
                'ENABLE_EXPERIMENTAL_MCP_CLI'
            ];

            // Remove proxy-related environment variables to restore defaults
            if (claudeConfig.env) {
                for (const key of PROXY_ENV_VARS) {
                    delete claudeConfig.env[key];
                }
                // Remove env entirely if empty to truly restore defaults
                if (Object.keys(claudeConfig.env).length === 0) {
                    delete claudeConfig.env;
                }
            }

            // Use replaceClaudeConfig to completely overwrite the config (not merge)
            const newConfig = await replaceClaudeConfig(claudeConfig);

            logger.info(`[WebUI] Restored Claude CLI config to defaults at ${getClaudeConfigPath()}`);

            return c.json({
                status: 'ok',
                config: newConfig,
                message: 'Claude CLI configuration restored to defaults'
            });
        } catch (error) {
            logger.error('[WebUI] Error restoring Claude config:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    // ==========================================
    // Claude CLI Mode Toggle API (Proxy/Paid)
    // ==========================================

    /**
     * GET /api/claude/mode - Get current mode (proxy or paid)
     * Returns 'proxy' if ANTHROPIC_BASE_URL is set to localhost, 'paid' otherwise
     */
    app.get('/api/claude/mode', async (c) => {
        try {
            const claudeConfig = await readClaudeConfig();
            const baseUrl = claudeConfig.env?.ANTHROPIC_BASE_URL || '';

            // Determine mode based on ANTHROPIC_BASE_URL
            const isProxy = baseUrl && (
                baseUrl.includes('localhost') ||
                baseUrl.includes('127.0.0.1') ||
                baseUrl.includes('::1') ||
                baseUrl.includes('0.0.0.0')
            );

            return c.json({
                status: 'ok',
                mode: isProxy ? 'proxy' : 'paid'
            });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/claude/mode - Switch between proxy and paid mode
     * Body: { mode: 'proxy' | 'paid' }
     * 
     * When switching to 'paid' mode:
     * - Removes the entire 'env' object from settings.json
     * - Claude CLI uses its built-in defaults (official Anthropic API)
     * 
     * When switching to 'proxy' mode:
     * - Sets 'env' to the first default preset config (from constants.js)
     */
    app.post('/api/claude/mode', async (c) => {
        try {
            const { mode } = await c.req.json();

            if (!mode || !['proxy', 'paid'].includes(mode)) {
                return c.json({
                    status: 'error',
                    error: 'mode must be "proxy" or "paid"'
                }, 400);
            }

            const claudeConfig = await readClaudeConfig();

            if (mode === 'proxy') {
                // Switch to proxy mode - use first default preset config (e.g., "Claude Thinking")
                claudeConfig.env = { ...DEFAULT_PRESETS[0].config };
            } else {
                // Switch to paid mode - remove env entirely
                delete claudeConfig.env;
            }

            // Save the updated config
            const newConfig = await replaceClaudeConfig(claudeConfig);

            logger.info(`[WebUI] Switched Claude CLI to ${mode} mode`);

            return c.json({
                status: 'ok',
                mode,
                config: newConfig,
                message: `Switched to ${mode === 'proxy' ? 'Proxy' : 'Paid (Anthropic API)'} mode. Restart Claude CLI to apply.`
            });
        } catch (error) {
            logger.error('[WebUI] Error switching mode:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    // ==========================================
    // Claude CLI Presets API
    // ==========================================


    /**
     * GET /api/claude/presets - Get all saved presets
     */
    app.get('/api/claude/presets', async (c) => {
        try {
            const presets = await readPresets();
            return c.json({ status: 'ok', presets });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/claude/presets - Save a new preset
     */
    app.post('/api/claude/presets', async (c) => {
        try {
            const { name, config: presetConfig } = await c.req.json();
            if (!name || typeof name !== 'string' || !name.trim()) {
                return c.json({ status: 'error', error: 'Preset name is required' }, 400);
            }
            if (!presetConfig || typeof presetConfig !== 'object') {
                return c.json({ status: 'error', error: 'Config object is required' }, 400);
            }

            const presets = await savePreset(name.trim(), presetConfig);
            return c.json({ status: 'ok', presets, message: `Preset "${name}" saved` });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * DELETE /api/claude/presets/:name - Delete a preset
     */
    app.delete('/api/claude/presets/:name', async (c) => {
        try {
            const name = c.req.param('name');
            if (!name) {
                return c.json({ status: 'error', error: 'Preset name is required' }, 400);
            }

            const presets = await deletePreset(name);
            return c.json({ status: 'ok', presets, message: `Preset "${name}" deleted` });
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/models/config - Update model configuration (hidden/pinned/alias)
     */
    app.post('/api/models/config', async (c) => {
        try {
            const { modelId, config: newModelConfig } = await c.req.json();

            if (!modelId || typeof newModelConfig !== 'object') {
                return c.json({ status: 'error', error: 'Invalid parameters' }, 400);
            }

            // Load current config
            const currentMapping = config.modelMapping || {};

            // Update specific model config
            currentMapping[modelId] = {
                ...currentMapping[modelId],
                ...newModelConfig
            };

            // Save back to main config
            const success = saveConfig({ modelMapping: currentMapping });

            if (success) {
                // Update in-memory config reference
                config.modelMapping = currentMapping;
                return c.json({ status: 'ok', modelConfig: currentMapping[modelId] });
            } else {
                throw new Error('Failed to save configuration');
            }
        } catch (error) {
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    // ==========================================
    // Logs API
    // ==========================================

    /**
     * GET /api/logs - Get log history
     */
    app.get('/api/logs', (c) => {
        return c.json({
            status: 'ok',
            logs: logger.getHistory ? logger.getHistory() : []
        });
    });

    /**
     * GET /api/logs/stream - Stream logs via SSE
     */
    app.get('/api/logs/stream', async (c) => {
        return streamSSE(c, async (stream) => {
            const sendLog = async (log) => {
                await stream.writeSSE({
                    data: JSON.stringify(log)
                });
            };

            // Send recent history if requested
            if (c.req.query('history') === 'true' && logger.getHistory) {
                const history = logger.getHistory();
                for (const log of history) {
                    await sendLog(log);
                }
            }

            // Subscribe to new logs
            if (logger.on) {
                logger.on('log', sendLog);
            }

            // Wait until aborted
            await new Promise((resolve, reject) => {
                stream.onAbort(() => {
                    resolve();
                });
            });

            // Cleanup on disconnect
            if (logger.off) {
                logger.off('log', sendLog);
            }
        });
    });

    // ==========================================
    // OAuth API
    // ==========================================

    /**
     * GET /api/auth/url - Get OAuth URL to start the flow
     * Uses CLI's OAuth flow (localhost:51121) instead of WebUI's port
     * to match Google OAuth Console's authorized redirect URIs
     */
    app.get('/api/auth/url', async (c) => {
        try {
            // Clean up old flows (> 10 mins)
            const now = Date.now();
            for (const [key, val] of pendingOAuthFlows.entries()) {
                if (now - val.timestamp > 10 * 60 * 1000) {
                    pendingOAuthFlows.delete(key);
                }
            }

            // Generate OAuth URL using default redirect URI (localhost:51121)
            const { url, verifier, state } = getAuthorizationUrl();

            // Start callback server on port 51121 (same as CLI)
            const { promise: serverPromise, abort: abortServer } = startCallbackServer(state, 120000); // 2 min timeout

            // Store the flow data
            pendingOAuthFlows.set(state, {
                serverPromise,
                abortServer,
                verifier,
                state,
                timestamp: Date.now()
            });

            // Start async handler for the OAuth callback
            serverPromise
                .then(async (code) => {
                    try {
                        logger.info('[WebUI] Received OAuth callback, completing flow...');
                        const accountData = await completeOAuthFlow(code, verifier);

                        // Add or update the account
                        // Note: Don't set projectId here - it will be discovered and stored
                        // in the refresh token via getProjectForAccount() on first use
                        await addAccount({
                            email: accountData.email,
                            refreshToken: accountData.refreshToken,
                            source: 'oauth'
                        });

                        // Reload AccountManager to pick up the new account
                        await accountManager.reload();

                        logger.success(`[WebUI] Account ${accountData.email} added successfully`);
                    } catch (err) {
                        logger.error('[WebUI] OAuth flow completion error:', err);
                    } finally {
                        pendingOAuthFlows.delete(state);
                    }
                })
                .catch((err) => {
                    // Only log if not aborted (manual completion causes this)
                    if (!err.message?.includes('aborted')) {
                        logger.error('[WebUI] OAuth callback server error:', err);
                    }
                    pendingOAuthFlows.delete(state);
                });

            return c.json({ status: 'ok', url, state });
        } catch (error) {
            logger.error('[WebUI] Error generating auth URL:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * POST /api/auth/complete - Complete OAuth with manually submitted callback URL/code
     * Used when auto-callback cannot reach the local server
     */
    app.post('/api/auth/complete', async (c) => {
        try {
            const { callbackInput, state } = await c.req.json();

            if (!callbackInput || !state) {
                return c.json({
                    status: 'error',
                    error: 'Missing callbackInput or state'
                }, 400);
            }

            // Find the pending flow
            const flowData = pendingOAuthFlows.get(state);
            if (!flowData) {
                return c.json({
                    status: 'error',
                    error: 'OAuth flow not found. The account may have been already added via auto-callback. Please refresh the account list.'
                }, 400);
            }

            const { verifier, abortServer } = flowData;

            // Extract code from input (URL or raw code)
            const { extractCodeFromInput, completeOAuthFlow } = await import('../auth/oauth.js');
            const { code } = extractCodeFromInput(callbackInput);

            // Complete the OAuth flow
            const accountData = await completeOAuthFlow(code, verifier);

            // Add or update the account
            await addAccount({
                email: accountData.email,
                refreshToken: accountData.refreshToken,
                projectId: accountData.projectId,
                source: 'oauth'
            });

            // Reload AccountManager to pick up the new account
            await accountManager.reload();

            // Abort the callback server since manual completion succeeded
            if (abortServer) {
                abortServer();
            }

            // Clean up
            pendingOAuthFlows.delete(state);

            logger.success(`[WebUI] Account ${accountData.email} added via manual callback`);

            return c.json({
                status: 'ok',
                email: accountData.email,
                message: `Account ${accountData.email} added successfully`
            });
        } catch (error) {
            logger.error('[WebUI] Manual OAuth completion error:', error);
            return c.json({ status: 'error', error: error.message }, 500);
        }
    });

    /**
     * Note: /oauth/callback route removed
     * OAuth callbacks are now handled by the temporary server on port 51121
     * (same as CLI) to match Google OAuth Console's authorized redirect URIs
     */

    logger.info('[WebUI] Mounted at /');
}
