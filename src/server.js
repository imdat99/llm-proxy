/**
 * Hono Server - Anthropic-compatible API & OpenAI-compatible API
 * Proxies to Google Cloud Code via Antigravity
 * Supports multi-account load balancing
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { streamSSE, stream } from 'hono/streaming';
import path from 'path';
import { fileURLToPath } from 'url';
import { sendMessage, sendMessageStream, listModels, getModelQuotas, getSubscriptionTier, isValidModel } from './cloudcode/index.js';
import { mountWebUI } from './webui/index.js';
import { config } from './config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
import { forceRefresh } from './auth/token-extractor.js';
// import { REQUEST_BODY_LIMIT } from './constants.ts'; // Hono doesn't strictly limit body size by default this way, handled differently
import { AccountManager } from './account-manager/index.js';
import { clearThinkingSignatureCache } from './format/signature-cache.js';
import { formatDuration } from './utils/helpers.js';
import { logger } from './utils/logger.js';
import usageStats from './modules/usage-stats.js';
import { convertOpenAIRequestToAnthropic, convertAnthropicResponseToOpenAI, convertAnthropicStreamToOpenAI } from './format/openai-converter.js';
import {
    convertOllamaChatRequestToAnthropic,
    convertOllamaGenerateRequestToAnthropic,
    convertAnthropicResponseToOllamaChat,
    convertAnthropicResponseToOllamaGenerate,
    convertAnthropicStreamToOllamaChat,
    convertAnthropicStreamToOllamaGenerate
} from './format/ollama-converter.js';

// Parse fallback flag directly from command line args to avoid circular dependency
const args = process.argv.slice(2);
const FALLBACK_ENABLED = args.includes('--fallback') || process.env.FALLBACK === 'true';

// Parse --strategy flag (format: --strategy=sticky or --strategy sticky)
let STRATEGY_OVERRIDE = null;
for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--strategy=')) {
        STRATEGY_OVERRIDE = args[i].split('=')[1];
    } else if (args[i] === '--strategy' && args[i + 1]) {
        STRATEGY_OVERRIDE = args[i + 1];
    }
}

const app = new Hono();

// Initialize account manager (will be fully initialized on first request or startup)
export const accountManager = new AccountManager();

// Track initialization status
let isInitialized = false;
let initError = null;
let initPromise = null;

/**
 * Ensure account manager is initialized (with race condition protection)
 */
async function ensureInitialized() {
    if (isInitialized) return;

    // If initialization is already in progress, wait for it
    if (initPromise) return initPromise;

    initPromise = (async () => {
        try {
            await accountManager.initialize(STRATEGY_OVERRIDE);
            isInitialized = true;
            const status = accountManager.getStatus();
            logger.success(`[Server] Account pool initialized: ${status.summary}`);
        } catch (error) {
            initError = error;
            let initPromise = null; // Allow retry on failure
            logger.error('[Server] Failed to initialize account manager:', error.message);
            throw error;
        }
    })();

    return initPromise;
}

// Middleware
app.use('*', cors());

// API Key authentication middleware for /v1/* endpoints
app.use('/v1/*', async (c, next) => {
    // Skip validation if apiKey is not configured
    if (!config.apiKey) {
        await next();
        return;
    }

    const authHeader = c.req.header('authorization');
    const xApiKey = c.req.header('x-api-key');

    let providedKey = '';
    if (authHeader && authHeader.startsWith('Bearer ')) {
        providedKey = authHeader.substring(7);
    } else if (xApiKey) {
        providedKey = xApiKey;
    }

    if (!providedKey || providedKey !== config.apiKey) {
        logger.warn(`[API] Unauthorized request, invalid API key`);
        return c.json({
            type: 'error',
            error: {
                type: 'authentication_error',
                message: 'Invalid or missing API key'
            }
        }, 401);
    }

    await next();
});

// Setup usage statistics middleware
usageStats.setupMiddleware(app);
usageStats.setupRoutes(app);

/**
 * Silent handler for Claude Code CLI root POST requests
 * Claude Code sends heartbeat/event requests to POST / which we don't need
 */
app.post('/', (c) => {
    return c.json({ status: 'ok' });
});

app.post('/api/event_logging/batch', (c) => {
    return c.json({ status: 'ok' });
});


// Mount WebUI (optional web interface for account management)


/**
 * Parse error message to extract error type, status code, and user-friendly message
 */
function parseError(error) {
    let errorType = 'api_error';
    let statusCode = 500;
    let errorMessage = error.message;

    if (error.message.includes('401') || error.message.includes('UNAUTHENTICATED')) {
        errorType = 'authentication_error';
        statusCode = 401;
        errorMessage = 'Authentication failed. Make sure Antigravity is running with a valid token.';
    } else if (error.message.includes('429') || error.message.includes('RESOURCE_EXHAUSTED') || error.message.includes('QUOTA_EXHAUSTED')) {
        errorType = 'invalid_request_error';  // Use invalid_request_error to force client to purge/stop
        statusCode = 400;  // Use 400 to ensure client does not retry (429 and 529 trigger retries)

        // Try to extract the quota reset time from the error
        const resetMatch = error.message.match(/quota will reset after ([\dh\dm\ds]+)/i);
        // Try to extract model from our error format "Rate limited on <model>" or JSON format
        const modelMatch = error.message.match(/Rate limited on ([^.]+)\./) || error.message.match(/"model":\s*"([^"]+)"/);
        const model = modelMatch ? modelMatch[1] : 'the model';

        if (resetMatch) {
            errorMessage = `You have exhausted your capacity on ${model}. Quota will reset after ${resetMatch[1]}.`;
        } else {
            errorMessage = `You have exhausted your capacity on ${model}. Please wait for your quota to reset.`;
        }
    } else if (error.message.includes('invalid_request_error') || error.message.includes('INVALID_ARGUMENT')) {
        errorType = 'invalid_request_error';
        statusCode = 400;
        const msgMatch = error.message.match(/"message":"([^"]+)"/);
        if (msgMatch) errorMessage = msgMatch[1];
    } else if (error.message.includes('All endpoints failed')) {
        errorType = 'api_error';
        statusCode = 503;
        errorMessage = 'Unable to connect to Claude API. Check that Antigravity is running.';
    } else if (error.message.includes('PERMISSION_DENIED')) {
        errorType = 'permission_error';
        statusCode = 403;
        errorMessage = 'Permission denied. Check your Antigravity license.';
    }

    return { errorType, statusCode, errorMessage };
}

// Request logging middleware
app.use('*', async (c, next) => {
    const start = Date.now();
    await next();
    const duration = Date.now() - start;
    const status = c.res.status;
    const method = c.req.method;
    const url = c.req.path;
    const logMsg = `[${method}] ${url} ${status} (${duration}ms)`;

    // Skip standard logging for event logging batch unless in debug mode
    if (url === '/api/event_logging/batch' || url.startsWith('/v1/messages/count_tokens') || url.startsWith('/.well-known/')) {
        if (logger.isDebugEnabled) {
            logger.debug(logMsg);
        }
    } else {
        // Colorize status code
        if (status >= 500) {
            logger.error(logMsg);
        } else if (status >= 400) {
            logger.warn(logMsg);
        } else {
            logger.info(logMsg);
        }
    }
});


/**
 * Test endpoint - Clear thinking signature cache
 * Used for testing cold cache scenarios in cross-model tests
 */
app.post('/test/clear-signature-cache', (c) => {
    clearThinkingSignatureCache();
    logger.debug('[Test] Cleared thinking signature cache');
    return c.json({ success: true, message: 'Thinking signature cache cleared' });
});

/**
 * Health check endpoint - Detailed status
 * Returns status of all accounts including rate limits and model quotas
 */
app.get('/health', async (c) => {
    try {
        await ensureInitialized();
        const start = Date.now();

        // Get high-level status first
        const status = accountManager.getStatus();
        const allAccounts = accountManager.getAllAccounts();

        // Fetch quotas for each account in parallel to get detailed model info
        const accountDetails = await Promise.allSettled(
            allAccounts.map(async (account) => {
                // Check model-specific rate limits
                const activeModelLimits = Object.entries(account.modelRateLimits || {})
                    .filter(([_, limit]) => limit.isRateLimited && limit.resetTime > Date.now());
                const isRateLimited = activeModelLimits.length > 0;
                const soonestReset = activeModelLimits.length > 0
                    ? Math.min(...activeModelLimits.map(([_, l]) => l.resetTime))
                    : null;

                const baseInfo = {
                    email: account.email,
                    lastUsed: account.lastUsed ? new Date(account.lastUsed).toISOString() : null,
                    modelRateLimits: account.modelRateLimits || {},
                    rateLimitCooldownRemaining: soonestReset ? Math.max(0, soonestReset - Date.now()) : 0
                };

                // Skip invalid accounts for quota check
                if (account.isInvalid) {
                    return {
                        ...baseInfo,
                        status: 'invalid',
                        error: account.invalidReason,
                        models: {}
                    };
                }

                try {
                    const token = await accountManager.getTokenForAccount(account);
                    const projectId = account.subscription?.projectId || null;
                    const quotas = await getModelQuotas(token, projectId);

                    // Format quotas for readability
                    const formattedQuotas = {};
                    for (const [modelId, info] of Object.entries(quotas)) {
                        formattedQuotas[modelId] = {
                            remaining: info.remainingFraction !== null ? `${Math.round(info.remainingFraction * 100)}%` : 'N/A',
                            remainingFraction: info.remainingFraction,
                            resetTime: info.resetTime || null
                        };
                    }

                    return {
                        ...baseInfo,
                        status: isRateLimited ? 'rate-limited' : 'ok',
                        models: formattedQuotas
                    };
                } catch (error) {
                    return {
                        ...baseInfo,
                        status: 'error',
                        error: error.message,
                        models: {}
                    };
                }
            })
        );

        // Process results
        const detailedAccounts = accountDetails.map((result, index) => {
            if (result.status === 'fulfilled') {
                return result.value;
            } else {
                const acc = allAccounts[index];
                return {
                    email: acc.email,
                    status: 'error',
                    error: (result.reason)?.message || 'Unknown error',
                    modelRateLimits: acc.modelRateLimits || {},
                    lastUsed: null,
                    rateLimitCooldownRemaining: 0,
                    models: {}
                };
            }
        });

        return c.json({
            status: 'ok',
            timestamp: new Date().toISOString(),
            latencyMs: Date.now() - start,
            summary: status.summary,
            counts: {
                total: status.total,
                available: status.available,
                rateLimited: status.rateLimited,
                invalid: status.invalid
            },
            accounts: detailedAccounts
        });

    } catch (error) {
        logger.error('[API] Health check failed:', error);
        return c.json({
            status: 'error',
            error: error.message,
            timestamp: new Date().toISOString()
        }, 503);
    }
});

/**
 * Account limits endpoint - fetch quota/limits for all accounts × all models
 * Returns a table showing remaining quota and reset time for each combination
 * Use ?format=table for ASCII table output, default is JSON
 */
app.get('/account-limits', async (c) => {
    try {
        await ensureInitialized();
        const allAccounts = accountManager.getAllAccounts();
        const format = c.req.query('format') || 'json';
        const includeHistory = c.req.query('includeHistory') === 'true';

        // Fetch quotas for each account in parallel
        const results = await Promise.allSettled(
            allAccounts.map(async (account) => {
                // Skip invalid accounts
                if (account.isInvalid) {
                    return {
                        email: account.email,
                        status: 'invalid',
                        error: account.invalidReason,
                        models: {}
                    };
                }

                try {
                    const token = await accountManager.getTokenForAccount(account);

                    // Fetch subscription tier first to get project ID
                    const subscription = await getSubscriptionTier(token);

                    // Then fetch quotas with project ID for accurate quota info
                    const quotas = await getModelQuotas(token, subscription.projectId);

                    // Update account object with fresh data
                    account.subscription = {
                        tier: subscription.tier,
                        projectId: subscription.projectId,
                        detectedAt: Date.now()
                    };
                    account.quota = {
                        models: quotas,
                        lastChecked: Date.now()
                    };

                    // Save updated account data to disk (async, don't wait)
                    accountManager.saveToDisk().catch(err => {
                        logger.error('[Server] Failed to save account data:', err);
                    });

                    return {
                        email: account.email,
                        status: 'ok',
                        subscription: account.subscription,
                        models: quotas
                    };
                } catch (error) {
                    return {
                        email: account.email,
                        status: 'error',
                        error: error.message,
                        subscription: account.subscription || { tier: 'unknown', projectId: null },
                        models: {}
                    };
                }
            })
        );

        // Process results
        const accountLimits = results.map((result, index) => {
            if (result.status === 'fulfilled') {
                return result.value;
            } else {
                return {
                    email: allAccounts[index].email,
                    status: 'error',
                    error: result.reason?.message || 'Unknown error',
                    models: {}
                };
            }
        });

        // Collect all unique model IDs
        const allModelIds = new Set();
        for (const account of accountLimits) {
            for (const modelId of Object.keys(account.models || {})) {
                allModelIds.add(modelId);
            }
        }

        const sortedModels = Array.from(allModelIds).sort();

        // Return ASCII table format
        if (format === 'table') {
            c.header('Content-Type', 'text/plain; charset=utf-8');

            // Build table
            const lines = [];
            const timestamp = new Date().toLocaleString();
            lines.push(`Account Limits (${timestamp})`);

            // Get account status info
            const status = accountManager.getStatus();
            lines.push(`Accounts: ${status.total} total, ${status.available} available, ${status.rateLimited} rate-limited, ${status.invalid} invalid`);
            lines.push('');

            // Table 1: Account status
            const accColWidth = 25;
            const statusColWidth = 15;
            const lastUsedColWidth = 25;
            const resetColWidth = 25;

            let accHeader = 'Account'.padEnd(accColWidth) + 'Status'.padEnd(statusColWidth) + 'Last Used'.padEnd(lastUsedColWidth) + 'Quota Reset';
            lines.push(accHeader);
            lines.push('─'.repeat(accColWidth + statusColWidth + lastUsedColWidth + resetColWidth));

            for (const acc of status.accounts) {
                const shortEmail = acc.email.split('@')[0].slice(0, 22);
                const lastUsed = acc.lastUsed ? new Date(acc.lastUsed).toLocaleString() : 'never';

                // Get status and error from accountLimits
                const accLimit = accountLimits.find(a => a.email === acc.email);
                let accStatus;
                if (acc.isInvalid) {
                    accStatus = 'invalid';
                } else if (accLimit?.status === 'error') {
                    accStatus = 'error';
                } else {
                    // Count exhausted models (0% or null remaining)
                    const models = accLimit?.models || {};
                    const modelCount = Object.keys(models).length;
                    const exhaustedCount = Object.values(models).filter(
                        (q) => q.remainingFraction === 0 || q.remainingFraction === null
                    ).length;

                    if (exhaustedCount === 0) {
                        accStatus = 'ok';
                    } else {
                        accStatus = `(${exhaustedCount}/${modelCount}) limited`;
                    }
                }

                // Get reset time from quota API
                const claudeModel = sortedModels.find((m) => m.includes('claude'));
                const quota = claudeModel && accLimit?.models?.[claudeModel];
                const resetTime = quota?.resetTime
                    ? new Date(quota.resetTime).toLocaleString()
                    : '-';

                let row = shortEmail.padEnd(accColWidth) + accStatus.padEnd(statusColWidth) + lastUsed.padEnd(lastUsedColWidth) + resetTime;

                // Add error on next line if present
                if (accLimit?.error) {
                    lines.push(row);
                    lines.push('  └─ ' + accLimit.error);
                } else {
                    lines.push(row);
                }
            }
            lines.push('');

            // Calculate column widths - need more space for reset time info
            const modelColWidth = Math.max(28, ...sortedModels.map(m => m.length)) + 2;
            const accountColWidth = 30;

            // Header row
            let header = 'Model'.padEnd(modelColWidth);
            for (const acc of accountLimits) {
                const shortEmail = acc.email.split('@')[0].slice(0, 26);
                header += shortEmail.padEnd(accountColWidth);
            }
            lines.push(header);
            lines.push('─'.repeat(modelColWidth + accountLimits.length * accountColWidth));

            // Data rows
            for (const modelId of sortedModels) {
                let row = modelId.padEnd(modelColWidth);
                for (const acc of accountLimits) {
                    const quota = acc.models?.[modelId];
                    let cell;
                    if (acc.status !== 'ok' && acc.status !== 'rate-limited') {
                        cell = `[${acc.status}]`;
                    } else if (!quota) {
                        cell = '-';
                    } else if (quota.remainingFraction === 0 || quota.remainingFraction === null) {
                        // Show reset time for exhausted models
                        if (quota.resetTime) {
                            const resetMs = new Date(quota.resetTime).getTime() - Date.now();
                            if (resetMs > 0) {
                                cell = `0% (wait ${formatDuration(resetMs)})`;
                            } else {
                                cell = '0% (resetting...)';
                            }
                        } else {
                            cell = '0% (exhausted)';
                        }
                    } else {
                        const pct = Math.round(quota.remainingFraction * 100);
                        cell = `${pct}%`;
                    }
                    row += cell.padEnd(accountColWidth);
                }
                lines.push(row);
            }

            return c.text(lines.join('\n'));
        }

        // Get account metadata from AccountManager
        const accountStatus = accountManager.getStatus();
        const accountMetadataMap = new Map(
            accountStatus.accounts.map(a => [a.email, a])
        );

        // Build response data
        const responseData = {
            timestamp: new Date().toLocaleString(),
            totalAccounts: allAccounts.length,
            models: sortedModels,
            modelConfig: config.modelMapping || {},
            globalQuotaThreshold: config.globalQuotaThreshold || 0,
            accounts: accountLimits.map(acc => {
                // Merge quota data with account metadata
                const metadata = accountMetadataMap.get(acc.email) || {};
                return {
                    email: acc.email,
                    status: acc.status,
                    error: acc.error || null,
                    // Include metadata from AccountManager (WebUI needs these)
                    source: metadata.source || 'unknown',
                    enabled: metadata.enabled !== false,
                    projectId: metadata.projectId || null,
                    isInvalid: metadata.isInvalid || false,
                    invalidReason: metadata.invalidReason || null,
                    lastUsed: metadata.lastUsed || null,
                    modelRateLimits: metadata.modelRateLimits || {},
                    // Quota threshold settings
                    quotaThreshold: metadata.quotaThreshold,
                    modelQuotaThresholds: metadata.modelQuotaThresholds || {},
                    // Subscription data (new)
                    subscription: acc.subscription || metadata.subscription || { tier: 'unknown', projectId: null },
                    // Quota limits
                    limits: Object.fromEntries(
                        sortedModels.map(modelId => {
                            const quota = acc.models?.[modelId];
                            if (!quota) {
                                return [modelId, null];
                            }
                            return [modelId, {
                                remaining: quota.remainingFraction !== null
                                    ? `${Math.round(quota.remainingFraction * 100)}%`
                                    : 'N/A',
                                remainingFraction: quota.remainingFraction,
                                resetTime: quota.resetTime || null
                            }];
                        })
                    )
                };
            })
        };

        // Optionally include usage history (for dashboard performance optimization)
        if (includeHistory) {
            // responseData.history = usageStats.getHistory();
            responseData.history = {}; // Temporary placeholder
        }

        return c.json(responseData);
    } catch (error) {
        return c.json({
            status: 'error',
            error: error.message
        }, 500);
    }
});

/**
 * Force token refresh endpoint
 */
app.post('/refresh-token', async (c) => {
    try {
        await ensureInitialized();
        // Clear all caches
        accountManager.clearTokenCache();
        accountManager.clearProjectCache();
        // Force refresh default token
        const token = await forceRefresh();
        return c.json({
            status: 'ok',
            message: 'Token caches cleared and refreshed',
            tokenPrefix: token.substring(0, 10) + '...'
        });
    } catch (error) {
        return c.json({
            status: 'error',
            error: error.message
        }, 500);
    }
});

/**
 * List models endpoint (OpenAI-compatible format)
 */
app.get('/v1/models', async (c) => {
    try {
        await ensureInitialized();
        const { account } = accountManager.selectAccount();
        if (!account) {
            return c.json({
                type: 'error',
                error: {
                    type: 'api_error',
                    message: 'No accounts available'
                }
            }, 503);
        }
        const token = await accountManager.getTokenForAccount(account);
        const models = await listModels(token);
        return c.json(models);
    } catch (error) {
        logger.error('[API] Error listing models:', error);
        return c.json({
            type: 'error',
            error: {
                type: 'api_error',
                message: error.message
            }
        }, 500);
    }
});

/**
 * LiteLLM-compatible Model Info endpoint
 * GET /v1/model/info
 */
app.get('/v1/model/info', async (c) => {
    try {
        await ensureInitialized();
        const { account } = accountManager.selectAccount();
        if (!account) {
            return c.json({
                type: 'error',
                error: {
                    type: 'api_error',
                    message: 'No accounts available'
                }
            }, 503);
        }
        const token = await accountManager.getTokenForAccount(account);
        const models = await listModels(token);

        const data = models.data.map(model => ({
            model_name: model.id,
            litellm_params: {
                model: model.id
            },
            model_info: {
                id: model.id,
                db_model: true
            }
        }));

        return c.json({ data });
    } catch (error) {
        logger.error('[API] Error getting model info:', error);
        return c.json({
            type: 'error',
            error: {
                type: 'api_error',
                message: error.message
            }
        }, 500);
    }
});

/**
 * Count tokens endpoint - Anthropic Messages API compatible
 * Uses local tokenization with official tokenizers (@anthropic-ai/tokenizer for Claude, @lenml/tokenizer-gemini for Gemini)
 */
app.post('/v1/messages/count_tokens', (c) => {
    return c.json({
        type: 'error',
        error: {
            type: 'not_implemented',
            message: 'Token counting is not implemented. Use /v1/messages with max_tokens or configure your client to skip token counting.'
        }
    }, 501);
});

/**
 * Anthropic-compatible Messages API
 * POST /v1/messages
 */
app.post('/v1/messages', async (c) => {
    try {
        // Ensure account manager is initialized
        await ensureInitialized();

        const body = await c.req.json();
        const {
            model,
            messages,
            stream,
            system,
            max_tokens,
            tools,
            tool_choice,
            thinking,
            top_p,
            top_k,
            temperature
        } = body;

        // Resolve model mapping if configured
        let requestedModel = model || 'claude-3-5-sonnet-20241022';
        const modelMapping = config.modelMapping || {};
        if (modelMapping[requestedModel] && modelMapping[requestedModel].mapping) {
            const targetModel = modelMapping[requestedModel].mapping;
            logger.info(`[Server] Mapping model ${requestedModel} -> ${targetModel}`);
            requestedModel = targetModel;
        }

        const modelId = requestedModel;

        // Validate model ID before processing
        const { account: validationAccount } = accountManager.selectAccount();
        if (validationAccount) {
            const token = await accountManager.getTokenForAccount(validationAccount);
            const projectId = validationAccount.subscription?.projectId || null;
            const valid = await isValidModel(modelId, token, projectId);

            if (!valid) {
                throw new Error(`invalid_request_error: Invalid model: ${modelId}. Use /v1/models to see available models.`);
            }
        }

        // Optimistic Retry: If ALL accounts are rate-limited for this model, reset them to force a fresh check.
        // If we have some available accounts, we try them first.
        if (accountManager.isAllRateLimited(modelId)) {
            logger.warn(`[Server] All accounts rate-limited for ${modelId}. Resetting state for optimistic retry.`);
            accountManager.resetAllRateLimits();
        }

        // Validate required fields
        if (!messages || !Array.isArray(messages)) {
            return c.json({
                type: 'error',
                error: {
                    type: 'invalid_request_error',
                    message: 'messages is required and must be an array'
                }
            }, 400);
        }

        // Filter out "count" requests (often automated background checks)
        if (messages.length === 1 && messages[0].content === 'count') {
            return c.json({});
        }

        // Build the request object
        const request = {
            model: modelId,
            messages,
            max_tokens: max_tokens || 4096,
            stream,
            system,
            tools,
            tool_choice,
            thinking,
            top_p,
            top_k,
            temperature
        };

        logger.info(`[API] Request for model: ${request.model}, stream: ${!!stream}`);

        // Debug: Log message structure to diagnose tool_use/tool_result ordering
        if (logger.isDebugEnabled) {
            logger.debug('[API] Message structure:');
            messages.forEach((msg, i) => {
                const contentTypes = Array.isArray(msg.content)
                    ? msg.content.map(c => c.type || 'text').join(', ')
                    : (typeof msg.content === 'string' ? 'text' : 'unknown');
                logger.debug(`  [${i}] ${msg.role}: ${contentTypes}`);
            });
        }

        if (stream) {
            // Handle streaming response using Hono streamSSE
            return streamSSE(c, async (stream) => {
                try {
                    // Use the streaming generator with account manager
                    for await (const event of sendMessageStream(request, accountManager, FALLBACK_ENABLED)) {
                        await stream.writeSSE({
                            data: JSON.stringify(event),
                            event: event.type
                        });
                    }
                } catch (streamError) {
                    logger.error('[API] Stream error:', streamError);
                    const { errorType, errorMessage } = parseError(streamError);

                    await stream.writeSSE({
                        data: JSON.stringify({
                            type: 'error',
                            error: { type: errorType, message: errorMessage }
                        }),
                        event: 'error'
                    });
                }
            });

        } else {
            // Handle non-streaming response
            const response = await sendMessage(request, accountManager, FALLBACK_ENABLED);
            return c.json(response);
        }
    } catch (error) {
        logger.error('[API] Error:', error);

        let { errorType, statusCode, errorMessage } = parseError(error);

        // For auth errors, try to refresh token
        if (errorType === 'authentication_error') {
            logger.warn('[API] Token might be expired, attempting refresh...');
            try {
                accountManager.clearProjectCache();
                accountManager.clearTokenCache();
                await forceRefresh();
                errorMessage = 'Token was expired and has been refreshed. Please retry your request.';
            } catch (refreshError) {
                errorMessage = 'Could not refresh token. Make sure Antigravity is running.';
            }
        }

        logger.warn(`[API] Returning error response: ${statusCode} ${errorType} - ${errorMessage}`);

        return c.json({
            type: 'error',
            error: {
                type: errorType,
                message: errorMessage
            }
        }, statusCode);
    }
});

/**
 * OpenAI-compatible Chat Completions API
 * POST /v1/chat/completions
 */
app.post('/v1/chat/completions', async (c) => {
    try {
        // Ensure account manager is initialized
        await ensureInitialized();

        const body = await c.req.json();

        // Convert OpenAI request to Anthropic format
        const anthropicReq = convertOpenAIRequestToAnthropic(body);

        const {
            stream: isStream,
            model
        } = anthropicReq;

        // Resolve model mapping if configured
        let requestedModel = model || 'claude-3-5-sonnet-20241022';
        const modelMapping = config.modelMapping || {};
        if (modelMapping[requestedModel] && modelMapping[requestedModel].mapping) {
            const targetModel = modelMapping[requestedModel].mapping;
            logger.info(`[Server] Mapping model ${requestedModel} -> ${targetModel}`);
            requestedModel = targetModel;
            anthropicReq.model = targetModel; // Update model in request
        }

        const modelId = requestedModel;

        // Validate model ID before processing
        // (Similar logic to /v1/messages)
        const { account: validationAccount } = accountManager.selectAccount();
        if (validationAccount) {
            const token = await accountManager.getTokenForAccount(validationAccount);
            const projectId = validationAccount.subscription?.projectId || null;
            const valid = await isValidModel(modelId, token, projectId);

            if (!valid) {
                // OpenAI error format
                return c.json({
                    error: {
                        message: `Invalid model: ${modelId}.`,
                        type: 'invalid_request_error',
                        param: 'model',
                        code: 'model_not_found'
                    }
                }, 400);
            }
        }

        // Optimistic Retry Check
        if (accountManager.isAllRateLimited(modelId)) {
            logger.warn(`[Server] All accounts rate-limited for ${modelId}. Resetting state for optimistic retry.`);
            accountManager.resetAllRateLimits();
        }

        logger.info(`[API] OpenAI Chat Completion Request for model: ${anthropicReq.model}, stream: ${!!isStream}`);

        if (isStream) {
            // Handle streaming response using Hono stream helper
            c.header('Content-Type', 'text/event-stream');
            c.header('Cache-Control', 'no-cache');
            c.header('Connection', 'keep-alive');

            return stream(c, async (stream) => {
                try {
                    // Get Anthropic stream generator
                    const anthropicStream = sendMessageStream(anthropicReq, accountManager, FALLBACK_ENABLED);

                    // Convert and write OpenAI chunks
                    for await (const chunk of convertAnthropicStreamToOpenAI(anthropicStream, modelId)) {
                        await stream.write(chunk);
                    }
                } catch (streamError) {
                    logger.error('[API] Stream error:', streamError);
                    // Try to send error in stream if possible, or just close
                    const { errorMessage } = parseError(streamError);
                    const errorChunk = {
                        error: {
                            message: errorMessage,
                            type: 'server_error',
                            code: 'server_error'
                        }
                    };
                    await stream.write(`data: ${JSON.stringify(errorChunk)}\n\n`);
                }
            });

        } else {
            // Handle non-streaming response
            const response = await sendMessage(anthropicReq, accountManager, FALLBACK_ENABLED);
            const openAIResponse = convertAnthropicResponseToOpenAI(response);
            return c.json(openAIResponse);
        }

    } catch (error) {
        logger.error('[API] Error processing OpenAI request:', error);
        const { statusCode, errorMessage } = parseError(error);

        return c.json({
            error: {
                message: errorMessage,
                type: 'server_error', // Map properly if possible
                code: statusCode
            }
        }, statusCode);
    }
});



/**
 * Ollama-compatible Tags API (List Models)
 * GET /api/tags
 */
app.get('/api/tags', async (c) => {
    try {
        await ensureInitialized();
        const { account } = accountManager.selectAccount();
        if (!account) {
            return c.json({ error: 'No accounts available' }, 503);
        }
        const token = await accountManager.getTokenForAccount(account);
        const models = await listModels(token);

        // Map to Ollama tags format
        const tags = models.data.map(model => ({
            name: model.id,
            model: model.id,
            modified_at: new Date().toISOString(),
            size: 0,
            digest: 'unknown',
            details: {
                parent_model: '',
                format: 'gguf',
                family: 'llama',
                families: ['llama'],
                parameter_size: '7B',
                quantization_level: 'Q4_0'
            }
        }));

        return c.json({ models: tags });
    } catch (error) {
        logger.error('[API] Error listing models for Ollama:', error);
        return c.json({ error: error.message }, 500);
    }
});

/**
 * Ollama-compatible Chat API
 * POST /api/chat
 */
app.post('/api/chat', async (c) => {
    try {
        await ensureInitialized();
        const body = await c.req.json();
        const anthropicReq = convertOllamaChatRequestToAnthropic(body);

        // Resolve model mapping if configured
        let requestedModel = anthropicReq.model || 'claude-3-5-sonnet-20241022';
        const modelMapping = config.modelMapping || {};
        if (modelMapping[requestedModel] && modelMapping[requestedModel].mapping) {
            requestedModel = modelMapping[requestedModel].mapping;
            anthropicReq.model = requestedModel;
        }

        // Optimistic Retry Check
        if (accountManager.isAllRateLimited(requestedModel)) {
            logger.warn(`[Server] All accounts rate-limited for ${requestedModel}. Resetting state for optimistic retry.`);
            accountManager.resetAllRateLimits();
        }

        logger.info(`[API] Ollama Chat Request for model: ${anthropicReq.model}, stream: ${!!anthropicReq.stream}`);

        if (anthropicReq.stream) {
            c.header('Content-Type', 'application/x-ndjson');
            return stream(c, async (stream) => {
                try {
                    const anthropicStream = sendMessageStream(anthropicReq, accountManager, FALLBACK_ENABLED);
                    for await (const chunk of convertAnthropicStreamToOllamaChat(anthropicStream, requestedModel)) {
                        await stream.write(chunk);
                    }
                } catch (error) {
                    logger.error('[API] Stream error:', error);
                    const { errorMessage } = parseError(error);
                    await stream.write(JSON.stringify({ error: errorMessage, done: true }));
                }
            });
        } else {
            const response = await sendMessage(anthropicReq, accountManager, FALLBACK_ENABLED);
            const ollamaResponse = convertAnthropicResponseToOllamaChat(response, requestedModel);
            return c.json(ollamaResponse);
        }

    } catch (error) {
        logger.error('[API] Error processing Ollama chat request:', error);
        const { statusCode, errorMessage } = parseError(error);
        return c.json({ error: errorMessage }, statusCode);
    }
});

/**
 * Ollama-compatible Generate API
 * POST /api/generate
 */
app.post('/api/generate', async (c) => {
    try {
        await ensureInitialized();
        const body = await c.req.json();
        const anthropicReq = convertOllamaGenerateRequestToAnthropic(body);

        // Resolve model mapping
        let requestedModel = anthropicReq.model || 'claude-3-5-sonnet-20241022';
        const modelMapping = config.modelMapping || {};
        if (modelMapping[requestedModel] && modelMapping[requestedModel].mapping) {
            requestedModel = modelMapping[requestedModel].mapping;
            anthropicReq.model = requestedModel;
        }

        // Optimistic Retry Check
        if (accountManager.isAllRateLimited(requestedModel)) {
            logger.warn(`[Server] All accounts rate-limited for ${requestedModel}. Resetting state for optimistic retry.`);
            accountManager.resetAllRateLimits();
        }

        logger.info(`[API] Ollama Generate Request for model: ${anthropicReq.model}, stream: ${!!anthropicReq.stream}`);

        if (anthropicReq.stream) {
            c.header('Content-Type', 'application/x-ndjson');
            return stream(c, async (stream) => {
                try {
                    const anthropicStream = sendMessageStream(anthropicReq, accountManager, FALLBACK_ENABLED);
                    for await (const chunk of convertAnthropicStreamToOllamaGenerate(anthropicStream, requestedModel)) {
                        await stream.write(chunk);
                    }
                } catch (error) {
                    logger.error('[API] Stream error:', error);
                    const { errorMessage } = parseError(error);
                    await stream.write(JSON.stringify({ error: errorMessage, done: true }));
                }
            });
        } else {
            const response = await sendMessage(anthropicReq, accountManager, FALLBACK_ENABLED);
            const ollamaResponse = convertAnthropicResponseToOllamaGenerate(response, requestedModel);
            return c.json(ollamaResponse);
        }
    } catch (error) {
        logger.error('[API] Error processing Ollama generate request:', error);
        const { statusCode, errorMessage } = parseError(error);
        return c.json({ error: errorMessage }, statusCode);
    }
});


// Mount WebUI (optional web interface for account management)
mountWebUI(app, __dirname, accountManager);

/**
 * Catch-all for unsupported endpoints
 */
// usageStats.setupRoutes(app);

app.all('*', (c) => {
    // Log 404s (use originalUrl since wildcard strips req.path)
    if (logger.isDebugEnabled) {
        logger.debug(`[API] 404 Not Found: ${c.req.method} ${c.req.path}`);
    }
    return c.json({
        type: 'error',
        error: {
            type: 'not_found_error',
            message: `Endpoint ${c.req.method} ${c.req.path} not found`
        }
    }, 404);
});

export default app;