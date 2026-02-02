
import { logger } from '../utils/logger.js';
import crypto from 'crypto';

/**
 * Convert Ollama Chat Request to Anthropic Messages API Request
 * @param {Object} ollamaRequest - Ollama formatted request
 * @returns {Object} Anthropic formatted request
 */
export function convertOllamaChatRequestToAnthropic(ollamaRequest) {
    const {
        model,
        messages,
        stream,
        options,
        format, // 'json' or undefined
        keep_alive
    } = ollamaRequest;

    const anthropicRequest = {
        model: model, // Will be mapped by server
        messages: [],
        stream: !!stream
    };

    // Map options
    if (options) {
        if (options.temperature !== undefined) anthropicRequest.temperature = options.temperature;
        if (options.top_p !== undefined) anthropicRequest.top_p = options.top_p;
        if (options.top_k !== undefined) anthropicRequest.top_k = options.top_k;
        if (options.num_predict) anthropicRequest.max_tokens = options.num_predict;
    }

    // Default max_tokens
    if (!anthropicRequest.max_tokens) anthropicRequest.max_tokens = 4096;

    // Handle Messages
    for (const msg of messages || []) {
        // Skip system messages first, as we handle them separately
        if (msg.role === 'system') continue;

        const newMsg = {
            role: msg.role === 'assistant' ? 'assistant' : 'user',
            content: []
        };

        // Handle images (Ollama passes array of base64 strings)
        if (msg.images && Array.isArray(msg.images)) {
            for (const img of msg.images) {
                // Determine media type (simple heuristic or default)
                // Ollama docs just say base64 encoded.
                // We'll assume image/jpeg for now or try to sniff if it has header
                let mediaType = 'image/jpeg';
                // If the string starts with data header, stripping it might be needed, 
                // but Ollama usually sends raw base64. 

                newMsg.content.push({
                    type: 'image',
                    source: {
                        type: 'base64',
                        media_type: mediaType,
                        data: img
                    }
                });
            }
        }

        if (msg.content) {
            newMsg.content.push({ type: 'text', text: msg.content });
        }

        anthropicRequest.messages.push(newMsg);
    }

    // Handle System Prompt
    const systemMessages = (messages || []).filter(m => m.role === 'system');
    if (systemMessages.length > 0) {
        anthropicRequest.system = systemMessages.map(m => m.content).join('\n\n');
    }

    return anthropicRequest;
}

/**
 * Convert Ollama Generate Request (Prompt-based) to Anthropic Messages API Request
 * @param {Object} ollamaRequest - Ollama formatted request
 * @returns {Object} Anthropic formatted request
 */
export function convertOllamaGenerateRequestToAnthropic(ollamaRequest) {
    const {
        model,
        prompt,
        system,
        template,
        context,
        stream,
        options,
        images,
        keep_alive
    } = ollamaRequest;

    const anthropicRequest = {
        model: model,
        stream: !!stream,
        messages: []
    };

    if (options) {
        if (options.temperature !== undefined) anthropicRequest.temperature = options.temperature;
        if (options.top_p !== undefined) anthropicRequest.top_p = options.top_p;
        if (options.top_k !== undefined) anthropicRequest.top_k = options.top_k;
        if (options.num_predict) anthropicRequest.max_tokens = options.num_predict;
    }

    if (!anthropicRequest.max_tokens) anthropicRequest.max_tokens = 4096;

    if (system) {
        anthropicRequest.system = system;
    }

    const userMsg = {
        role: 'user',
        content: []
    };

    if (images && Array.isArray(images)) {
        for (const img of images) {
            userMsg.content.push({
                type: 'image',
                source: {
                    type: 'base64',
                    media_type: 'image/jpeg',
                    data: img
                }
            });
        }
    }

    if (prompt) {
        userMsg.content.push({ type: 'text', text: prompt });
    }

    anthropicRequest.messages.push(userMsg);

    return anthropicRequest;
}

/**
 * Convert Anthropic Response to Ollama Chat Response
 */
export function convertAnthropicResponseToOllamaChat(anthropicResponse, requestModel) {
    // Anthropic response: { id, type, role, content: [{type, text}], model, stop_reason, usage }

    let content = '';
    if (anthropicResponse.content) {
        content = anthropicResponse.content
            .filter(b => b.type === 'text')
            .map(b => b.text)
            .join('');
    }

    // Calculate generic durations (fake)
    // Ollama returns durations in nanoseconds
    const total_duration = 1000000000; // 1s
    const load_duration = 100000000;   // 100ms
    const prompt_eval_count = anthropicResponse.usage?.input_tokens || 0;
    const eval_count = anthropicResponse.usage?.output_tokens || 0;

    return {
        model: requestModel || anthropicResponse.model,
        created_at: new Date().toISOString(),
        message: {
            role: 'assistant',
            content: content
        },
        done: true,
        done_reason: anthropicResponse.stop_reason,
        total_duration,
        load_duration,
        prompt_eval_count,
        eval_count
    };
}

/**
 * Convert Anthropic Response to Ollama Generate Response
 */
export function convertAnthropicResponseToOllamaGenerate(anthropicResponse, requestModel) {
    let responseText = '';
    if (anthropicResponse.content) {
        responseText = anthropicResponse.content
            .filter(b => b.type === 'text')
            .map(b => b.text)
            .join('');
    }

    return {
        model: requestModel || anthropicResponse.model,
        created_at: new Date().toISOString(),
        response: responseText,
        done: true,
        done_reason: anthropicResponse.stop_reason,
        context: [], // Context not supported in this proxy
        total_duration: 1000000000,
        load_duration: 100000000,
        prompt_eval_count: anthropicResponse.usage?.input_tokens || 0,
        eval_count: anthropicResponse.usage?.output_tokens || 0
    };
}

/**
 * Convert Anthropic Stream to Ollama Chat Stream
 * Yields JSON strings
 */
export async function* convertAnthropicStreamToOllamaChat(anthropicStream, modelName) {
    for await (const event of anthropicStream) {
        if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
            yield JSON.stringify({
                model: modelName,
                created_at: new Date().toISOString(),
                message: {
                    role: 'assistant',
                    content: event.delta.text
                },
                done: false
            }) + '\n';
        } else if (event.type === 'message_stop') {
            yield JSON.stringify({
                model: modelName,
                created_at: new Date().toISOString(),
                done: true,
                total_duration: 0,
                load_duration: 0,
                prompt_eval_count: 0,
                eval_count: 0
            }) + '\n';
        }
    }
}

/**
 * Convert Anthropic Stream to Ollama Generate Stream
 * Yields JSON strings
 */
export async function* convertAnthropicStreamToOllamaGenerate(anthropicStream, modelName) {
    for await (const event of anthropicStream) {
        if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
            yield JSON.stringify({
                model: modelName,
                created_at: new Date().toISOString(),
                response: event.delta.text,
                done: false
            }) + '\n';
        } else if (event.type === 'message_stop') {
            yield JSON.stringify({
                model: modelName,
                created_at: new Date().toISOString(),
                done: true,
                total_duration: 0,
                load_duration: 0,
                prompt_eval_count: 0,
                eval_count: 0
            }) + '\n';
        }
    }
}
