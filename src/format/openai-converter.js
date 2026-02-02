
import { logger } from '../utils/logger.js';
import crypto from 'crypto';

/**
 * Convert OpenAI Chat Completion Request to Anthropic Messages API Request
 * @param {Object} openAIRequest - OpenAI formatted request
 * @returns {Object} Anthropic formatted request
 */
export function convertOpenAIRequestToAnthropic(openAIRequest) {
    const {
        model,
        messages,
        max_tokens,
        stream,
        temperature,
        top_p,
        tools,
        tool_choice
    } = openAIRequest;

    const anthropicRequest = {
        model: model, // Will be mapped by server if needed
        max_tokens: max_tokens || 4096,
        stream: !!stream,
        messages: []
    };

    if (temperature !== undefined) anthropicRequest.temperature = temperature;
    if (top_p !== undefined) anthropicRequest.top_p = top_p;

    // Handle System Prompt
    // OpenAI passes system prompt as a message with role="system"
    // Anthropic expects top-level "system" parameter
    const systemMessages = messages.filter(m => m.role === 'system');
    if (systemMessages.length > 0) {
        anthropicRequest.system = systemMessages.map(m => m.content).join('\n\n');
    }

    // Handle Messages
    for (const msg of messages) {
        if (msg.role === 'system') continue; // Handled above

        const newMsg = {
            role: msg.role === 'assistant' ? 'assistant' : 'user',
            content: []
        };

        if (typeof msg.content === 'string') {
            newMsg.content.push({ type: 'text', text: msg.content });
        } else if (Array.isArray(msg.content)) {
            // Handle array content (text + image)
            for (const part of msg.content) {
                if (part.type === 'text') {
                    newMsg.content.push({ type: 'text', text: part.text });
                } else if (part.type === 'image_url') {
                    // OpenAI image format: { type: "image_url", image_url: { url: "..." } }
                    // Anthropic image format: { type: "image", source: { type: "base64", media_type: "...", data: "..." } }
                    // Note: We need to check if the URL is base64 or a real URL.
                    // If it's a real URL, this converter might struggle if the server execution context doesn't support fetching.
                    // However, llm-proxy content-converter supports urls if CloudCode supports it.
                    // For now, let's assume base64 is passed in data URL format, or we pass it through.

                    const url = part.image_url?.url || '';
                    if (url.startsWith('data:')) {
                        const match = url.match(/^data:([^;]+);base64,(.+)$/);
                        if (match) {
                            newMsg.content.push({
                                type: 'image',
                                source: {
                                    type: 'base64',
                                    media_type: match[1],
                                    data: match[2]
                                }
                            });
                        }
                    } else {
                        // Pass as URL if supported downstream, otherwise this might fail in Anthropic validation unless CloudCode adapts it.
                        // CloudCode content converter supports valid fileUri.
                        // We'll try to map it to what we think might work or just pass a text placeholder if we can't support it?
                        // Actually, let's try to assume the downstream can handle it if we format it right.
                        // But Anthropic strict API only accepts base64.
                        // For now, we only support base64 data URIs.
                        logger.warn('[OpenAI Converter] Remote image URLs might not be fully supported. Prefer base64 data URIs.');
                    }
                }
            }
        }

        // Handle Tool Calls (Assistant Message)
        if (msg.tool_calls) {
            for (const toolCall of msg.tool_calls) {
                if (toolCall.type === 'function') {
                    let input = {};
                    try {
                        input = JSON.parse(toolCall.function.arguments);
                    } catch (e) {
                        logger.warn('[OpenAI Converter] Failed to parse tool arguments', e);
                    }

                    newMsg.content.push({
                        type: 'tool_use',
                        id: toolCall.id,
                        name: toolCall.function.name,
                        input: input
                    });
                }
            }
        }

        // Handle Tool Responses (Tool Message)
        // OpenAI: role="tool", tool_call_id="...", content="..."
        // Anthropic: role="user", content=[{type: "tool_result", tool_use_id: "...", content: "..."}]
        if (msg.role === 'tool') {
            // Create a user message with tool_result
            // Note: Anthropic expects tool results to be part of a user turn.
            // If the previous message was 'user', we might need to merge, but standard conversation flow
            // usually alternates.
            // OpenAI treats 'tool' as a separate role.

            // If we encounter a 'tool' role, we treat it as a user message with tool_result content.
            // If there are multiple consecutive tool messages, they should be grouped into one user message content array
            // to match Anthropic's expectation of one user turn containing multiple results.
            // However, this loop processes one message at a time.
            // We need to group them.
            // The simple approach: convert to user message. If the pipeline merges consecutive user messages?
            // Anthropic API merges consecutive user messages? No, it forbids them.
            // SO WE MUST GROUP CONSECUTIVE TOOL MESSAGES.

            // Refactoring strategy: We need to preprocess messages to group tool outputs.
        }

        anthropicRequest.messages.push(newMsg);
    }

    // Post-processing: Merge consecutive User messages (Text and Tool Results)
    // OpenAI allows User -> Tool -> Tool -> User (mixed?) No.
    // OpenAI: User -> Assistant (calls tools) -> Tool(s) -> Assistant.
    // Anthropic: User -> Assistant (tool_use) -> User (tool_result) -> Assistant.
    // So 'Tool' messages in OpenAI effectively map to 'User' messages in Anthropic.
    // If we have User -> Tool, we technically have User -> User, which Anthropic forbids.
    // Wait, OpenAI flow for tool use:
    // 1. User: "Help me"
    // 2. Assistant: tool_calls: [id:1]
    // 3. Tool: role: tool, tool_call_id: 1, content: "result"

    // Anthropic flow:
    // 1. User: "Help me"
    // 2. Assistant: tool_use: [id:1]
    // 3. User: tool_result: [id:1, content: "result"]

    // So OpenAI 'tool' role maps directly to Anthropic 'user' role with 'tool_result' content.
    // We just need to ensure we don't have multiple User blocks if they can be merged.
    // Actually, distinct 'tool' messages in OpenAI usually correspond to distinct tool calls.
    // If OpenAI sends multiple tool outputs, they are separate messages.
    // Anthropic expects ONE user message containing ALL tool results for the preceding tool uses.

    const coalescedMessages = [];
    let currentAttributes = null;

    for (const msg of anthropicRequest.messages) {
        // If it's a tool-mapped user message (which we haven't fully distinguished yet)
        // Let's look at the original messages again.
    }
}

// Redoing the loop to handle coalescing correctly from the start
function processMessages(messages) {
    const result = [];
    let buffer = null; // Buffer for merging 'tool' messages into a single 'user' block

    for (const msg of messages) {
        if (msg.role === 'system') continue;

        if (msg.role === 'tool') {
            // It's a tool result
            const toolResultContent = {
                type: 'tool_result',
                tool_use_id: msg.tool_call_id,
                content: msg.content // Simple string content usually
            };

            // If we already have a user message buffer, append to it
            if (buffer && buffer.role === 'user') {
                buffer.content.push(toolResultContent);
            } else {
                // Start a new buffer
                // But wait, if the PREVIOUS message was 'user', we should merge with that?
                // OpenAI: Assistant -> Tool -> Tool.
                // It's unlikely to have User -> Tool immediately without Assistant in between.

                // If previous message in 'result' is user, append?
                const filePrev = result[result.length - 1];
                if (filePrev && filePrev.role === 'user') {
                    filePrev.content.push(toolResultContent);
                    buffer = filePrev;
                } else {
                    buffer = {
                        role: 'user',
                        content: [toolResultContent]
                    };
                    result.push(buffer);
                }
            }
            continue;
        }

        // Reset buffer if we hit non-tool message
        buffer = null;

        const newMsg = {
            role: msg.role === 'assistant' ? 'assistant' : 'user',
            content: []
        };

        // Normal content processing (text/image)
        if (msg.content) {
            if (typeof msg.content === 'string') {
                newMsg.content.push({ type: 'text', text: msg.content });
            } else if (Array.isArray(msg.content)) {
                for (const part of msg.content) {
                    if (part.type === 'text') {
                        newMsg.content.push({ type: 'text', text: part.text });
                    } else if (part.type === 'image_url') {
                        const url = part.image_url?.url || '';
                        // ... (image handling as before) ...
                        if (url.startsWith('data:')) {
                            const match = url.match(/^data:([^;]+);base64,(.+)$/);
                            if (match) {
                                newMsg.content.push({
                                    type: 'image',
                                    source: { type: 'base64', media_type: match[1], data: match[2] }
                                });
                            }
                        }
                    }
                }
            }
        }

        // Assistant tool calls
        if (msg.role === 'assistant' && msg.tool_calls) {
            for (const toolCall of msg.tool_calls) {
                if (toolCall.type === 'function') {
                    let input = {};
                    try {
                        input = JSON.parse(toolCall.function.arguments);
                    } catch (e) {
                        // ignore or log
                    }
                    newMsg.content.push({
                        type: 'tool_use',
                        id: toolCall.id,
                        name: toolCall.function.name,
                        input: input
                    });
                }
            }
        }

        result.push(newMsg);
    }
    return result;
}


// Updating the main function with the new logic
export function convertOpenAIRequestToAnthropic(openAIRequest) {
    const {
        model,
        messages,
        max_tokens,
        stream,
        temperature,
        top_p,
        tools,
        tool_choice
    } = openAIRequest;

    const anthropicRequest = {
        model: model,
        max_tokens: max_tokens || 4096,
        stream: !!stream,
        messages: []
    };

    if (temperature !== undefined) anthropicRequest.temperature = temperature;
    if (top_p !== undefined) anthropicRequest.top_p = top_p;

    // System Prompt
    const systemMessages = messages.filter(m => m.role === 'system');
    if (systemMessages.length > 0) {
        anthropicRequest.system = systemMessages.map(m => m.content).join('\n\n');
    }

    // Process Messages
    anthropicRequest.messages = processMessages(messages);

    // Tools
    if (tools && tools.length > 0) {
        // If tool_choice is 'none', don't send tools
        if (tool_choice !== 'none') {
            anthropicRequest.tools = tools.map(t => ({
                name: t.function.name,
                description: t.function.description,
                input_schema: t.function.parameters
            }));
        }

        // Tool Choice
        if (tool_choice) {
            if (typeof tool_choice === 'string') {
                if (tool_choice === 'auto') {
                    anthropicRequest.tool_choice = { type: 'auto' };
                } else if (tool_choice === 'required') {
                    anthropicRequest.tool_choice = { type: 'any' };
                }
            } else if (typeof tool_choice === 'object' && tool_choice.type === 'function') {
                anthropicRequest.tool_choice = {
                    type: 'tool',
                    name: tool_choice.function.name
                };
            }
        }
    }

    return anthropicRequest;
}

/**
 * Convert Anthropic Response to OpenAI Chat Completion Response
 */
export function convertAnthropicResponseToOpenAI(anthropicResponse) {
    const timestamp = Math.floor(Date.now() / 1000);
    const model = anthropicResponse.model || 'model'; // Should come from response

    // Calculate usage if available
    const usage = {
        prompt_tokens: anthropicResponse.usage?.input_tokens || 0,
        completion_tokens: anthropicResponse.usage?.output_tokens || 0,
        total_tokens: (anthropicResponse.usage?.input_tokens || 0) + (anthropicResponse.usage?.output_tokens || 0)
    };

    const choices = [];

    // Determine finish reason
    let finish_reason = 'stop';
    if (anthropicResponse.stop_reason === 'tool_use') finish_reason = 'tool_calls';
    if (anthropicResponse.stop_reason === 'max_tokens') finish_reason = 'length';
    if (!anthropicResponse.stop_reason) finish_reason = 'stop'; // default

    const message = {
        role: 'assistant',
        content: null
    };

    // Parse content
    const contentBlocks = anthropicResponse.content || [];
    const textBlocks = contentBlocks.filter(b => b.type === 'text');
    const toolUseBlocks = contentBlocks.filter(b => b.type === 'tool_use');

    if (textBlocks.length > 0) {
        message.content = textBlocks.map(b => b.text).join('');
    }

    if (toolUseBlocks.length > 0) {
        message.tool_calls = toolUseBlocks.map(b => ({
            id: b.id,
            type: 'function',
            function: {
                name: b.name,
                arguments: JSON.stringify(b.input)
            }
        }));
    }

    choices.push({
        index: 0,
        message: message,
        finish_reason: finish_reason
    });

    return {
        id: anthropicResponse.id || `chatcmpl-${crypto.randomUUID()}`,
        object: 'chat.completion',
        created: timestamp,
        model: model,
        choices: choices,
        usage: usage
    };
}

/**
 * Convert Anthropic Stream to OpenAI Stream
 * Yields strings like 'data: {...}\n\n'
 */
export async function* convertAnthropicStreamToOpenAI(anthropicStream, modelName) {
    const id = `chatcmpl-${crypto.randomUUID()}`;
    const timestamp = Math.floor(Date.now() / 1000);

    // Send initial chunk
    yield createStreamChunk(id, timestamp, modelName, { role: 'assistant', content: '' }, null);

    for await (const event of anthropicStream) {
        if (event.type === 'content_block_start') {
            if (event.content_block.type === 'tool_use') {
                // Start a tool call
                const toolCallChunk = {
                    tool_calls: [{
                        index: event.index,
                        id: event.content_block.id,
                        type: 'function',
                        function: {
                            name: event.content_block.name,
                            arguments: ''
                        }
                    }]
                };
                yield createStreamChunk(id, timestamp, modelName, toolCallChunk, null);
            }
        } else if (event.type === 'content_block_delta') {
            if (event.delta.type === 'text_delta') {
                yield createStreamChunk(id, timestamp, modelName, { content: event.delta.text }, null);
            } else if (event.delta.type === 'input_json_delta') {
                const toolCallChunk = {
                    tool_calls: [{
                        index: event.index,
                        function: {
                            arguments: event.delta.partial_json
                        }
                    }]
                };
                yield createStreamChunk(id, timestamp, modelName, toolCallChunk, null);
            }
        } else if (event.type === 'message_stop') {
            yield createStreamChunk(id, timestamp, modelName, {}, 'stop');
        } else if (event.type === 'message_delta') {
            // Updated usage, stop_reason, etc.
            if (event.delta && event.delta.stop_reason) {
                let finish_reason = 'stop';
                if (event.delta.stop_reason === 'tool_use') finish_reason = 'tool_calls';
                if (event.delta.stop_reason === 'max_tokens') finish_reason = 'length';
                yield createStreamChunk(id, timestamp, modelName, {}, finish_reason);
            }
        }
    }

    yield 'data: [DONE]\n\n';
}

function createStreamChunk(id, created, model, delta, finish_reason) {
    const chunk = {
        id: id,
        object: 'chat.completion.chunk',
        created: created,
        model: model,
        choices: [{
            index: 0,
            delta: delta,
            finish_reason: finish_reason
        }]
    };
    return `data: ${JSON.stringify(chunk)}\n\n`;
}

// Helper to process messages (reuse logic if needed or ensure it's cleaner)
// Defined inside the module scope at the top of this code block for now.
