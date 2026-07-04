// ── AI Chat Sidebar ──────────────────────────────────────────────────────
(function() {
    'use strict';

    var sessionId = null;
    var isStreaming = false;

    var messagesEl = document.getElementById('aiChatMessages');
    var emptyState = document.getElementById('aiEmptyState');
    var chatForm = document.getElementById('aiChatForm');
    var chatInput = document.getElementById('aiChatInput');
    var sendBtn = document.getElementById('aiSendBtn');
    var sessionList = document.getElementById('aiSessionList');
    var newChatBtn = document.getElementById('aiNewChatBtn');

    if (!chatForm) return;

    // Auto-resize textarea
    chatInput.addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = Math.min(this.scrollHeight, 120) + 'px';
    });

    // Submit on Enter (Shift+Enter for newline)
    chatInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            chatForm.dispatchEvent(new Event('submit'));
        }
    });

    chatForm.addEventListener('submit', function(e) {
        e.preventDefault();
        var message = chatInput.value.trim();
        if (!message || isStreaming) return;
        sendMessage(message);
    });

    if (newChatBtn) {
        newChatBtn.addEventListener('click', function(e) {
            e.preventDefault();
            startNewChat();
        });
    }

    function startNewChat() {
        sessionId = null;
        messagesEl.innerHTML = '';
        if (emptyState) {
            messagesEl.appendChild(emptyState);
            emptyState.style.display = '';
        }
    }

    function escHtml(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function getPageContext() {
        return {
            page_url: window.location.pathname,
            page_type: document.body.dataset.blueprint || '',
            entity_id: document.body.dataset.entityId || null
        };
    }

    // ── Markdown-lite renderer ───────────────────────────────────────────
    function renderMarkdown(text) {
        var html = escHtml(text);
        // Code blocks
        html = html.replace(/```(\w*)\n([\s\S]*?)```/g, function(_, lang, code) {
            return '<pre class="bg-black rounded p-2 my-1" style="font-size:0.8rem;"><code>' +
                code.trim() + '</code></pre>';
        });
        // Inline code
        html = html.replace(/`([^`]+)`/g, '<code class="bg-black px-1 rounded">$1</code>');
        // Bold
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        // Italic (single *)
        html = html.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');
        // Headings (## and ###)
        html = html.replace(/^### (.+)$/gm, '<strong class="d-block mt-2">$1</strong>');
        html = html.replace(/^## (.+)$/gm, '<strong class="d-block mt-2 fs-6">$1</strong>');
        // Bullet lists
        html = html.replace(/^- (.+)$/gm, '<span class="d-block ms-2">&bull; $1</span>');
        // Line breaks
        html = html.replace(/\n\n/g, '<br><br>');
        html = html.replace(/\n/g, '<br>');
        return html;
    }

    // ── Message rendering ────────────────────────────────────────────────
    function addMessage(role, content) {
        if (emptyState) emptyState.style.display = 'none';

        var wrapper = document.createElement('div');
        wrapper.className = 'mb-3 ' + (role === 'user' ? 'text-end' : '');

        var bubble = document.createElement('div');
        bubble.className = 'd-inline-block text-start p-2 rounded ' +
            (role === 'user' ? 'bg-primary text-white' : 'bg-secondary bg-opacity-25');
        bubble.style.maxWidth = '90%';
        bubble.style.wordBreak = 'break-word';

        if (role === 'user') {
            bubble.style.whiteSpace = 'pre-wrap';
            bubble.textContent = content;
        } else {
            bubble.innerHTML = renderMarkdown(content);
        }

        wrapper.appendChild(bubble);
        messagesEl.appendChild(wrapper);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        return bubble;
    }

    function addStreamingBubble() {
        if (emptyState) emptyState.style.display = 'none';

        var wrapper = document.createElement('div');
        wrapper.className = 'mb-3';

        var bubble = document.createElement('div');
        bubble.className = 'd-inline-block text-start p-2 rounded bg-secondary bg-opacity-25';
        bubble.style.maxWidth = '90%';
        bubble.style.wordBreak = 'break-word';
        bubble.innerHTML = '<span class="text-muted"><i class="bi bi-three-dots"></i></span>';

        wrapper.appendChild(bubble);
        messagesEl.appendChild(wrapper);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        return bubble;
    }

    function addToolCall(name, input, result) {
        var wrapper = document.createElement('div');
        wrapper.className = 'mb-2 ms-2';

        var details = document.createElement('details');
        details.className = 'small';

        var summary = document.createElement('summary');
        summary.className = 'text-info';
        summary.innerHTML = '<i class="bi bi-gear-wide-connected"></i> ' + escHtml(name);
        details.appendChild(summary);

        var pre = document.createElement('pre');
        pre.className = 'small mb-0 mt-1 p-2 bg-black rounded';
        pre.style.maxHeight = '200px';
        pre.style.overflow = 'auto';
        pre.style.fontSize = '0.75rem';
        pre.style.whiteSpace = 'pre-wrap';

        var content = '';
        if (input) content += 'Input: ' + JSON.stringify(input, null, 2) + '\n\n';
        if (result) {
            try {
                content += 'Result: ' + JSON.stringify(JSON.parse(result), null, 2);
            } catch(e) {
                content += 'Result: ' + result;
            }
        }
        pre.textContent = content;
        details.appendChild(pre);
        wrapper.appendChild(details);
        messagesEl.appendChild(wrapper);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        return wrapper;
    }

    function setInputEnabled(enabled) {
        chatInput.disabled = !enabled;
        sendBtn.disabled = !enabled;
        if (enabled) {
            sendBtn.innerHTML = '<i class="bi bi-send"></i>';
        } else {
            sendBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
        }
    }

    // ── Streaming chat ───────────────────────────────────────────────────
    function sendMessage(message) {
        isStreaming = true;
        setInputEnabled(false);
        chatInput.value = '';
        chatInput.style.height = 'auto';

        addMessage('user', message);
        var assistantBubble = addStreamingBubble();
        var fullText = '';

        var body = JSON.stringify({
            message: message,
            session_id: sessionId,
            page_context: getPageContext()
        });

        fetch('/ai/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: body
        }).then(function(response) {
            if (!response.ok) {
                return response.json().then(function(err) {
                    assistantBubble.innerHTML =
                        '<span class="text-danger"><i class="bi bi-exclamation-triangle"></i> ' +
                        escHtml(err.error || 'Request failed') + '</span>';
                    throw new Error(err.error);
                });
            }

            var reader = response.body.getReader();
            var decoder = new TextDecoder();
            var buffer = '';

            function read() {
                reader.read().then(function(result) {
                    if (result.done) {
                        isStreaming = false;
                        setInputEnabled(true);
                        chatInput.focus();
                        return;
                    }

                    buffer += decoder.decode(result.value, {stream: true});
                    var lines = buffer.split('\n');
                    buffer = lines.pop();

                    for (var i = 0; i < lines.length; i++) {
                        var line = lines[i];
                        if (!line.startsWith('data: ')) continue;

                        try {
                            var event = JSON.parse(line.substring(6));

                            if (event.type === 'text') {
                                fullText += event.content;
                                assistantBubble.innerHTML = renderMarkdown(fullText);
                                messagesEl.scrollTop = messagesEl.scrollHeight;
                            } else if (event.type === 'tool_call') {
                                addToolCall(event.name, event.input, null);
                            } else if (event.type === 'tool_result') {
                                addToolCall(event.name, null, event.result);
                            } else if (event.type === 'error') {
                                assistantBubble.innerHTML = renderMarkdown(fullText) +
                                    '<div class="text-danger mt-1"><i class="bi bi-exclamation-triangle"></i> ' +
                                    escHtml(event.message) + '</div>';
                            } else if (event.type === 'done') {
                                // Stream complete
                            }
                        } catch(e) {
                            // Skip malformed events
                        }
                    }

                    read();
                });
            }
            read();

            return response;
        }).catch(function(err) {
            isStreaming = false;
            setInputEnabled(true);
            if (!fullText) {
                assistantBubble.innerHTML =
                    '<span class="text-danger"><i class="bi bi-exclamation-triangle"></i> ' +
                    escHtml(err.message || 'Connection error') + '</span>';
            }
        }).finally(function() {
            loadSessions();
        });
    }

    // ── Session management ───────────────────────────────────────────────
    function loadSessions() {
        fetch('/ai/sessions').then(function(r) { return r.json(); }).then(function(sessions) {
            // Clear existing session items (keep New Chat and divider)
            var items = sessionList.querySelectorAll('.ai-session-item');
            for (var i = 0; i < items.length; i++) items[i].remove();

            for (var j = 0; j < sessions.length; j++) {
                var s = sessions[j];
                var li = document.createElement('li');
                li.className = 'ai-session-item';

                var a = document.createElement('a');
                a.className = 'dropdown-item small d-flex justify-content-between align-items-center';
                a.href = '#';
                a.dataset.sessionId = s.id;

                var span = document.createElement('span');
                span.className = 'text-truncate';
                span.style.maxWidth = '260px';
                span.textContent = s.title || 'Untitled';

                var delBtn = document.createElement('button');
                delBtn.className = 'btn btn-sm btn-outline-danger border-0 p-0 px-1 ms-1';
                delBtn.title = 'Delete session';
                delBtn.style.fontSize = '0.7rem';
                delBtn.style.lineHeight = '1';
                delBtn.innerHTML = '<i class="bi bi-trash"></i>';
                delBtn.dataset.sessionId = s.id;
                delBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    deleteSession(parseInt(this.dataset.sessionId));
                });

                a.appendChild(span);
                a.appendChild(delBtn);
                a.addEventListener('click', function(e) {
                    e.preventDefault();
                    loadSession(parseInt(this.dataset.sessionId));
                });
                li.appendChild(a);
                sessionList.appendChild(li);
            }

            // Track latest session if we don't have one yet
            if (!sessionId && sessions.length > 0) {
                sessionId = sessions[0].id;
            }
        }).catch(function() {});
    }

    function loadSession(id) {
        fetch('/ai/sessions/' + id).then(function(r) { return r.json(); }).then(function(data) {
            if (data.error) return;
            sessionId = data.id;
            messagesEl.innerHTML = '';
            if (emptyState) emptyState.style.display = 'none';

            for (var i = 0; i < data.messages.length; i++) {
                var msg = data.messages[i];
                addMessage(msg.role, msg.content);
            }
            messagesEl.scrollTop = messagesEl.scrollHeight;
        }).catch(function() {});
    }

    function deleteSession(id) {
        fetch('/ai/sessions/' + id, { method: 'DELETE' })
            .then(function(r) {
                if (r.ok) {
                    if (sessionId === id) startNewChat();
                    loadSessions();
                }
            })
            .catch(function() {});
    }

    // Load sessions when sidebar opens
    var sidebar = document.getElementById('aiChatSidebar');
    if (sidebar) {
        sidebar.addEventListener('show.bs.offcanvas', function() {
            loadSessions();
        });
        sidebar.addEventListener('shown.bs.offcanvas', function() {
            chatInput.focus();
        });
    }
})();
