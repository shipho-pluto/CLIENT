document.addEventListener('DOMContentLoaded', function() {
    const messageForm = document.getElementById('message-form');
    const messagesContainer = document.getElementById('messages');
    const messageInput = document.getElementById('message-content');
    const messageTypeSelect = document.getElementById('message-type');
    const currentUserId = 9; // Пример ID пользователя

    loadMessages();

    async function loadMessages() {
        try {
            showLoading(true);
            const response = await fetch('/api/messages');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

            const data = await response.json();
            messagesContainer.innerHTML = '';

            data.messages.forEach(msg => {
                addMessageToUI({
                    id: msg.id,
                    content: msg.content,
                    type: msg.type,
                    userId: msg.uid,
                    timestamp: msg.datetime,
                });
            });
        } catch (error) {
            showError(error.message);
        } finally {
            showLoading(false);
        }
    }

    messageForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const messageType = messageTypeSelect.value;
        const content = messageInput.value.trim();

        if (!validateInput(messageType, content)) return;

        try {
            showLoading(true);
            const response = await fetch('/api/messages', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    'type': messageType,
                    'message-content': content,
                })
            });

            if (!response.ok) throw new Error(await response.text());

            const result = await response.json();

            addMessageToUI({
                id: result.message_id,
                content: content,
                type: messageType,
                userId: currentUserId,
                timestamp: result.datetime
            });

            messageInput.value = '';
        } catch (error) {
            showError(error.message);
        } finally {
            showLoading(false);
        }
    });

    function addMessageToUI(message) {
        const isMyMessage = message.userId === currentUserId;
        const messageElement = document.createElement('div');

        messageElement.className = `message ${isMyMessage ? 'sent' : 'received'}`;
        messageElement.innerHTML = `
            <div class="message-header">
                <span class="message-type">${message.type}</span>
                <span class="message-time">${message.timestamp}</span>
            </div>
            <div class="message-content">${message.content}</div>
        `;

        messagesContainer.appendChild(messageElement);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    function validateInput(type, content) {
        if (!content.trim()) {
            showError('Message content cannot be empty!');
            return false;
        }
        if (!type) {
            showError('Please select a message type!');
            return false;
        }
        return true;
    }

    function showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        messagesContainer.prepend(errorDiv);
        setTimeout(() => errorDiv.remove(), 3000);
    }

    function showLoading(isLoading) {
        const button = messageForm.querySelector('button');
        button.disabled = isLoading;
        button.innerHTML = isLoading
            ? '<div class="spinner"></div> Sending...'
            : 'Send Message';
    }
});