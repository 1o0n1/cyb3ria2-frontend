import init, { generate_keypair_base64, encrypt, decrypt, encrypt_with_password, decrypt_with_password } from './pkg/crypto_core.js';

const API_URL = `${window.location.origin}/api`;
let currentChatPartner = null;
let webSocket = null;
let unreadCounts = {};

async function main() {
    await init();
    log("WASM Crypto Core Loaded.");

    document.getElementById('register-btn').addEventListener('click', handleRegister);
    document.getElementById('login-btn').addEventListener('click', handleLogin);
    document.getElementById('send-btn').addEventListener('click', handleSendMessage);
    document.getElementById('logout-btn').addEventListener('click', handleLogout); // Эта строка ищет функцию handleLogout

    loadUnreadCounts();
    checkAuthState();
}

function loadUnreadCounts() {
    const storedCounts = localStorage.getItem('unreadCounts');
    unreadCounts = storedCounts ? JSON.parse(storedCounts) : {};
    log("Unread message counts loaded.");
}

function saveUnreadCounts() {
    localStorage.setItem('unreadCounts', JSON.stringify(unreadCounts));
}

function updateUserListNotifications() {
    const userElements = document.querySelectorAll('.contact-item');
    userElements.forEach(el => {
        const userId = el.dataset.userId;
        const count = unreadCounts[userId] || 0;
        const badge = el.querySelector(`#notify-${userId}`);
        if (badge) {
            badge.innerText = count > 0 ? `[+${count}]` : '';
        }
    });
}

// --- ИСПРАВЛЕНИЕ: ВОТ НЕДОСТАЮЩАЯ ФУНКЦИЯ ---
function handleLogout() {
    log("Logging out...");
    if (webSocket) {
        webSocket.onclose = null; // Отключаем авто-реконнект
        webSocket.close();
        webSocket = null;
    }
    // Очищаем ВСЕ данные сессии
    localStorage.removeItem('jwtToken');
    localStorage.removeItem('userPublicKey');
    localStorage.removeItem('userPrivateKey');
    localStorage.removeItem('username');
    localStorage.removeItem('unreadCounts'); 

    // Переключаем интерфейс
    document.getElementById('auth-view').style.display = 'block';
    document.getElementById('chat-view').style.display = 'none';
    
    // Безопасно очищаем имя пользователя
    const userNameEl = document.getElementById('current-user-name');
    if (userNameEl) {
        userNameEl.innerText = '';
    }
    
    document.getElementById('log').innerHTML = '> Logged out successfully.<br>';
}
// --- КОНЕЦ ИСПРАВЛЕНИЯ ---


function handleIncomingMessage(message) {
    log(`WebSocket message received.`);
    const myId = JSON.parse(atob(localStorage.getItem('jwtToken').split('.')[1])).sub;
    const isMyOwnMessage = message.user_id === myId;
    const partnerIdForChat = isMyOwnMessage ? message.recipient_id : message.user_id;

    if (currentChatPartner && partnerIdForChat === currentChatPartner.id) {
        const myPrivateKey = localStorage.getItem('userPrivateKey');
        const theirPublicKey = currentChatPartner.publicKey;
        try {
            const decryptedText = decrypt(myPrivateKey, theirPublicKey, message.content);
            displayMessage(decryptedText, isMyOwnMessage);
        } catch (e) {
            displayMessage("<em>[Could not decrypt incoming message]</em>", isMyOwnMessage);
        }
    } else if (!isMyOwnMessage) {
        const senderId = message.user_id;
        unreadCounts[senderId] = (unreadCounts[senderId] || 0) + 1;
        saveUnreadCounts();
        updateUserListNotifications();
        log(`Unread count for user ${senderId} is now ${unreadCounts[senderId]}.`);
    }
}

async function loadUsers() {
    log("Loading user list...");
    const token = localStorage.getItem('jwtToken');
    if (!token) return log("Error: Not authenticated.");

    try {
        const response = await fetch(`${API_URL}/users`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (!response.ok) throw new Error("Failed to fetch users");
        
        const users = await response.json();
        const userListDiv = document.getElementById('user-list');
        userListDiv.innerHTML = '<h3>Contacts</h3>';

        const myId = JSON.parse(atob(token.split('.')[1])).sub;
        users.forEach(user => {
            if (user.id === myId || !user.public_key) return;
            
            const userElement = document.createElement('div');
            userElement.className = 'contact-item';
            userElement.innerHTML = `> ${user.username}<span class="notification-badge" id="notify-${user.id}"></span>`;
            
            userElement.style.cursor = 'pointer';
            userElement.dataset.userId = user.id;
            userElement.dataset.publicKey = user.public_key;
            userElement.dataset.username = user.username;
            
            userElement.addEventListener('click', () => selectChatPartner(userElement));
            userListDiv.appendChild(userElement);
        });

        updateUserListNotifications();
        log("User list loaded.");
    } catch (error) {
        log(`Error: ${error.message}`);
    }
}

function selectChatPartner(userElement) {
    const partnerId = userElement.dataset.userId;

    if (unreadCounts[partnerId] > 0) {
        log(`Resetting notification count for user ${partnerId}.`);
        unreadCounts[partnerId] = 0;
        saveUnreadCounts();
        updateUserListNotifications();
    }

    currentChatPartner = {
        id: userElement.dataset.userId,
        publicKey: userElement.dataset.publicKey,
        username: userElement.dataset.username,
    };
    document.getElementById('current-chat-user').innerText = currentChatPartner.username;
    document.getElementById('message-list').innerHTML = '<em>Loading conversation...</em>';
    log(`Selected chat with ${currentChatPartner.username}.`);
    loadConversation(currentChatPartner);
}

function updateUserInfo() {
    const username = localStorage.getItem('username');
    if (username) { document.getElementById('current-user-name').innerText = username; }
}

async function handleRegister() {
    const email = document.getElementById('email').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    if (!email || !username || !password) return log("Error: All fields are required.");
    log("Generating cryptographic keys...");
    const [secretKeyB64, publicKeyB64] = generate_keypair_base64();
    log("Keys generated successfully.");
    try {
        log("Encrypting private key with your password for secure storage...");
        const encryptedPrivateKey = encrypt_with_password(password, secretKeyB64);
        log("Private key encrypted.");
        const response = await fetch(`${API_URL}/users`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, username, password, public_key: publicKeyB64, encrypted_private_key: encryptedPrivateKey }),
        });
        if (!response.ok) throw new Error((await response.json()).error || 'Registration failed');
        const result = await response.json();
        log(`Registration successful for ${result.username}. Please log in now.`);
    } catch (error) {
        log(`Error: ${error.message}`);
    }
}

async function handleLogin() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    if (!email || !password) return log("Error: Email and password are required.");
    log("Sending login request...");
    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        if (!response.ok) throw new Error((await response.json()).error || 'Login failed');
        const result = await response.json();
        log("Login successful! Token received.");
        localStorage.setItem('jwtToken', result.token);
        const payload = JSON.parse(atob(result.token.split('.')[1]));
        localStorage.setItem('userPublicKey', payload.pk);
        localStorage.setItem('username', payload.username);
        log(`Username '${payload.username}' saved to session.`);
        if (result.encrypted_private_key) {
            log("Encrypted private key received. Decrypting...");
            try {
                const privateKey = decrypt_with_password(password, result.encrypted_private_key);
                localStorage.setItem('userPrivateKey', privateKey);
                log("Private key decrypted and saved to session.");
            } catch (e) {
                log("CRITICAL ERROR: Failed to decrypt private key. Check password.");
            }
        } else {
            log("Warning: No private key found for your account.");
        }
        checkAuthState();
    } catch (error) {
        log(`Error: ${error.message}`);
    }
}

function showChatView() {
    document.getElementById('auth-view').style.display = 'none';
    document.getElementById('chat-view').style.display = 'block';
    log("Switched to chat view.");
    const privateKey = localStorage.getItem('userPrivateKey');
    if (privateKey) {
        log("Private key found. Encryption is available.");
        document.getElementById('message-input').disabled = false;
        document.getElementById('send-btn').disabled = false;
        loadUsers();
    } else {
        log("Warning: Private key not found. You can receive messages, but cannot send.");
        document.getElementById('message-input').disabled = true;
        document.getElementById('send-btn').disabled = true;
    }
}

function checkAuthState() {
    const token = localStorage.getItem('jwtToken');
    const publicKey = localStorage.getItem('userPublicKey');
    if (token && publicKey) {
        log("Active session found. User is logged in.");
        updateUserInfo();
        showChatView();
        connectWebSocket();
    } else {
        log("No active session found. Please log in.");
        document.getElementById('auth-view').style.display = 'block';
        document.getElementById('chat-view').style.display = 'none';
    }
}

function connectWebSocket() {
    if (webSocket && webSocket.readyState === WebSocket.OPEN) return;
    const token = localStorage.getItem('jwtToken');
    if (!token) return;
    const wsUrl = API_URL.replace(/^http/, 'ws') + `/ws?token=${token}`;
    webSocket = new WebSocket(wsUrl);
    webSocket.onopen = () => log("WebSocket connection established.");
    webSocket.onmessage = (event) => handleIncomingMessage(JSON.parse(event.data));
    webSocket.onclose = () => {
        log("WebSocket connection closed. Reconnecting in 5s...");
        webSocket = null;
        setTimeout(connectWebSocket, 5000);
    };
    webSocket.onerror = (error) => log(`WebSocket error: ${error.message || 'Unknown error'}`);
}

async function handleSendMessage() {
    const messageText = document.getElementById('message-input').value;
    if (!messageText.trim() || !currentChatPartner) return;
    const myPrivateKey = localStorage.getItem('userPrivateKey');
    const theirPublicKey = currentChatPartner.publicKey;
    const token = localStorage.getItem('jwtToken');
    if (!myPrivateKey) return log("CRITICAL ERROR: Private key is missing.");
    try {
        const encryptedMessageB64 = encrypt(myPrivateKey, theirPublicKey, messageText);
        const response = await fetch(`${API_URL}/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ recipient_id: currentChatPartner.id, content: encryptedMessageB64 })
        });
        if (!response.ok) throw new Error((await response.json()).error || 'Failed to send');
        log(`Message sent successfully.`);
        document.getElementById('message-input').value = '';
    } catch (e) {
        log(`Error: ${e}`);
    }
}

function displayMessage(text, isMine) {
    const messageList = document.getElementById('message-list');
    if (messageList.innerHTML.includes('<em>')) {
        messageList.innerHTML = '';
    }
    const msgDiv = document.createElement('div');
    const prefix = isMine ? 'You:' : `${currentChatPartner.username}:`;
    const safeText = text.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    msgDiv.innerHTML = `<b>${prefix}</b> ${safeText}`;
    if (isMine) msgDiv.style.textAlign = 'right';
    messageList.appendChild(msgDiv);
    messageList.scrollTop = messageList.scrollHeight;
}

async function loadConversation(partner) {
    log(`Loading messages with ${partner.username}...`);
    const token = localStorage.getItem('jwtToken');
    const myPrivateKey = localStorage.getItem('userPrivateKey');
    const theirPublicKey = partner.publicKey;
    try {
        const response = await fetch(`${API_URL}/messages/${partner.id}`, { headers: { 'Authorization': `Bearer ${token}` } });
        if (!response.ok) throw new Error("Failed to load conversation");
        const encryptedMessages = await response.json();
        const messageList = document.getElementById('message-list');
        messageList.innerHTML = encryptedMessages.length === 0 ? '<em>No messages yet.</em>' : '';
        const myId = JSON.parse(atob(token.split('.')[1])).sub;
        for (const msg of encryptedMessages) {
            try {
                const decryptedText = decrypt(myPrivateKey, theirPublicKey, msg.content);
                displayMessage(decryptedText, msg.user_id === myId);
            } catch (e) {
                displayMessage("<em>[Could not decrypt this message]</em>", msg.user_id === myId);
            }
        }
        log("Conversation loaded.");
    } catch (error) {
        log(`Error: ${error.message}`);
    }
}

function log(message) {
    const logDiv = document.getElementById('log');
    logDiv.innerHTML += `> ${message}<br>`;
    logDiv.scrollTop = logDiv.scrollHeight;
}

main();