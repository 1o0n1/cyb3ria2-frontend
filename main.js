import init, { generate_keypair_base64, encrypt, decrypt } from './crypto-core/pkg/crypto_core.js';

const API_URL = 'http://localhost:3000';
let currentChatPartner = null; // Глобальная переменная для хранения инфо о собеседнике

// =================================================================================
// ОСНОВНАЯ ФУНКЦИЯ ЗАПУСКА
// =================================================================================
async function main() {
    await init();
    log("WASM Crypto Core Loaded.");

    document.getElementById('register-btn').addEventListener('click', handleRegister);
    document.getElementById('login-btn').addEventListener('click', handleLogin);
    document.getElementById('send-btn').addEventListener('click', handleSendMessage);

    checkAuthState();
}

// =================================================================================
// ЛОГИКА АУТЕНТИФИКАЦИИ
// =================================================================================
async function handleRegister() {
    // ... этот код у тебя уже верный, оставляем без изменений ...
    const email = document.getElementById('email').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    if (!email || !username || !password) return log("Error: All fields are required.");

    log("Generating cryptographic keys...");
    const [secretKeyB64, publicKeyB64] = generate_keypair_base64();
    log("Keys generated successfully.");

    try {
        log("Sending registration request...");
        const response = await fetch(`${API_URL}/users`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, username, password, public_key: publicKeyB64 }),
        });
        if (!response.ok) throw new Error((await response.json()).error || 'Registration failed');
        
        const result = await response.json();
        log(`Registration successful for ${result.username}`);
        
        // Сохраняем ВСЕ ключи. Это единственный момент, когда сохраняется приватный ключ.
        localStorage.setItem('userPrivateKey', secretKeyB64);
        localStorage.setItem('userPublicKey', publicKeyB64);
        
        log("Registration complete. Please log in now.");
    } catch (error) {
        log(`Error: ${error.message}`);
    }
}

async function handleLogin() {
    // ... этот код у тебя тоже верный, оставляем ...
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
        
        // 1. Сохраняем токен
        localStorage.setItem('jwtToken', result.token);
        
        // 2. Декодируем токен и сохраняем public key
        const payloadB64 = result.token.split('.')[1];
        const payload = JSON.parse(atob(payloadB64));
        localStorage.setItem('userPublicKey', payload.pk);
        log("Public key extracted from token and saved.");

        // 3. Теперь, когда все нужные части сохранены, перепроверяем состояние
        checkAuthState();
    } catch (error) {
        log(`Error: ${error.message}`);
    }
}

// =================================================================================
// УПРАВЛЕНИЕ ИНТЕРФЕЙСОМ И СОСТОЯНИЕМ
// =================================================================================
function showChatView() {
    document.getElementById('auth-view').style.display = 'none';
    document.getElementById('chat-view').style.display = 'block';
    log("Switched to chat view.");

    // ПРОВЕРКА НА ВОЗМОЖНОСТЬ ШИФРОВАНИЯ
    const privateKey = localStorage.getItem('userPrivateKey');
    if (privateKey) {
        log("Private key found. Encryption is available.");
        // Если ключ есть, загружаем пользователей для чата
        loadUsers();
    } else {
        log("Warning: Private key not found. You can receive messages, but cannot send.");
        // Если ключа нет, можно, например, заблокировать поле ввода
        document.getElementById('message-input').disabled = true;
        document.getElementById('send-btn').disabled = true;
    }
}

// --- ФИНАЛЬНАЯ, ПРАВИЛЬНАЯ ВЕРСИЯ ---
function checkAuthState() {
    const token = localStorage.getItem('jwtToken');
    const publicKey = localStorage.getItem('userPublicKey');
    
    // ГЛАВНОЕ ИЗМЕНЕНИЕ: Сессия активна, если есть ТОКЕН и ПУБЛИЧНЫЙ КЛЮЧ.
    if (token && publicKey) {
        log("Active session found. User is logged in.");
        showChatView();
    } else {
        log("No active session found. Please log in.");
        // Показываем форму входа, если чего-то не хватает
        document.getElementById('auth-view').style.display = 'block';
        document.getElementById('chat-view').style.display = 'none';
    }
}

// =================================================================================
// ЛОГИКА ЧАТА
// =================================================================================
async function loadUsers() {
    log("Loading user list...");
    const token = localStorage.getItem('jwtToken');
    if (!token) return log("Error: Not authenticated.");

    try {
        const response = await fetch(`${API_URL}/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) throw new Error("Failed to fetch users");
        
        const users = await response.json();
        const userListDiv = document.getElementById('user-list');
        userListDiv.innerHTML = '<h3>Contacts</h3>';

        const myId = JSON.parse(atob(token.split('.')[1])).sub;
        users.forEach(user => {
            if (user.id === myId || !user.public_key) return; // Не показываем себя и юзеров без ключа
            
            const userElement = document.createElement('div');
            userElement.innerText = `> ${user.username}`;
            userElement.style.cursor = 'pointer';
            userElement.dataset.userId = user.id;
            userElement.dataset.publicKey = user.public_key;
            userElement.dataset.username = user.username; // Сохраняем имя для заголовка
            
            userElement.addEventListener('click', () => selectChatPartner(userElement));
            userListDiv.appendChild(userElement);
        });
        log("User list loaded.");
    } catch (error) {
        log(`Error: ${error.message}`);
    }
}

// --- ОБНОВЛЕННАЯ ФУНКЦИЯ ---
function selectChatPartner(userElement) {
    currentChatPartner = {
        id: userElement.dataset.userId,
        publicKey: userElement.dataset.publicKey,
        username: userElement.dataset.username,
    };
    document.getElementById('current-chat-user').innerText = currentChatPartner.username;
    const messageList = document.getElementById('message-list');
    messageList.innerHTML = '<em>Loading conversation...</em>'; // Показываем загрузку
    log(`Selected chat with ${currentChatPartner.username}.`);
    
    // СРАЗУ ЗАГРУЖАЕМ ИСТОРИЮ ПЕРЕПИСКИ
    loadConversation(currentChatPartner);
}

async function handleSendMessage() {
    const messageText = document.getElementById('message-input').value;
    if (!messageText.trim()) return;
    if (!currentChatPartner) return log("Error: No chat partner selected.");

    log("Encrypting message with WASM...");
    const myPrivateKey = localStorage.getItem('userPrivateKey');
    const theirPublicKey = currentChatPartner.publicKey;
    const token = localStorage.getItem('jwtToken');

    if (!myPrivateKey) return log("CRITICAL ERROR: Private key is missing. Cannot send message.");

    try {
        // 1. Вызываем WASM для шифрования
        const encryptedMessageB64 = encrypt(myPrivateKey, theirPublicKey, messageText);
        log("Message encrypted successfully.");

        // 2. Отправляем зашифрованное сообщение на бэкенд
        const response = await fetch(`${API_URL}/messages`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                recipient_id: currentChatPartner.id,
                content: encryptedMessageB64
            })
        });

        if (!response.ok) throw new Error((await response.json()).error || 'Failed to send message');

        const sentMessage = await response.json();
        log(`Message sent successfully. ID: ${sentMessage.id}`);
        
        document.getElementById('message-input').value = ''; // Очищаем поле ввода
        
        // Отображаем наше собственное сообщение сразу
        const messageList = document.getElementById('message-list');
        const msgDiv = document.createElement('div');
        msgDiv.innerHTML = `<b>You:</b> ${messageText}`;
        messageList.appendChild(msgDiv);
        messageList.scrollTop = messageList.scrollHeight;

    } catch (e) {
        log(`Error: ${e}`);
    }
}

// --- НОВАЯ ФУНКЦИЯ ---
async function loadConversation(partner) {
    const token = localStorage.getItem('jwtToken');
    const myPrivateKey = localStorage.getItem('userPrivateKey');
    const theirPublicKey = partner.publicKey;

    try {
        const response = await fetch(`${API_URL}/messages/${partner.id}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) throw new Error("Failed to load conversation");

        const encryptedMessages = await response.json();
        const messageList = document.getElementById('message-list');
        messageList.innerHTML = ''; // Очищаем "Loading..."

        if (encryptedMessages.length === 0) {
            messageList.innerHTML = '<em>No messages yet.</em>';
            return;
        }

        const myId = JSON.parse(atob(token.split('.')[1])).sub;

        for (const msg of encryptedMessages) {
            try {
                // Расшифровываем сообщение с помощью WASM
                const decryptedText = decrypt(myPrivateKey, theirPublicKey, msg.content);
                // Отображаем
                displayMessage(decryptedText, msg.user_id === myId);
            } catch (e) {
                displayMessage("<em>[Could not decrypt this message]</em>", msg.user_id === myId);
            }
        }
    } catch (error) {
        log(`Error: ${error.message}`);
    }
}

// --- НОВАЯ ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ---
function displayMessage(text, isMine) {
    const messageList = document.getElementById('message-list');
    const msgDiv = document.createElement('div');
    
    // Добавляем префикс, чтобы было понятно, кто автор
    const prefix = isMine ? 'You:' : `${currentChatPartner.username}:`;
    msgDiv.innerHTML = `<b>${prefix}</b> ${text}`;
    
    // Выравниваем свои сообщения справа
    if (isMine) {
        msgDiv.style.textAlign = 'right';
    }

    messageList.appendChild(msgDiv);
    messageList.scrollTop = messageList.scrollHeight; // Авто-прокрутка вниз
}

main();