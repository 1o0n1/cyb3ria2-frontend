import init, { generate_keypair_base64 } from './crypto-core/pkg/crypto_core.js';

const API_URL = 'http://localhost:3000';

// =================================================================================
// ОСНОВНАЯ ФУНКЦИЯ ЗАПУСКА
// =================================================================================
async function main() {
    await init();
    log("WASM Crypto Core Loaded.");

    const registerBtn = document.getElementById('register-btn');
    const loginBtn = document.getElementById('login-btn');

    registerBtn.addEventListener('click', handleRegister);
    loginBtn.addEventListener('click', handleLogin);

    checkAuthState();
}

// =================================================================================
// ЛОГИКА АУТЕНТИФИКАЦИИ (РЕГИСТРАЦИЯ И ВХОД) - НАДЕЖНАЯ ВЕРСИЯ
// =================================================================================
async function handleRegister() {
    const email = document.getElementById('email').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    if (!email || !username || !password) {
        log("Error: Email, username and password are required.");
        return;
    }

    log("Generating cryptographic keys...");
    const [secretKeyB64, publicKeyB64] = generate_keypair_base64();
    log("Keys generated successfully.");

    try {
        log("Sending registration request to server...");
        const response = await fetch(`${API_URL}/users`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, username, password, public_key: publicKeyB64 }),
        });

        // Надежная проверка ответа
        if (!response.ok) {
            let errorMsg = `HTTP error! status: ${response.status}`;
            try {
                const errorData = await response.json();
                errorMsg = errorData.error || errorMsg;
            } catch (e) { /* Игнорируем ошибку парсинга JSON, используем HTTP статус */ }
            throw new Error(errorMsg);
        }
        
        const result = await response.json();

        log(`Registration successful for user: ${result.username}`);
        log("Saving private key to local storage...");
        
        localStorage.setItem('userPrivateKey', secretKeyB64);
        localStorage.setItem('userPublicKey', publicKeyB64);
        
        log("Registration complete. Please log in now.");

    } catch (error) {
        log(`Error: ${error.message}`);
    }
}

async function handleLogin() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (!email || !password) {
        log("Error: Email and password are required.");
        return;
    }

    log("Sending login request to server...");

    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });

        // Аналогичная надежная проверка ответа
        if (!response.ok) {
            let errorMsg = `HTTP error! status: ${response.status}`;
            try {
                const errorData = await response.json();
                errorMsg = errorData.error || errorMsg;
            } catch (e) { /* Игнорируем */ }
            throw new Error(errorMsg);
        }

        const result = await response.json();

        log("Login successful! Token received.");
        
        localStorage.setItem('jwtToken', result.token);

        const payloadB64 = result.token.split('.')[1];
        const payloadJson = atob(payloadB64);
        const payload = JSON.parse(payloadJson);
        
        localStorage.setItem('userPublicKey', payload.pk);
        log("Public key extracted from token and saved.");

        showChatView();

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
    
    // TODO: Здесь будет логика загрузки пользователей и сообщений
}

function checkAuthState() {
    const token = localStorage.getItem('jwtToken');
    const publicKey = localStorage.getItem('userPublicKey');
    const privateKey = localStorage.getItem('userPrivateKey'); // Проверим и его, он нужен для отправки

    if (token && publicKey && privateKey) {
        log("Active session found. User is logged in.");
        showChatView();
    } else {
        log("No active session found. Please log in or register.");
        // Чистим хранилище, если чего-то не хватает для полноценной работы
        localStorage.removeItem('jwtToken');
        localStorage.removeItem('userPublicKey');
        localStorage.removeItem('userPrivateKey');
    }
}

// =================================================================================
// ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ
// =================================================================================
function log(message) {
    const logDiv = document.getElementById('log');
    logDiv.innerHTML += `> ${message}<br>`;
    logDiv.scrollTop = logDiv.scrollHeight;
}

// ================================================================================
// ЗАПУСК ПРИЛОЖЕНИЯ
// ================================================================================
main();