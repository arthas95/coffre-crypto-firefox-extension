let backgroundPrivateKey = null;
let backgroundUnlockedAt = null;
let backgroundLockTimer = null;

const DUREE_UNLOCK = 60 * 60 * 1000; // 1 heure

function verrouillerBackground() {
    backgroundPrivateKey = null;
    backgroundUnlockedAt = null;

    if (backgroundLockTimer) {
        clearTimeout(backgroundLockTimer);
        backgroundLockTimer = null;
    }
}

function garderClePriveeDansBackground(privateKey) {
    backgroundPrivateKey = privateKey;
    backgroundUnlockedAt = Date.now();

    if (backgroundLockTimer) {
        clearTimeout(backgroundLockTimer);
    }

    backgroundLockTimer = setTimeout(() => {
        verrouillerBackground();
    }, DUREE_UNLOCK);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

browser.runtime.onMessage.addListener((message) => {
    if (message.type === "UNLOCK_PRIVATE_KEY") {
        return importerEtGarderClePrivee(message.privateKeyJwk);
    }

    if (message.type === "LOCK_PRIVATE_KEY") {
        verrouillerBackground();

        return Promise.resolve({
            ok: true,
            message: "Coffre verrouillé."
        });
    }

    if (message.type === "GET_UNLOCK_STATUS") {
        return Promise.resolve({
            ok: true,
            unlocked: backgroundPrivateKey !== null,
            unlockedAt: backgroundUnlockedAt
        });
    }

    if (message.type === "DECRYPT_MESSAGE") {
        return dechiffrerMessageDansBackground(message.messageBase64);
    }

    return Promise.resolve({
        ok: false,
        error: "Type de message inconnu."
    });
});

async function importerEtGarderClePrivee(privateKeyJwk) {
    try {
        if (!privateKeyJwk) {
            return {
                ok: false,
                error: "Aucune clé privée reçue."
            };
        }

        const privateKey = await crypto.subtle.importKey(
            "jwk",
            privateKeyJwk,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            false,
            ["decrypt"]
        );

        garderClePriveeDansBackground(privateKey);

        return {
            ok: true,
            message: "Coffre déverrouillé pendant 1 heure."
        };

    } catch (error) {
        return {
            ok: false,
            error: "Impossible d'importer la clé privée dans le background."
        };
    }
}

async function dechiffrerMessageDansBackground(messageBase64) {
    try {
        if (backgroundPrivateKey == null) {
            return {
                ok: false,
                error: "Coffre verrouillé. Déverrouillez votre coffre avec le mot de passe maître."
            };
        }

        if (!messageBase64) {
            return {
                ok: false,
                error: "Aucun message chiffré fourni."
            };
        }

        const messageBuffer = base64ToArrayBuffer(messageBase64);

        const messageDechiffreBytes = await crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            backgroundPrivateKey,
            messageBuffer
        );

        const decoder = new TextDecoder();
        const messageDechiffre = decoder.decode(messageDechiffreBytes);

        return {
            ok: true,
            message: messageDechiffre
        };

    } catch (error) {
        return {
            ok: false,
            error: "Impossible de déchiffrer ce message. Il n'a peut-être pas été chiffré avec votre clé publique actuelle."
        };
    }
}