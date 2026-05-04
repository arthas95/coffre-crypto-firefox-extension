console.log("Coffre Crypto : content script WhatsApp chargé");

let isEncrypting = false;

// =======================================================
// OUTILS GÉNÉRAUX
// =======================================================

function attendre(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary);
}

function nettoyerMessageChiffreRSA(texte) {
    if (!texte) {
        return "";
    }

    let message = texte
        .replace(/\s+/g, "")
        .replace(/[\u200B-\u200D\uFEFF]/g, "")
        .trim();

    // RSA 4096 = 512 octets = 684 caractères Base64.
    if (message.length > 684) {
        message = message.slice(-684);
    }

    return message;
}

// =======================================================
// TÉMOIN VISUEL
// =======================================================

function afficherTemoinChargement() {
    if (document.getElementById("coffre-crypto-loaded")) {
        return;
    }

    const badge = document.createElement("div");
    badge.id = "coffre-crypto-loaded";
    badge.textContent = "Coffre Crypto actif";

    document.body.appendChild(badge);
}

// =======================================================
// DÉCHIFFRER LES MESSAGES REÇUS
// =======================================================

function trouverMessagesRecus() {
    return document.querySelectorAll(".message-in");
}

function extraireTexteMessage(messageElement) {
    const texteElements = messageElement.querySelectorAll(
        'span[data-testid="selectable-text"]'
    );

    if (!texteElements || texteElements.length === 0) {
        return null;
    }

    let texteFinal = "";

    texteElements.forEach(element => {
        texteFinal += element.innerText + "\n";
    });

    texteFinal = texteFinal.trim();

    if (!texteFinal) {
        return null;
    }

    return texteFinal;
}

function trouverZoneInsertion(messageElement) {
    const container = messageElement.querySelector('[data-testid="msg-container"]');

    if (container) {
        return container;
    }

    const addonContainer = messageElement.querySelector(
        '[data-testid="addon-bubble-container"]'
    );

    if (addonContainer) {
        return addonContainer;
    }

    return messageElement;
}

function afficherResultat(messageElement, texte, estErreur = false) {
    let resultat = messageElement.querySelector(".coffre-crypto-result");

    if (!resultat) {
        resultat = document.createElement("div");
        resultat.className = "coffre-crypto-result";

        const zone = trouverZoneInsertion(messageElement);
        zone.appendChild(resultat);
    }

    if (estErreur) {
        resultat.classList.add("coffre-crypto-error");
    } else {
        resultat.classList.remove("coffre-crypto-error");
    }

    resultat.textContent = texte;
}

async function demanderDechiffrement(messageElement, texteChiffre) {
    try {
        const messageNettoye = nettoyerMessageChiffreRSA(texteChiffre);

        if (!messageNettoye) {
            afficherResultat(
                messageElement,
                "Aucun message chiffré détecté.",
                true
            );
            return;
        }

        const response = await browser.runtime.sendMessage({
            type: "DECRYPT_MESSAGE",
            messageBase64: messageNettoye
        });

        if (!response || !response.ok) {
            afficherResultat(
                messageElement,
                response?.error || "Impossible de déchiffrer ce message.",
                true
            );
            return;
        }

        afficherResultat(messageElement, response.message, false);

    } catch (error) {
        console.error("Erreur déchiffrement depuis WhatsApp :", error);

        afficherResultat(
            messageElement,
            "Erreur avec l’extension Coffre Crypto.",
            true
        );
    }
}

function ajouterBoutonSurMessage(messageElement) {
    if (messageElement.dataset.coffreCryptoReady === "true") {
        return;
    }

    const texte = extraireTexteMessage(messageElement);

    if (!texte) {
        return;
    }

    const bouton = document.createElement("button");
    bouton.type = "button";
    bouton.className = "coffre-crypto-btn";
    bouton.textContent = "Déchiffrer";

    bouton.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();

        bouton.disabled = true;
        bouton.textContent = "Déchiffrement...";

        await demanderDechiffrement(messageElement, texte);

        bouton.disabled = false;
        bouton.textContent = "Déchiffrer";
    });

    const zone = trouverZoneInsertion(messageElement);
    zone.appendChild(bouton);

    messageElement.dataset.coffreCryptoReady = "true";
}

function scannerMessagesWhatsapp() {
    afficherTemoinChargement();

    const messages = trouverMessagesRecus();

    messages.forEach(message => {
        ajouterBoutonSurMessage(message);
    });
}

// =======================================================
// CLÉ PUBLIQUE DU DESTINATAIRE
// =======================================================

async function recupererClePubliqueTiersDepuisStorage() {
    const result = await browser.storage.local.get("clefPubliqueTiers");
    const clefPubliqueTierTexte = result.clefPubliqueTiers;

    if (!clefPubliqueTierTexte) {
        return null;
    }

    const tierPublicKeyJwk = JSON.parse(clefPubliqueTierTexte);

    const tierPublicKey = await crypto.subtle.importKey(
        "jwk",
        tierPublicKeyJwk,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["encrypt"]
    );

    return tierPublicKey;
}

// =======================================================
// BARRE DE MESSAGE WHATSAPP
// =======================================================

function trouverBarreMessageWhatsapp() {
    const zoneExacte = document.querySelector(
        '[data-testid="conversation-compose-box-input"][contenteditable="true"]'
    );

    if (zoneExacte) {
        return zoneExacte;
    }

    const footer = document.querySelector("footer");

    if (!footer) {
        return null;
    }

    const zoneParRole = footer.querySelector(
        'div[contenteditable="true"][role="textbox"]'
    );

    if (zoneParRole) {
        return zoneParRole;
    }

    const zones = footer.querySelectorAll('div[contenteditable="true"]');

    for (const zone of zones) {
        const rect = zone.getBoundingClientRect();

        if (rect.width > 50 && rect.height > 10) {
            return zone;
        }
    }

    return null;
}

function lireTexteBarreMessage(zoneMessage) {
    if (!zoneMessage) {
        return "";
    }

    return zoneMessage.innerText.trim();
}

// =======================================================
// REMPLACEMENT PAR VRAI COLLAGE
// =======================================================

function focusEtSelectionnerTout(zoneMessage) {
    zoneMessage.focus();

    const selection = window.getSelection();
    const range = document.createRange();

    range.selectNodeContents(zoneMessage);
    selection.removeAllRanges();
    selection.addRange(range);
}

function envoyerRaccourciClavier(element, key, code, ctrlKey = false) {
    element.dispatchEvent(new KeyboardEvent("keydown", {
        bubbles: true,
        cancelable: true,
        key: key,
        code: code,
        ctrlKey: ctrlKey,
        metaKey: false
    }));

    element.dispatchEvent(new KeyboardEvent("keyup", {
        bubbles: true,
        cancelable: true,
        key: key,
        code: code,
        ctrlKey: ctrlKey,
        metaKey: false
    }));
}

async function viderChampWhatsapp(zoneMessage) {
    zoneMessage.focus();

    // 1. Ctrl+A
    envoyerRaccourciClavier(zoneMessage, "a", "KeyA", true);
    focusEtSelectionnerTout(zoneMessage);

    await attendre(80);

    // 2. Backspace
    envoyerRaccourciClavier(zoneMessage, "Backspace", "Backspace", false);
    document.execCommand("delete", false, null);

    await attendre(120);
}

function creerPasteEventAvecTexte(texte) {
    const dataTransfer = new DataTransfer();
    dataTransfer.setData("text/plain", texte);

    return new ClipboardEvent("paste", {
        bubbles: true,
        cancelable: true,
        clipboardData: dataTransfer
    });
}

async function collerTexteDansWhatsapp(zoneMessage, texte) {
    zoneMessage.focus();

    const pasteEvent = creerPasteEventAvecTexte(texte);

    // WhatsApp/Lexical écoute normalement l'événement paste.
    zoneMessage.dispatchEvent(pasteEvent);

    await attendre(150);
}

async function remplacerTexteBarreMessage(zoneMessage, nouveauTexte) {
    zoneMessage.focus();

    // 1. On vide l’état via action utilisateur simulée.
    await viderChampWhatsapp(zoneMessage);

    let contenuApresSuppression = zoneMessage.innerText.trim();

    if (contenuApresSuppression.length > 0) {
        console.warn("Suppression incomplète, tentative 2 :", contenuApresSuppression);
        await viderChampWhatsapp(zoneMessage);
    }

    // 2. On colle le chiffré via événement paste.
    await collerTexteDansWhatsapp(zoneMessage, nouveauTexte);

    let contenuFinal = zoneMessage.innerText.trim();

    // 3. Si le paste n'a pas été accepté, fallback insertText.
    if (contenuFinal !== nouveauTexte) {
        console.warn("Paste non accepté, fallback insertText. Contenu :", contenuFinal);

        await viderChampWhatsapp(zoneMessage);

        zoneMessage.focus();
        document.execCommand("insertText", false, nouveauTexte);

        await attendre(150);
        contenuFinal = zoneMessage.innerText.trim();
    }

    // 4. Vérification stricte.
    if (contenuFinal !== nouveauTexte) {
        console.warn("Remplacement échoué. Contenu final :", contenuFinal);

        alert(
            "WhatsApp refuse encore le remplacement propre. Le message n'a pas été injecté correctement."
        );

        return false;
    }

    console.log("Message chiffré injecté proprement.");
    return true;
}

// =======================================================
// CHIFFRER
// =======================================================

async function chiffrerTextePourTiers(texteClair) {
    const tierPublicKey = await recupererClePubliqueTiersDepuisStorage();

    if (tierPublicKey == null) {
        alert(
            "Aucune clé publique de destinataire enregistrée. Ajoutez-la d'abord dans la popup."
        );
        return null;
    }

    const encoder = new TextEncoder();
    const messageBytes = encoder.encode(texteClair);

    if (messageBytes.length > 350) {
        alert("Message trop long pour RSA direct. Écris un message plus court.");
        return null;
    }

    const messageChiffre = await crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        tierPublicKey,
        messageBytes
    );

    return arrayBufferToBase64(messageChiffre);
}

async function chiffrerMessageDansWhatsapp() {
    if (isEncrypting) {
        return;
    }

    isEncrypting = true;

    const zoneMessage = trouverBarreMessageWhatsapp();

    if (!zoneMessage) {
        alert("Barre de message WhatsApp introuvable.");
        isEncrypting = false;
        return;
    }

    const texteClair = lireTexteBarreMessage(zoneMessage);

    if (!texteClair) {
        alert("Écris d'abord un message à chiffrer.");
        isEncrypting = false;
        return;
    }

    try {
        const messageChiffreBase64 = await chiffrerTextePourTiers(texteClair);

        if (!messageChiffreBase64) {
            isEncrypting = false;
            return;
        }

        const remplacementOk = await remplacerTexteBarreMessage(
            zoneMessage,
            messageChiffreBase64
        );

        if (!remplacementOk) {
            console.warn("Injection non validée.");
        }

    } catch (error) {
        console.error("Erreur chiffrement WhatsApp :", error);
        alert("Impossible de chiffrer le message.");
    }

    setTimeout(() => {
        isEncrypting = false;
    }, 700);
}

// =======================================================
// BOUTON CHIFFRER
// =======================================================

function ajouterBoutonChiffrerDansWhatsapp() {
    const footer = document.querySelector("footer");

    if (!footer) {
        return;
    }

    let bouton = document.getElementById("coffre-crypto-encrypt-btn");

    if (bouton) {
        return;
    }

    bouton = document.createElement("button");
    bouton.type = "button";
    bouton.id = "coffre-crypto-encrypt-btn";
    bouton.textContent = "Chiffrer";

    bouton.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();

        if (isEncrypting) {
            return;
        }

        bouton.disabled = true;
        bouton.textContent = "Chiffrement...";

        await chiffrerMessageDansWhatsapp();

        setTimeout(() => {
            bouton.disabled = false;
            bouton.textContent = "Chiffrer";
        }, 700);
    });

    footer.appendChild(bouton);
}

// =======================================================
// INITIALISATION
// =======================================================

function initialiserCoffreCryptoWhatsapp() {
    afficherTemoinChargement();
    scannerMessagesWhatsapp();
    ajouterBoutonChiffrerDansWhatsapp();
}

setInterval(() => {
    scannerMessagesWhatsapp();
    ajouterBoutonChiffrerDansWhatsapp();
}, 1000);

const observer = new MutationObserver(() => {
    scannerMessagesWhatsapp();
    ajouterBoutonChiffrerDansWhatsapp();
});

observer.observe(document.body, {
    childList: true,
    subtree: true
});

initialiserCoffreCryptoWhatsapp();