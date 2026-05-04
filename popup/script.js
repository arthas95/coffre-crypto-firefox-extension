// =======================================================
// VARIABLES GLOBALES
// =======================================================

// Ces variables serviront à garder temporairement les clés en mémoire JS
// après les avoir récupérées depuis localStorage.

let privateKey = null;
let publicKey = null;

let privateKeyUnlockedAt = null;
let privateKeyTimer = null;
const DEFAULT_ITERATIONS = 300000;


const DUREE_UNLOCK = 60 * 60 * 1000; // 1 heure

async function getIterations() {
    const storedIterations = Number(await storageGet("iterations"));

    if (storedIterations) {
        return storedIterations;
    }

    await storageSet("iterations", String(DEFAULT_ITERATIONS));
    return DEFAULT_ITERATIONS;
}
async function storageSet(key, value) {
    await browser.storage.local.set({
        [key]: value
    });
}

async function storageGet(key) {
    const result = await browser.storage.local.get(key);
    return result[key] ?? null;
}

async function storageRemove(key) {
    await browser.storage.local.remove(key);
}

async function storageClear() {
    await browser.storage.local.clear();
}



function garderClePriveeEnMemoire(clePrivee) {
    privateKey = clePrivee;
    privateKeyUnlockedAt = Date.now();

    if (privateKeyTimer) {
        clearTimeout(privateKeyTimer);
    }

    privateKeyTimer = setTimeout(() => {
        verrouillerClePrivee();
        alert("Session expirée : clé privée supprimée de la mémoire.");
    }, DUREE_UNLOCK);

    console.log("Clé privée gardée en mémoire pour 1 heure");
}

async function verrouillerClePrivee() {
    privateKey = null;
    privateKeyUnlockedAt = null;

    if (privateKeyTimer) {
        clearTimeout(privateKeyTimer);
        privateKeyTimer = null;
    }

    try {
        await browser.runtime.sendMessage({
            type: "LOCK_PRIVATE_KEY"
        });
    } catch (error) {
        // Le background peut ne pas répondre si l'extension vient d'être rechargée.
    }

    alert("Coffre verrouillé.");
}
// =======================================================
// OUTILS DE CONVERSION : ArrayBuffer <-> Base64
// =======================================================

// Quand crypto.subtle chiffre un message, il renvoie un ArrayBuffer.
// Un ArrayBuffer est du binaire brut, pas facile à afficher.
// Cette fonction transforme ce binaire en texte base64 lisible/copiable.
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary);
}

// Quand on veut déchiffrer, il faut refaire l’inverse.
// Le message chiffré est affiché en base64,
// mais crypto.subtle.decrypt attend du binaire ArrayBuffer.
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}


// =======================================================
// 1. DÉRIVER UNE CLÉ DEPUIS UN MOT DE PASSE
// =======================================================

//async function lancerDerivation(event) {
//    // Empêche le formulaire de recharger la page
//    event.preventDefault();
//
 //   // On récupère le mot de passe tapé par l'utilisateur
 //   let mdp = document.getElementById('mdp').value;
 //   console.log("Mot de passe tapé :", mdp);
//
 //   // La crypto ne travaille pas directement avec du texte.
 //   // On transforme donc le mot de passe en octets.
 //   const encoder = new TextEncoder();
 //   const passwordBytes = encoder.encode(mdp);

  //  // On importe le mot de passe comme matière brute pour PBKDF2.
  //  // Ce n'est pas encore la clé finale.
  //  const basekey = await crypto.subtle.importKey(
   //     "raw",
   //     passwordBytes,
   //     "PBKDF2",
   //     false,
  //      ["deriveBits"]
  //  );

    // On génère un salt aléatoire de 16 octets.
    // Le salt n'est pas secret, mais il faut le garder pour retrouver la même clé.
   // const salt = crypto.getRandomValues(new Uint8Array(16));

    // On dérive 256 bits avec PBKDF2.
    // 256 bits = 32 octets.
   // const deriveBits = await crypto.subtle.deriveBits(
   //     {
   //         name: "PBKDF2",
   //         salt: salt,
    //        iterations: 30000,
    //        hash: "SHA-256"
    //    },
    //    basekey,
    //    256
   // );

   // // On convertit la clé dérivée brute en hexadécimal pour pouvoir la voir.
   // const keyArray = new Uint8Array(deriveBits);
//
   // const keyHex = Array.from(keyArray)
     //   .map(byte => byte.toString(16).padStart(2, "0"))
     //   .join("");

    //console.log("Clé dérivée en hex :", keyHex);

    //// On stocke uniquement les paramètres nécessaires pour redériver la clé.
   // // On ne stocke pas la clé dérivée elle-même.
   // if (localStorage.getItem("encryptedPrivateKey") === null) {
   // localStorage.setItem("salt", JSON.stringify(Array.from(salt)));
  //  localStorage.setItem("iterations", "30000");
  //  localStorage.setItem("hash", "SHA-256");
 //   localStorage.setItem("kdf", "PBKDF2");
//} else {
   // console.log("Un coffre existe déjà : le salt existant n'a pas été remplacé.");
//}
//}


// =======================================================
// 2. GÉNÉRER UNE PAIRE RSA 4096 BITS
// =======================================================

async function genererRSA(event) {
    event.preventDefault();

    if (
      await storageGet("publicKey") !== null ||
       await storageGet("encryptedPrivateKey") !== null
    ) {
        const confirmation = confirm(
            "Une paire RSA existe déjà. Si vous en générez une nouvelle, les anciens messages ne seront plus déchiffrables. Continuer ?"
        );

        if (!confirmation) {
            return;
        }
    }

    const mdp = document.getElementById("mdp").value;

    if (!mdp) {
        alert("Veuillez entrer un mot de passe maître avant de générer la paire RSA.");
        return;
    }

    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKeyJwk = await crypto.subtle.exportKey(
        "jwk",
        keyPair.publicKey
    );

    const privateKeyJwk = await crypto.subtle.exportKey(
        "jwk",
        keyPair.privateKey
    );

    const salt = crypto.getRandomValues(new Uint8Array(16));

    const aesKey = await deriverCleAESDepuisMotDePasse(mdp, salt);

    const coffre = await chiffrerClePriveeRSA(privateKeyJwk, aesKey);

   await storageSet("publicKey", JSON.stringify(publicKeyJwk));
    await storageSet("encryptedPrivateKey", coffre.encryptedPrivateKey);
    await storageSet("privateKeyIv", coffre.iv);

    await storageSet("salt", JSON.stringify(Array.from(salt)));
    await storageSet("iterations", String(await getIterations()));
   await storageSet("hash", "SHA-256");
    await storageSet("kdf", "PBKDF2");

    await storageRemove("privateKey");

    //console.log("Clé publique JWK stockée :", publicKeyJwk);
    //console.log("Clé privée RSA chiffrée stockée :", coffre.encryptedPrivateKey);

    alert("Paire RSA générée. Clé privée chiffrée avec le mot de passe maître.");
}
// =======================================================
// 3. RÉCUPÉRER LA CLÉ PUBLIQUE DEPUIS localStorage
// =======================================================

async function recupererPublicKey() {
    // On récupère la clé publique stockée sous forme de texte JSON
    const publicKeyText = await storageGet("publicKey");

    // Si rien n'est stocké, on retourne null
    if (publicKeyText == null) {
        return null;
    }

    // On transforme le texte JSON en objet JavaScript
    const publicKeyJwk = JSON.parse(publicKeyText);

    // On réimporte la clé dans crypto.subtle pour obtenir une vraie CryptoKey utilisable
    const publicKey = await crypto.subtle.importKey(
        "jwk",
        publicKeyJwk,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        true,
        ["encrypt"]
    );

    return publicKey;
}


// =======================================================
// 4. RÉCUPÉRER LA CLÉ PRIVÉE DEPUIS localStorage
// =======================================================

async function recupererPrivateKeyDepuisMotDePasse(mdp) {
    // 1. On récupère les éléments stockés
    const encryptedPrivateKey = await storageGet("encryptedPrivateKey");
    const iv = await storageGet("privateKeyIv");
    const saltStocke = await storageGet("salt");

    if (encryptedPrivateKey == null || iv == null || saltStocke == null) {
        return null;
    }

    // 2. On reconstruit le salt
    const salt = new Uint8Array(JSON.parse(saltStocke));

    // 3. On redérive la même clé AES avec le mot de passe
    const aesKey = await deriverCleAESDepuisMotDePasse(mdp, salt);

    // 4. On déchiffre la clé privée RSA
    const privateKeyJwk = await dechiffrerClePriveeRSA(
        encryptedPrivateKey,
        iv,
        aesKey
    );

    // 5. On importe la clé privée RSA utilisable par crypto.subtle
    const privateKey = await crypto.subtle.importKey(
        "jwk",
        privateKeyJwk,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        false,//
        ["decrypt"]
    );

    return privateKey;
}

// =======================================================
// 5. VÉRIFIER SI UNE PAIRE DE CLÉS EXISTE EN MÉMOIRE
// =======================================================

async function verifierKey(event) {
    event.preventDefault();

    try {
        const mdp = document.getElementById("mdp").value;

        if (!mdp) {
            alert("Veuillez entrer votre mot de passe maître.");
            return;
        }

        const clePubliqueRecuperee = await recupererPublicKey();
        const resultat = await recupererPrivateKeyEtJwkDepuisMotDePasse(mdp);

        if (resultat == null || clePubliqueRecuperee == null) {
            alert("Paire de clés absente ou incomplète.");
            return;
        }

        publicKey = clePubliqueRecuperee;

        // Optionnel : garde aussi dans la popup tant qu'elle reste ouverte
        privateKey = resultat.privateKey;

        const response = await browser.runtime.sendMessage({
            type: "UNLOCK_PRIVATE_KEY",
            privateKeyJwk: resultat.privateKeyJwk
        });

        document.getElementById("mdp").value = "";

        if (!response || !response.ok) {
            alert(response?.error || "Impossible de déverrouiller le coffre.");
            return;
        }

        alert("Coffre déverrouillé pendant 1 heure.");

    } catch (error) {
        alert("Mot de passe incorrect ou clé privée impossible à déchiffrer.");
    }
}


// =======================================================
// 6. AJOUTER LA ZONE HTML POUR CHIFFRER / DÉCHIFFRER
// =======================================================

function ajouterTexteChiffreDechiffre() {
    // Évite d'ajouter plusieurs fois les mêmes champs avec les mêmes id
    if (document.getElementById("messageAchiffrer")) {
        return;
    }

    // On définit le contenu HTML à ajouter dynamiquement
    const nouveauContenu = `
        <h1>Chiffrer message</h1>
        <form>
            <input type="text" name="messageAchiffrer" id="messageAchiffrer" placeholder="Message à chiffrer">
            <button onclick="chiffrerMessage(event)">Chiffrer message</button>
        </form>

        <h1>Déchiffrer message</h1>
        <form>
            <input type="text" name="messageAdechiffrer" id="messageAdechiffrer" placeholder="Message chiffré en base64">
            <button onclick="dechiffrerMessage(event)">Déchiffrer message</button>
        </form>
    `;

    // On ajoute cette zone à la fin du body
    document.body.insertAdjacentHTML('beforeend', nouveauContenu);
}


// =======================================================
// 7. CHIFFRER UN MESSAGE AVEC LA CLÉ PUBLIQUE
// =======================================================

async function chiffrerMessage(event) {
    event.preventDefault();

    // On récupère la clé publique depuis localStorage
    const publicKey = await recupererPublicKey();

    if (publicKey == null) {
        alert("Aucune clé publique trouvée");
        return;
    }

    // On récupère le message clair
    const message = document.getElementById('messageAchiffrer').value;

    // On transforme le texte en octets
    const encoder = new TextEncoder();
    const messagesBytes = encoder.encode(message);

    // On chiffre avec RSA-OAEP et la clé publique
    const messageChiffre = await crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        publicKey,
        messagesBytes
    );

    // Le résultat est du binaire.
    // On le convertit en base64 pour pouvoir l'afficher/copier/coller.
    const messageChiffreBase64 = arrayBufferToBase64(messageChiffre);

    //console.log("Message chiffré brut :", messageChiffre);
    //console.log("Message chiffré base64 :", messageChiffreBase64);


}


// =======================================================
// 8. DÉCHIFFRER UN MESSAGE AVEC LA CLÉ PRIVÉE
// =======================================================

async function dechiffrerMessage(event) {
    event.preventDefault();

    const messageBase64 = document.getElementById("messageAdechiffrer").value.trim();

    if (!messageBase64) {
        alert("Veuillez coller un message chiffré.");
        return;
    }

    try {
        const response = await browser.runtime.sendMessage({
            type: "DECRYPT_MESSAGE",
            messageBase64: messageBase64
        });

        if (!response || !response.ok) {
            alert(response?.error || "Impossible de déchiffrer le message.");
            return;
        }

        document.getElementById("messageDechiffre").value = response.message;

    } catch (error) {
        alert("Erreur de communication avec le background.");
    }
}
async function afficherClePub(event) {
    event.preventDefault();

    const publicKeyText = await storageGet("publicKey");

    if (publicKeyText == null) {
        alert("Aucune clé publique trouvée");
        return;
    }

    //console.log("Clé publique à partager :", publicKeyText);
    alert(publicKeyText);
}
async function copyBoardPublicKey(event) {
    event.preventDefault();

    const publicKeyText = await storageGet("publicKey");

    if (publicKeyText == null) {
        alert("Aucune clé publique trouvée");
        return;
    }

    try {
        await navigator.clipboard.writeText(publicKeyText);
        alert("Clé publique copiée dans le presse-papiers");
    } catch (error) {
        console.error(error);
        alert("Impossible de copier la clé publique");
    }
}
async function copyBoardMessageChiffre(event){
    event.preventDefault();
    const message = document.getElementById("messageChiffrePourTier").value;
    if (message != null){
        try {
        await navigator.clipboard.writeText(message);
        alert("Message chiffré copié dans le presse-papiers");
    } catch (error) {
        console.error(error);
        alert("Impossible de copier le message chiffré");
    }
    }

}

async function  chargerClePubliqueTiersSauvegardee() {
    const ancienneCle = await storageGet("clefPubliqueTiers");

    if (ancienneCle != null) {
        document.getElementById("publicKeyText").value = ancienneCle;

        const disclaimer = document.getElementById("publicKeyDisclaimer");
        disclaimer.textContent =
            "Voici la clé publique de votre précédent correspondant. Modifiez le texte ci-dessous si vous souhaitez changer d’hôte.";
        disclaimer.style.display = "block";
    }
}

async function clefPubliqueTier(event) {
    event.preventDefault();

    // 1. On récupère le texte dans le textarea
    const clefPubliqueTierTexte = document.getElementById('publicKeyText').value.trim();

    if (clefPubliqueTierTexte === "") {
        alert("Veuillez coller une clé publique.");
        return null;
    }

    try {
        // 2. On transforme le texte JSON en objet JWK
        const tierPublicKeyJwk = JSON.parse(clefPubliqueTierTexte);

        // 3. On importe la clé publique du tiers pour vérifier qu’elle est valide
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

        // 4. Si l’import réussit, on sauvegarde le texte JSON dans localStorage
       await storageSet("clefPubliqueTiers", clefPubliqueTierTexte);

        alert("Clé publique du correspondant enregistrée.");

        return tierPublicKey;

    } catch (error) {
        console.error(error);
        alert("Clé publique invalide. Vérifiez le texte collé.");
        return null;
    }
}
async function recupererClefPubliqueTiers() {
    const clefPubliqueTierTexte = await storageGet("clefPubliqueTiers");

    if (clefPubliqueTierTexte == null) {
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

async function chiffrerMessagePourTiers(event) {
    event.preventDefault();

    const tierPublicKey = await recupererClefPubliqueTiers();

    if (tierPublicKey == null) {
        alert("Aucune clé publique de correspondant enregistrée.");
        return;
    }

    const message = document.getElementById("messagePourTier").value;

    const encoder = new TextEncoder();
    const messageBytes = encoder.encode(message);

    const messageChiffre = await crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        tierPublicKey,
        messageBytes
    );

    const messageChiffreBase64 = arrayBufferToBase64(messageChiffre);

    document.getElementById("messageChiffrePourTier").value = messageChiffreBase64;

    //console.log("Message chiffré pour le tiers :", messageChiffreBase64);
}
async function deriverCleAESDepuisMotDePasse(mdp, salt) {
    // 1. On transforme le mot de passe en octets
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(mdp);

    // 2. On importe le mot de passe comme base PBKDF2
    const basekey = await crypto.subtle.importKey(
        "raw",
        passwordBytes,
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    // 3. On dérive une vraie clé AES-GCM 256 bits
    const aesKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: await getIterations(),
            hash: "SHA-256"
        },
        basekey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );

    return aesKey;
}
async function chiffrerClePriveeRSA(privateKeyJwk, aesKey) {
    // 1. On transforme la clé privée JWK en texte JSON
    const privateKeyText = JSON.stringify(privateKeyJwk);

    // 2. On transforme ce texte en octets
    const encoder = new TextEncoder();
    const privateKeyBytes = encoder.encode(privateKeyText);

    // 3. AES-GCM a besoin d'un IV unique
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 4. On chiffre la clé privée RSA avec la clé AES dérivée
    const encryptedPrivateKey = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        aesKey,
        privateKeyBytes
    );

    // 5. On retourne le chiffré + l'IV
    return {
        encryptedPrivateKey: arrayBufferToBase64(encryptedPrivateKey),
        iv: arrayBufferToBase64(iv)
    };
}
async function dechiffrerClePriveeRSA(encryptedPrivateKeyBase64, ivBase64, aesKey) {
    // 1. On reconvertit le chiffré base64 en ArrayBuffer
    const encryptedPrivateKeyBuffer = base64ToArrayBuffer(encryptedPrivateKeyBase64);

    // 2. On reconvertit l'IV base64 en ArrayBuffer
    const ivBuffer = base64ToArrayBuffer(ivBase64);

    // 3. On déchiffre avec AES-GCM
    const privateKeyBytes = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: ivBuffer
        },
        aesKey,
        encryptedPrivateKeyBuffer
    );

    // 4. On transforme les octets en texte JSON
    const decoder = new TextDecoder();
    const privateKeyText = decoder.decode(privateKeyBytes);

    // 5. On retransforme le JSON texte en objet JWK
    const privateKeyJwk = JSON.parse(privateKeyText);

    return privateKeyJwk;
}
function afficherFenetre(nom) {
    const fenetres = document.querySelectorAll(".window");
    const tabs = document.querySelectorAll(".tab");

    fenetres.forEach(fenetre => {
        fenetre.classList.remove("active-window");
    });

    tabs.forEach(tab => {
        tab.classList.remove("active");
    });

    const fenetreActive = document.getElementById("fenetre-" + nom);
    const tabActive = document.getElementById("tab-" + nom);

    if (fenetreActive) {
        fenetreActive.classList.add("active-window");
    }

    if (tabActive) {
        tabActive.classList.add("active");
    }
}

document.addEventListener("DOMContentLoaded", async () => {
    // Navigation onglets
    const tabs = document.querySelectorAll(".tab");

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const nomFenetre = tab.dataset.window;
            afficherFenetre(nomFenetre);
        });
    });

    // Boutons coffre
    const btnGenererRSA = document.getElementById("btn-generer-rsa");
    if (btnGenererRSA) {
        btnGenererRSA.addEventListener("click", genererRSA);
    }

    const btnVerifierKey = document.getElementById("btn-verifier-key");
    if (btnVerifierKey) {
        btnVerifierKey.addEventListener("click", verifierKey);
    }

    const btnAfficherClePub = document.getElementById("btn-afficher-cle-pub");
    if (btnAfficherClePub) {
        btnAfficherClePub.addEventListener("click", afficherClePub);
    }

    const btnCopierClePub = document.getElementById("btn-copier-cle-pub");
    if (btnCopierClePub) {
        btnCopierClePub.addEventListener("click", copyBoardPublicKey);
    }

    const btnVerrouiller = document.getElementById("btn-verrouiller");
    if (btnVerrouiller) {
        btnVerrouiller.addEventListener("click", verrouillerClePrivee);
    }

    // Bouton lecture
    const btnDechiffrerMessage = document.getElementById("btn-dechiffrer-message");
    if (btnDechiffrerMessage) {
        btnDechiffrerMessage.addEventListener("click", dechiffrerMessage);
    }

    // Boutons envoi
    const btnEnregistrerCleTier = document.getElementById("btn-enregistrer-cle-tier");
    if (btnEnregistrerCleTier) {
        btnEnregistrerCleTier.addEventListener("click", clefPubliqueTier);
    }

    const btnChiffrerTier = document.getElementById("btn-chiffrer-tier");
    if (btnChiffrerTier) {
        btnChiffrerTier.addEventListener("click", chiffrerMessagePourTiers);
    }

    const btnCopierMessageChiffre = document.getElementById("btn-copier-message-chiffre");
    if (btnCopierMessageChiffre) {
        btnCopierMessageChiffre.addEventListener("click", copyBoardMessageChiffre);
    }

    // Recharge la clé publique du dernier correspondant
    if (typeof chargerClePubliqueTiersSauvegardee === "function") {
        await chargerClePubliqueTiersSauvegardee();
    }
});

async function recupererPrivateKeyEtJwkDepuisMotDePasse(mdp) {
    const encryptedPrivateKey = await storageGet("encryptedPrivateKey");
    const iv = await storageGet("privateKeyIv");
    const saltStocke = await storageGet("salt");

    if (encryptedPrivateKey == null || iv == null || saltStocke == null) {
        return null;
    }

    const salt = new Uint8Array(JSON.parse(saltStocke));

    const aesKey = await deriverCleAESDepuisMotDePasse(mdp, salt);

    const privateKeyJwk = await dechiffrerClePriveeRSA(
        encryptedPrivateKey,
        iv,
        aesKey
    );

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

    return {
        privateKey,
        privateKeyJwk
    };
}
//function debugStorage() {
//    console.log("publicKey :", localStorage.getItem("publicKey"));
//    console.log("encryptedPrivateKey :", localStorage.getItem("encryptedPrivateKey"));
//    console.log("privateKeyIv :", localStorage.getItem("privateKeyIv"));
//    console.log("salt :", localStorage.getItem("salt"));
//    console.log("ancienne privateKey en clair :", localStorage.getItem("privateKey"));
//}