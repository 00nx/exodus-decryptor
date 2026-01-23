/* exodus pass decryptor */


const zlib = require("zlib");
const bs = require("bitcoin-seed");
const fs = require("fs");
const path = require("path");
const os = require("os");
const seco = require("secure-container");



const LOG_LEVEL = process.env.LOG_LEVEL || "info";
function log(level, message, meta = {}) {
    const levels = ["error", "warn", "info", "debug"];
    if (levels.indexOf(level) > levels.indexOf(LOG_LEVEL)) return;

    const payload = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : "";
    console[level](`[${level.toUpperCase()}] ${message}${payload}`);
}


function extractSecoPayload(secoData) {
    if (!Buffer.isBuffer(secoData)) {
        throw new TypeError("SECO payload must be a Buffer");
    }

    if (secoData.length < 4) {
        throw new Error("Invalid SECO data: buffer too small");
    }

    const expectedLength = secoData.readUInt32BE(0);

    if (secoData.length < expectedLength + 4) {
        throw new Error(
            `Invalid SECO data: expected ${expectedLength + 4} bytes, got ${secoData.length}`
        );
    }

    return secoData.slice(4, expectedLength + 4);
}


async function decryptAndExtractMnemonic(encryptedData, password) {
    try {
        const { data: decrypted } = await seco.decrypt(encryptedData, password);
        const shrinked = extractSecoPayload(decrypted);
        const gunzipped = zlib.gunzipSync(shrinked);
        const seed = bs.fromBuffer(gunzipped);
        if (!seed || !seed.mnemonicString) {
            throw new Error("Failed to extract mnemonic from buffer.");
        }
        return seed.mnemonicString;
    } catch (error) {
        throw new Error(`Failed to process seed data: ${error.message}`);
    }
}

function locateExodus() {
    let exodusDir;
    const platform = os.platform();

    try {
        if (platform === "win32") {
            exodusDir = path.join(process.env.APPDATA, "Exodus", "exodus.wallet");
        } else if (platform === "darwin") {
            exodusDir = path.join(os.homedir(), "Library", "Application Support", "Exodus", "exodus.wallet");
        } else if (platform === "linux") {
            exodusDir = path.join(os.homedir(), ".config", "Exodus", "exodus.wallet");
        } else {
            return { exodus: false, error: `Unsupported operating system: ${platform}` };
        }

        const seedPath = path.join(exodusDir, "seed.seco");
        const passphrasePath = path.join(exodusDir, "passphrase.json"); // dont try if u have sum other os 

        if (fs.existsSync(seedPath)) {
            return {
                exodus: true,
                path: seedPath,
                walletDir: exodusDir,
                passwordRequired: !fs.existsSync(passphrasePath),
            };
        }
        return { exodus: false, error: `seed.seco not found at: ${seedPath}` };
    } catch (error) {
        return { exodus: false, error: `Filesystem error during Exodus location: ${error.message}` };
    }
}

async function findPasswordFromList(seedFilePath, passwords) {
    let seedData;
    try {
        seedData = fs.readFileSync(seedFilePath);
    } catch (error) {
        return { success: false, error: `Failed to read seed file: ${error.message}` };
    }

    const start = process.hrtime();
    let tried_passwords = 0;
    const uniquePasswords = Array.isArray(passwords) ? [...new Set(passwords)] : [];

    for (const p of uniquePasswords) {
        if (p && typeof p === "string" && p.length >= 8) {
            tried_passwords++;
            try {
                await seco.decrypt(seedData, p);
                const end = process.hrtime(start);
                const timeTakenMs = (end[0] * 1e9 + end[1]) / 1e6;
                return {
                    success: true,
                    password: p,
                    timeMs: timeTakenMs,
                    timeFormatted: `${end[0]}s ${Math.round(end[1] / 1000000)}ms`,
                    tried_passwords,
                };
            } catch {}
        }
    }

    const end = process.hrtime(start);
    const timeTakenMs = (end[0] * 1e9 + end[1]) / 1e6;
    return {
        success: false,
        error: "Password not found in the provided list.",
        tried_passwords,
        timeMs: timeTakenMs,
    };
}

async function extractWalletMnemonic(passwords) {
    const exodusInfo = locateExodus();

    if (!exodusInfo.exodus) {
        return { success: false, ...exodusInfo };
    }

    let seedData;
    try {
        seedData = fs.readFileSync(exodusInfo.path);
    } catch (error) {
        return { success: false, error: `Failed to read seed file '${exodusInfo.path}': ${error.message}`, exodusInfo };
    }

    if (!exodusInfo.passwordRequired) {
        const passphrasePath = path.join(exodusInfo.walletDir, "passphrase.json");
        try {
            const passphraseJson = fs.readFileSync(passphrasePath, "utf8"); // ts gotta be utf8 
            const passphraseData = JSON.parse(passphraseJson);
            const passphrase = passphraseData.passphrase;

            if (!passphrase) {
                return { success: false, error: "Passphrase file found but content is invalid.", exodusInfo };
            }

            const mnemonic = await decryptAndExtractMnemonic(seedData, passphrase);
            return { success: true, exodusInfo, mnemonic, password: "[Stored Passphrase]" };
        } catch (error) {
            return { success: false, error: `Error processing stored passphrase: ${error.message}`, exodusInfo };
        }
    }

    const bforced = await findPasswordFromList(exodusInfo.path, passwords);
    if (bforced.success) {
        try {
            const mnemonic = await decryptAndExtractMnemonic(seedData, bforced.password);
            return {
                success: true,
                exodusInfo,
                mnemonic,
                password: bforced.password,
                bruteForceInfo: bforced,
            };
        } catch (error) {
            return {
                success: false,
                error: `Decryption failed after brute-force: ${error.message}`,
                exodusInfo,
                bruteForceInfo: bforced,
            };
        }
    }
    return { success: false, error: `Brute-force failed: ${bforced.error}`, bruteForceInfo: bforced, exodusInfo };
}

(async () => {
    try {
        const passwordListPath = "list.txt";
        let passwords = [];
        if (fs.existsSync(passwordListPath)) {
            passwords = fs.readFileSync(passwordListPath, "utf8")
                .split(/\r?\n/)
                .map((pw) => pw.trim())
                .filter((pw) => pw.length > 0);
            if (passwords.length > 0) {
                console.log(`Loaded ${passwords.length} passwords from ${passwordListPath}`);
            }
        } else {
            console.warn(`Warning: Password list '${passwordListPath}' not found. Proceeding without brute-force.`);
        }

        const result = await extractWalletMnemonic(passwords);

        console.log("\n--- Result ---");
        if (result.success) {
            console.log("Status: Success!");
            console.log("Exodus Found:", result.exodusInfo.exodus);
            console.log("Seed Path:", result.exodusInfo.path);
            console.log("Password:", result.password);
            console.log("Mnemonic:", result.mnemonic);
            console.log("initialized the result successfully");
            if (result.bruteForceInfo) {
                console.log(
                    `Brute-Force Time: ${result.bruteForceInfo.timeFormatted} (${result.bruteForceInfo.tried_passwords} passwords tried)`
                );
            }
        } else {
            console.error("Status: Failed!");
            console.error("Exodus Found:", result.exodusInfo?.exodus ?? false);
            if (result.exodusInfo?.path) console.error("Seed Path:", result.exodusInfo.path);
            console.error("Error:", result.error);
            if (result.bruteForceInfo) {
                console.error(
                    `Brute-Force Info: ${result.bruteForceInfo.tried_passwords} passwords tried in ${result.bruteForceInfo.timeMs}ms`
                );
            }
        }
        console.log("--------------");
    } catch (error) {
        console.error("\n--- Critical Error ---");
        console.error("Unexpected error:", error.message);
        console.error("----------------------");
    }
})();




