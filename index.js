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
    if (!Buffer.isBuffer(secoData)) throw new TypeError("SECO payload must be a Buffer");
    if (secoData.length < 4) throw new Error("Invalid SECO data: buffer too small");

    const expectedLength = secoData.readUInt32BE(0);
    if (secoData.length < expectedLength + 4) {
        throw new Error(`Invalid SECO data: expected ${expectedLength + 4} bytes, got ${secoData.length}`);
    }
    return secoData.slice(4, expectedLength + 4);
}

async function decryptAndExtractMnemonic(encryptedData, password) {
    const { data: decrypted } = await seco.decrypt(encryptedData, password);
    const shrinked = extractSecoPayload(decrypted);
    const gunzipped = zlib.gunzipSync(shrinked);
    const seed = bs.fromBuffer(gunzipped);
    
    if (!seed || !seed.mnemonicString) {
        throw new Error("Failed to extract mnemonic from buffer.");
    }
    return seed.mnemonicString;
}

function locateExodus() {
    const platform = os.platform();
    let exodusDir;

    switch (platform) {
        case "win32":
            exodusDir = path.join(process.env.APPDATA || "", "Exodus", "exodus.wallet");
            break;
        case "darwin":
            exodusDir = path.join(os.homedir(), "Library", "Application Support", "Exodus", "exodus.wallet");
            break;
        case "linux":
            exodusDir = path.join(os.homedir(), ".config", "Exodus", "exodus.wallet");
            break;
        default:
            return { success: false, error: `Unsupported OS: ${platform}` };
    }

    const seedPath = path.join(exodusDir, "seed.seco");

    if (!fs.existsSync(seedPath)) {
        return { success: false, error: `seed.seco not found at: ${seedPath}` };
    }

    return {
        success: true,
        seedPath,
        walletDir: exodusDir,
        platform
    };
}

async function findPasswordFromList(seedFilePath, passwords) {
    const seedData = fs.readFileSync(seedFilePath);
    const start = process.hrtime();
    let tried = 0;
    let skipped = 0;
    
    // Remove duplicates and create a clean list
    const uniquePasswords = [...new Set(passwords)];
    const totalPasswords = uniquePasswords.length;
    
    console.log(`\n📋 Starting password check...`);
    console.log(`Total passwords loaded: ${passwords.length}`);
    console.log(`Unique passwords to try: ${totalPasswords}`);
    console.log(`Minimum password length: 6 characters\n`);

    for (let i = 0; i < uniquePasswords.length; i++) {
        const p = uniquePasswords[i];
        
        // Validate password
        if (typeof p !== "string" || p.length < 6) {
            skipped++;
            log("debug", `Skipping invalid password at position ${i + 1}`, { 
                password: p, 
                type: typeof p, 
                length: p?.length 
            });
            continue;
        }
        
        tried++;
        
        // Progress indicator every 25 passwords
        if (tried % 25 === 0) {
            const elapsed = process.hrtime(start);
            const elapsedMs = (elapsed[0] * 1e9 + elapsed[1]) / 1e6;
            const rate = tried / (elapsedMs / 1000);
            console.log(`⏳ Progress: ${tried}/${totalPasswords} passwords tried (${rate.toFixed(2)} pwd/sec)`);
        }
        
        try {
            // Attempt decryption
            await seco.decrypt(seedData, p);
            
            // If we get here, decryption succeeded!
            const end = process.hrtime(start);
            const timeMs = (end[0] * 1e9 + end[1]) / 1e6;
            
            return {
                success: true,
                password: p,
                tried,
                skipped,
                timeMs,
                timeFormatted: `${end[0]}s ${Math.round(end[1] / 1e6)}ms`
            };
            
        } catch (err) {
            // Decryption failed, continue to next password
            // Log detailed errors occasionally to help debugging
            if (tried % 100 === 0) {
                log("debug", `Attempt ${tried} failed`, { 
                    error: err.message,
                    passwordLength: p.length 
                });
            }
            // Continue loop - this is expected behavior
            continue;
        }
    }

    // All passwords tried, none worked
    const end = process.hrtime(start);
    const timeMs = (end[0] * 1e9 + end[1]) / 1e6;
    
    return { 
        success: false, 
        tried, 
        skipped,
        timeMs,
        timeFormatted: `${end[0]}s ${Math.round(end[1] / 1e6)}ms`
    };
}

async function main() {
    try {
        const passwordListPath = "list.txt";
        let passwords = [];

        console.log("🔍 Exodus Wallet Password Recovery Tool\n");

        // Load password list
        if (fs.existsSync(passwordListPath)) {
            const fileContent = fs.readFileSync(passwordListPath, "utf8");
            passwords = fileContent
                .split(/\r?\n/)
                .map(pw => pw.trim())
                .filter(pw => pw.length > 0);

            console.log(`✅ Loaded ${passwords.length} passwords from list.txt`);
        } else {
            console.error("❌ Password list 'list.txt' not found!");
            console.error("Please create a list.txt file with one password per line.");
            return;
        }

        if (passwords.length === 0) {
            console.error("❌ Password list is empty!");
            return;
        }

        // Locate Exodus wallet
        const exodusInfo = locateExodus();

        if (!exodusInfo.success) {
            console.error("❌ Exodus wallet not found:", exodusInfo.error);
            return;
        }

        console.log(`✅ Exodus wallet found`);
        console.log(`   Platform: ${exodusInfo.platform}`);
        console.log(`   Seed file: ${exodusInfo.seedPath}\n`);

        // Read seed file
        const seedData = fs.readFileSync(exodusInfo.seedPath);
        console.log(`✅ Seed file loaded (${seedData.length} bytes)\n`);

        // Try all passwords
        const result = await findPasswordFromList(exodusInfo.seedPath, passwords);

        console.log("\n" + "=".repeat(60));
        
        if (result.success) {
            // SUCCESS - Password found!
            console.log("\n🎉 SUCCESS! PASSWORD FOUND!\n");
            console.log("=".repeat(60));
            console.log(`Password: ${result.password}`);
            console.log("=".repeat(60));
            
            // Extract and display mnemonic
            try {
                const mnemonic = await decryptAndExtractMnemonic(seedData, result.password);
                console.log("\n🔑 Recovery Phrase (Mnemonic):\n");
                console.log(mnemonic);
                console.log("\n" + "=".repeat(60));
            } catch (mnemonicError) {
                console.error("\n⚠️  Password is correct but failed to extract mnemonic:");
                console.error(mnemonicError.message);
            }
            
            console.log(`\n📊 Statistics:`);
            console.log(`   Passwords tried: ${result.tried}`);
            console.log(`   Passwords skipped: ${result.skipped}`);
            console.log(`   Time elapsed: ${result.timeFormatted}`);
            console.log(`   Speed: ${(result.tried / (result.timeMs / 1000)).toFixed(2)} passwords/sec`);
            console.log("\n" + "=".repeat(60));
            
        } else {
            // FAILURE - No password found
            console.log("\n❌ PASSWORD NOT FOUND\n");
            console.log("=".repeat(60));
            console.log(`All passwords from list.txt have been tried.`);
            console.log(`\n📊 Statistics:`);
            console.log(`   Passwords tried: ${result.tried}`);
            console.log(`   Passwords skipped: ${result.skipped}`);
            console.log(`   Total in list: ${passwords.length}`);
            console.log(`   Time elapsed: ${result.timeFormatted}`);
            console.log(`   Speed: ${(result.tried / (result.timeMs / 1000)).toFixed(2)} passwords/sec`);
            console.log("\n💡 Suggestions:");
            console.log("   - Double-check your password list");
            console.log("   - Try common variations (uppercase, numbers, special chars)");
            console.log("   - Ensure passwords are at least 6 characters long");
            console.log("\n" + "=".repeat(60));
        }

    } catch (error) {
        console.error("\n💥 CRITICAL ERROR\n");
        console.error("=".repeat(60));
        console.error("Error:", error.message);
        if (error.stack) {
            console.error("\nStack trace:");
            console.error(error.stack);
        }
        console.error("=".repeat(60));
    }
}

main();
