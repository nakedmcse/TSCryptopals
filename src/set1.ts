// Set 1 Answers
import {CryptoPals, Decryption} from "./tsCryptopalsLib";

function question1() {
    console.log("Question 1");
    console.log("Hex: 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    console.log(`Base64:${CryptoPals.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")}`);
    console.log();
}

function question2() {
    console.log("Question 2");
    const x: Buffer = Buffer.from("1c0111001f010100061a024b53535009181c", "hex");
    const y: Buffer = Buffer.from("686974207468652062756c6c277320657965", "hex");
    const fixed: Buffer | null = CryptoPals.fixedXor(x, y);
    if(fixed) {
        console.log(`Fixed xor output: ${fixed.toString("hex")}`);
    } else {
        console.log("Fixed xor failed");
    }
    console.log();
}

function question3() {
    console.log("Question 3");
    const given = Buffer.from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", "hex");
    console.log("Decrypt single byte xor given: 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    const singleDecrypt = CryptoPals.decodeSingleByteXor(given);
    console.log(`Key: ${singleDecrypt.key}`);
    console.log(singleDecrypt.text);
    console.log();
}

async function question4() {
    console.log("Question 4");
    console.log("Detect single character xor from file");
    const lines = await CryptoPals.readFile('txt/set1q4.txt');
    let candidates: Decryption[] = [];
    let bestscore = 100;
    let winningCandidate = 0;
    if(lines) {
        for(const line of lines) {
            candidates.push(CryptoPals.decodeSingleByteXor(Buffer.from(line, "hex")));
        }
        for(let i = 0; i < candidates.length; i++) {
            const score = CryptoPals.englishFreqDiff(candidates[i].text);
            if(score < bestscore) {
                winningCandidate = i;
                bestscore = score;
            }
        }
        console.log(`Key: ${candidates[winningCandidate].key}`);
        console.log(`Line ${winningCandidate}: ${candidates[winningCandidate].text}`)
    } else {
        console.log("Could not read set1q4.txt")
    }
}

function question5() {
    console.log("Question 5");
    console.log("Implement Repeating Key Xor");
    const firstline = Buffer.from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
    const encryptedfirst = CryptoPals.repeatingKeyXor(firstline, "ICE");
    console.log("Encrypted line:")
    console.log(encryptedfirst.toString("hex"));
    console.log();
}

async function question6() {
    console.log("Question 6");
    console.log("Implement hamming distance");
    console.log("Distance between:this is a test and wokka wokka!!!")
    console.log(CryptoPals.hammingDistance(Buffer.from("this is a test"), Buffer.from("wokka wokka!!!")));
    console.log();

    console.log("Break repeating-key xor");
    const rlines = await CryptoPals.readFile('txt/set1q6.txt');
    if(rlines) {
        const rbuf = Buffer.from(rlines.join(''), "base64");
        const recoveredRepeating = CryptoPals.decodeRepeatingXor(rbuf);
        console.log(`Key: ${recoveredRepeating.key}`);
        console.log(recoveredRepeating.text.slice(0,240));
    } else {
        console.log("Could not read set1q6.txt");
    }
    console.log();
}

async function question7() {
    console.log("Question 7");
    console.log("Decrypt AES128 ECB File")
    const ecblines = await CryptoPals.readFile('txt/set1q7.txt');
    if(ecblines) {
        const ecbbuf = Buffer.from(ecblines.join(''), "base64");
        const ecbdecode = CryptoPals.decodeAES128ECB(ecbbuf, "YELLOW SUBMARINE");
        console.log(ecbdecode.toString().slice(0,240))
    } else {
        console.log("Could not read set1q7.txt");
    }
    console.log();
}

async function question8() {
    console.log("Question 8");
    console.log("Detect line with AES ECB");
    const aeslines = await CryptoPals.readFile('txt/set1q8.txt');
    let detectedLine = 0;
    if(aeslines) {
        for(let i = 0; i < aeslines.length; i++) {
            if(CryptoPals.likelyAES128ECB(Buffer.from(aeslines[i], "hex"))) {
                detectedLine = i + 1;
                break;
            }
        }
        if(detectedLine > 0) {
            console.log(`AES/ECB detected at line ${detectedLine}`);
        } else {
            console.log('AES/ECB not detected');
        }
    } else {
        console.log("Could not read set1q8.txt");
    }
    console.log();
}

async function timeGenerateKeys() {
    console.log("Timing Generate Keys");
    const start = performance.now();
    const syncKeys = CryptoPals.generateKeys(3);
    const end = performance.now();
    console.log(`Sync keygen took ${end-start}ms, returning ${syncKeys.length} keys`);
}

async function main() {
    console.log("Cryptopals Set 1 Answers");
    console.log();

    question1();
    question2();
    question3();
    await question4();
    question5();
    await question6();
    await question7();
    await question8();
    await timeGenerateKeys();
}

main();