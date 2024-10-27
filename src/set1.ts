// Set 1 Answers
import {CryptoPals, Decryption} from "./tsCryptopalsLib";

async function main() {
    console.log("Cryptopals Set 1 Answers");
    console.log();

    console.log("Hex: 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    console.log(`Base64:${CryptoPals.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")}`);
    console.log();

    const given = Buffer.from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", "hex");
    console.log("Decrypt single byte xor given: 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    const singleDecrypt = CryptoPals.decodeSingleByteXor(given);
    console.log(`Key: ${singleDecrypt.key}`);
    console.log(singleDecrypt.text);
    console.log();

    console.log("Detect single character xor from file");
    const lines = await CryptoPals.readFile('set1q4.txt');
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

    console.log("Implement Repeating Key Xor");
    const firstline = Buffer.from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
    const encryptedfirst = CryptoPals.repeatingKeyXor(firstline, "ICE");
    console.log("Encrypted line:")
    console.log(encryptedfirst.toString("hex"));
    console.log();

    console.log("Implement hamming distance");
    console.log("Distance between:this is a test and wokka wokka!!!")
    console.log(CryptoPals.hammingDistance("this is a test", "wokka wokka!!!"));
}

main();