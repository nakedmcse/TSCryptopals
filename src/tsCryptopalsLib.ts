// TS Cryptopals lib
import fs from "node:fs/promises";

interface StringDictionary<T> {
    [key: string]: T;
}
export class Decryption {
    public constructor(public key: string, public text: string) {}
}

export class CryptoPals {
    private static bitCountLookup: number[] = Array.from({ length: 256 }, (_, i) =>
        i.toString(2).split('0').join('').length
    );

    public static async readFile(filepath: string): Promise<string[]|null> {
        try {
            const filedata = await fs.readFile(filepath, "utf-8");
            return filedata.split('\n');
        } catch {
            return null;
        }
    }

    public static hexToBase64(hex: string): string | null {
        const hex_regex: RegExp = /^[0-9a-fA-F]+$/;
        if(hex.length % 2 !== 0) return null;
        if(!hex_regex.test(hex)) return null;

        const bytes: Buffer = Buffer.from(hex, "hex");
        return bytes.toString("base64");
    }

    public static fixedXor(x: Buffer, y: Buffer): Buffer | null {
        if(x.length !== y.length) return null;
        const retval = Buffer.alloc(x.length);
        for(let i = 0; i < x.length; i++) {
            retval[i] = x[i] ^ y[i];
        }
        return retval;
    }

    public static repeatingKeyXor(x: Buffer, keyString: string): Buffer {
        const retval = Buffer.alloc(x.length);
        const key = Buffer.from(keyString);
        for(let i = 0; i < x.length; i++) {
            retval[i] = x[i] ^ key[i % key.length];
        }
        return retval;
    }

    public static englishFreqDiff(text: string): number {
        const englishFreqs: StringDictionary<number> =
            {"E":0.126, "T":0.0937, "A":0.0834, "O":0.077, "N":0.068, "I":0.0671, "H":0.0611, "S":0.0611, "R":0.0568, "L":0.0424, "D":0.0414, "U":0.0285,
             "C":0.0273, "M":0.0253, "W":0.0234, "Y":0.0204, "F":0.0203, "G":0.0192, "P":0.0166, "B":0.0154, "V":0.0106, "K":0.0087, "J":0.0023, "X":0.002,
             "Q":0.0009, "Z":0.0006, " ":0.2};
        const textFreqs: StringDictionary<number> = {};
        let retval = 100;
        const keys = Object.keys(englishFreqs);
        for(const key of keys) textFreqs[key] = 0;
        for(const char of text.toUpperCase()) {
            if(keys.includes(char)) textFreqs[char] += 1;
        }
        const sum = Object.values(textFreqs).reduce((a, v) => a+v, 0);
        if (sum === 0) return retval;  // nothing to compare
        for(const key of keys) textFreqs[key] = Math.abs(englishFreqs[key] - (textFreqs[key]/text.length));
        retval = Object.values(textFreqs).reduce((a, v) => a+v, 0);
        return retval;
    }

    public static decodeSingleByteXor(x: Buffer): Decryption {
        let retval = "";
        let bestscore = 100;
        let keyOrd = 0;
        for( let i = 0; i < 256; i++){
            const y: Buffer = Buffer.alloc(x.length).fill(i);
            const candidate: Buffer | null = this.fixedXor(x, y);
            if(candidate) {
                const possible = candidate.toString()
                const score = this.englishFreqDiff(possible);
                if(score < bestscore) {
                    retval = possible;
                    bestscore = score;
                    keyOrd = i;
                }
            }
        }
        return new Decryption(String.fromCharCode(keyOrd), retval);
    }

    public static hammingDistance(xString: string, yString: string): number {
        let retval = 0;
        const x = Buffer.from(xString);
        const y = Buffer.from(yString);
        if(x.length !== y.length) {
            retval += Math.abs(x.length - y.length) * 8;  // Account for missing bytes
        }
        const len = Math.min(x.length, y.length);
        for(let i = 0; i < len; i++) {
            retval += this.bitCountLookup[x[i] ^ y[i]];
        }
        return retval;
    }
}