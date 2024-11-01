// TS Cryptopals lib
import fs from "node:fs/promises";
import crypto from "crypto";

interface StringDictionary<T> {
    [key: string]: T;
}

export class Decryption {
    public constructor(public key: string, public text: string) {}
}

export class Combination<T> {
    public constructor(public x: T, public y: T) {}
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

    public static generateKeys(keylen: number, start: number = 0, end: number = 0): Array<string> {
        const retval: string[] = [];
        if(keylen > 4) keylen = 4;
        if(end === 0) end = 2**(keylen*8);
        for(let i = start; i < end; i++) {
            if(i <= 2**8) {
                retval.push(String.fromCharCode(i & 0xFF));
            }
            else if(i <= 2**16) {
                const extract1 = String.fromCharCode((i & 0xFF00) >> 8);
                const extract2 = String.fromCharCode(i & 0xFF);
                retval.push(extract1 + extract2);
            }
            else if(i <= 2**24) {
                const extract1 = String.fromCharCode((i & 0xFF0000) >> 16);
                const extract2 = String.fromCharCode((i & 0xFF00) >> 8);
                const extract3 = String.fromCharCode(i & 0xFF);
                retval.push(extract1 + extract2 + extract3);
            }
            else {
                const extract1 = String.fromCharCode((i & 0xFF000000) >> 24);
                const extract2 = String.fromCharCode((i & 0xFF0000) >> 16);
                const extract3 = String.fromCharCode((i & 0xFF00) >> 8);
                const extract4 = String.fromCharCode(i & 0xFF);
                retval.push(extract1 + extract2 + extract3 + extract4);
            }
        }
        return retval;
    }

    public static combinations<T>(inboundList: Array<T>): Array<Combination<T>> {
        const retval = new Array<Combination<T>>();
        for(let i = 0; i < inboundList.length - 1; i++) {
            for(let j = i+1; j < inboundList.length; j++) {
                retval.push(new Combination<T>(inboundList[i], inboundList[j]));
            }
        }
        return retval;
    }

    public static getBlocks(x: Buffer, blocksize: number, maxblocks: number = -1): Array<Buffer> {
        const retval = new Array<Buffer>();
        for (let i = 0; i < x.length; i += blocksize) {
            if(maxblocks === 0) break;
            retval.push(x.subarray(i, i+blocksize));
            maxblocks--;
        }
        return retval;
    }

    public static hexToBase64(hex: string): string | null {
        const hex_regex: RegExp = /^[0-9a-fA-F]+$/;
        if(hex.length % 2 !== 0) return null;
        if(!hex_regex.test(hex)) return null;

        return Buffer.from(hex, "hex").toString("base64");
    }

    public static fixedXor(x: Buffer, y: Buffer): Buffer | null {
        if(x.length !== y.length) return null;
        return Buffer.from(x.map((v, idx) => (v ^ y[idx])));
    }

    public static repeatingKeyXor(x: Buffer, keyString: string): Buffer {
        const key = Buffer.from(keyString);
        return Buffer.from(x.map((v, idx) => (v ^ key[idx % key.length])));
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

    public static englishScore(text: string): number {
        let retval = 0;
        const countLetters: string[] = [' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u'];
        for(const letter of text) {
            if(countLetters.includes(letter)) retval++;
        }
        return retval;
    }

    public static decodeSingleByteXor(x: Buffer): Decryption {
        const retval = new Decryption("", "");
        let bestscore = 0;
        for( let i = 0; i < 256; i++){
            const y: Buffer = Buffer.alloc(x.length).fill(i);
            const candidate: Buffer | null = this.fixedXor(x, y);
            if(candidate) {
                const possible = candidate.toString()
                const score = this.englishScore(possible);
                if(score > bestscore) {
                    bestscore = score;
                    retval.text = possible;
                    retval.key = String.fromCharCode(i);
                }
            }
        }
        return retval;
    }

    public static hammingDistance(x: Buffer, y: Buffer): number {
        let retval = 0;
        if(x.length !== y.length) {
            retval += Math.abs(x.length - y.length) * 8;  // Account for missing bytes
        }
        const len = Math.min(x.length, y.length);
        for(let i = 0; i < len; i++) {
            retval += this.bitCountLookup[x[i] ^ y[i]];
        }
        return retval;
    }

    public static getRepeatingXorKeyLength(x: Buffer): number[] {
        const hammings: number[] = [];
        const maxkeyLen = Math.floor(x.length / 4) > 40 ? 40 : Math.floor(x.length / 4)

        for(let i = 2; i < maxkeyLen; i++) {
            const blocks = this.getBlocks(x, i, 4);
            const combos = this.combinations(blocks);
            const hammingSum = combos.map(e => this.hammingDistance(e.x, e.y))
                .reduce((acc, v) => (acc + v));
            const avgHamming = (hammingSum / combos.length) / i;
            hammings.push(avgHamming)
        }

        // Return min 4 as best candidates
        const retval = hammings.map((val, idx) => ({val, idx}))
            .sort((a, b) => a.val - b.val)
            .slice(0,4).map(x => x.idx+2);
        return retval;
    }

    public static decodeRepeatingXor(x: Buffer): Decryption {
        let retval = new Decryption('','');
        const keyLength = this.getRepeatingXorKeyLength(x);
        const blockSize = Math.floor(x.length / keyLength[0]);

        for(let i = 0; i < keyLength[0]; i++) {
            const blockSlice = Buffer.alloc(blockSize);
            for(let j = 0; j < blockSize; j++) blockSlice[j] = x[(j * keyLength[0])+i];
            const recoverKey = this.decodeSingleByteXor(blockSlice);
            retval.key += recoverKey.key;
        }

        retval.text = this.repeatingKeyXor(x, retval.key).toString();
        return retval;
    }

    public static decodeRepeatingXorBruteForce(x: Buffer, maxKeylen: number): Decryption {
        let retval = new Decryption('', '');
        const possibleKeys = this.generateKeys(maxKeylen);
        let bestMatch = 0;
        for(const key of possibleKeys) {
            const text = this.repeatingKeyXor(x, key).toString();
            const score = this.englishScore(text);
            if(score > bestMatch) {
                retval.key = key;
                retval.text = text;
                bestMatch = score;
            }
        }
        return retval;
    }

    public static decodeAES128ECB(x: Buffer, key: string): Buffer {
        const aes = crypto.createDecipheriv('aes-128-ecb', Buffer.from(key), null);
        aes.setAutoPadding(true);
        const decoded = aes.update(x);
        return Buffer.concat([decoded, aes.final()]);
    }

    public static encodeAES128ECB(x: Buffer, key: string): Buffer {
        const aes = crypto.createCipheriv('aes-128-ecb', Buffer.from(key), null);
        aes.setAutoPadding(true);
        const encoded = aes.update(x);
        return Buffer.concat([encoded, aes.final()]);
    }

    public static likelyAES128ECB(x: Buffer): boolean {
        const blocks = new Map<string, Buffer>();
        for(let i = 0; i < x.length; i = i + 16) {
            const key = x.subarray(i, i+16).toString("hex");
            if(blocks.has(key)) return true;
            blocks.set(key, x.subarray(i, i+16));
        }
        return false;
    }
}