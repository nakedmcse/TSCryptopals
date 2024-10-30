// Cryptopals Tests
import {CryptoPals, Decryption} from "./tsCryptopalsLib";
import fs from "node:fs/promises";
import {afterEach, describe, expect, it, vi} from "vitest";

describe("unit tests", () => {
    afterEach(() => {
        vi.clearAllMocks();
    });

    describe("Section 1", () => {
        it("readFile: Return array of lines", async () => {
            vi.mock("node:fs/promises", () => {
                return {
                    default: {
                        readFile: vi.fn().mockResolvedValue("line 1\nline 2\nline 3")
                    }
                }
            });

            const fileLines = await CryptoPals.readFile("/some/path/file.txt");

            expect(fileLines).toEqual(["line 1", "line 2", "line 3"]);
            expect(fs.readFile).toHaveBeenCalledWith("/some/path/file.txt", "utf-8");
        })

        it("generateKeys: Return all 2 char key combinations", () => {
            const retval = CryptoPals.generateKeys(2);
            expect(retval.includes("A")).toEqual(true);
            expect(retval.includes("ZZ")).toEqual(true);
            expect(retval.length).toEqual(2**16);
        })

        it("combinations: Return a list of combinations", () => {
            const testList: Array<string> = ['a', 'b', 'c', 'd'];
            const retval = CryptoPals.combinations(testList);
            expect(retval.length).toEqual(6);
        })

        it("getBlocks: Return a list of blocks", () => {
            const testBuffer = Buffer.from("123456789");
            const retval = CryptoPals.getBlocks(testBuffer, 3);
            expect(retval.length).toEqual(3);
        })

        it("getBlocks: Return first two of a list of blocks", () => {
            const testBuffer = Buffer.from("123456789");
            const retval = CryptoPals.getBlocks(testBuffer, 3, 2);
            expect(retval.length).toEqual(2);
        })

        it("hexToBase64: Return SSdt...b29t", () => {
            const retval = CryptoPals.hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
            expect(retval).toEqual("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        })

        it("fixedXor: Return xored buffer", () => {
            const x = Buffer.from("1c0111001f010100061a024b53535009181c", "hex");
            const y = Buffer.from("686974207468652062756c6c277320657965", "hex");
            const retval = CryptoPals.fixedXor(x, y);
            expect(retval).toEqual(Buffer.from("746865206b696420646f6e277420706c6179", "hex"));
        })

        it("englishFreqDiff: Return English line",() => {
            const english: string = "The quick brown fox jumped over the lazy hen";
            const garbage: string = "xbh bnofepioj bhhfhehi hnnghwyugebiw sgbg ssx";
            const englishScore: number = CryptoPals.englishFreqDiff(english);
            const garbageScore: number = CryptoPals.englishFreqDiff(garbage);
            expect(englishScore).toBeLessThan(garbageScore);
        })

        it("englishScore: Return English line",() => {
            const english: string = "The quick brown fox jumped over the lazy hen";
            const garbage: string = "xbh bnofepioj bhhfhehi hnnghwyugebiw sgbg ssx";
            const englishScore: number = CryptoPals.englishScore(english);
            const garbageScore: number = CryptoPals.englishScore(garbage);
            expect(garbageScore).toBeLessThan(englishScore);
        })

        it("decodeSingleByteXor: Return english line and key", () => {
            const testBuffer = Buffer.from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", "hex");
            const decoded: Decryption = CryptoPals.decodeSingleByteXor(testBuffer);
            expect(decoded.text).toEqual("Cooking MC's like a pound of bacon");
            expect(decoded.key).toEqual("X");
        })

        it("repeatingKeyXor: Return encrypted and decrypted buffer", () => {
            const line = Buffer.from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
            const encoded = CryptoPals.repeatingKeyXor(line, "ICE");
            const decoded = CryptoPals.repeatingKeyXor(encoded, "ICE");
            expect(encoded.toString("hex")).toEqual("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
            expect(decoded.toString()).toEqual("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
        })

        it("hammingDistance: Return 37 for given strings", () => {
            const hamming = CryptoPals.hammingDistance(Buffer.from("this is a test"), Buffer.from("wokka wokka!!!"));
            expect(hamming).toEqual(37);
        })

        it("getRepeatingXorKeyLength: Return matching key length", () => {
            const line = Buffer.from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
            const encoded = CryptoPals.repeatingKeyXor(line, "ICEBABY123");
            const recoveredKeyLength = CryptoPals.getRepeatingXorKeyLength(encoded);
            expect(recoveredKeyLength[0]).toEqual(10);
        })

        it("decodeRepeatingXorBruteForce: Return english text and key for short key", () => {
            const line = Buffer.from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
            const encoded = CryptoPals.repeatingKeyXor(line, "IC");
            const decoded = CryptoPals.decodeRepeatingXorBruteForce(encoded, 2);
            expect(decoded.text).toEqual("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
            expect(decoded.key).toEqual("IC");
        })

        it("encodeAES128ECB: Returns given hex for phrase",  () => {
            const phrase = Buffer.from("You may take our lives, but you'll never take our freedom!");
            const encoded = CryptoPals.encodeAES128ECB(phrase, "YELLOW SUBMARINE");
            expect(encoded.toString("hex")).toEqual("3bbe4d8bdc321f28fadf89e20a722d491a79d2517ddefcf3d49055b120e5b6b9d55d814cf7d035377bc4a87da0afdf55db6c42340a2873e99962dcbd659f4a1e");
        })

        it("decodeAES128ECB: Returns phrase for given hex", () => {
            const encoded = Buffer.from("3bbe4d8bdc321f28fadf89e20a722d491a79d2517ddefcf3d49055b120e5b6b9d55d814cf7d035377bc4a87da0afdf55db6c42340a2873e99962dcbd659f4a1e", "hex");
            const decoded = CryptoPals.decodeAES128ECB(encoded, "YELLOW SUBMARINE");
            expect(decoded.toString()).toEqual("You may take our lives, but you'll never take our freedom!")
        })

        it("likelyAES128ECB: Returns true for encoded text", () => {
            const phrase = Buffer.from("This is a test!!This is a test!!");
            const encoded = CryptoPals.encodeAES128ECB(phrase, "YELLOW SUBMARINE");
            expect(CryptoPals.likelyAES128ECB(encoded)).toEqual(true);
        })

    })
})