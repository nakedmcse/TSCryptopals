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

        it("decodeSingleByteXor: Return english line and key", () => {
            const testBuffer = Buffer.from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", "hex");
            const decoded: Decryption = CryptoPals.decodeSingleByteXor(testBuffer);
            expect(decoded.text).toEqual("Cooking MC's like a pound of bacon");
            expect(decoded.key).toEqual("X");
        })

        it("repeatingKeyXor: Return encrypted buffer", () => {
            const line = Buffer.from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
            const encoded = CryptoPals.repeatingKeyXor(line, "ICE");
            expect(encoded.toString("hex")).toEqual("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
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
    })
})