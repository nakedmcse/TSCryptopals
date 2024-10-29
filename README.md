# TSCryptopals
This contains a typescript implementation of the cryptopals set 1 challenges.  It has been implemented
as a library containing the functions, as set of vitest tests for the library and a program (set1) which 
answers the questions.

## Library

The library contains the functions necessary for the questions.

### readFile
This reads a given file into a line array.

### combinations
This returns a list of all x,y combinations of items from a given list.

### getBlocks
This returns a list of blocks of a given block size extracted from a given Buffer.
An option maximum number of blocks to return can also be specified.

### hexToBase64
This takes a given hex string and returns the base64 encoded version of it.

### fixedXor
This takes two given Buffers and if they are the same length it returns a buffer which is the result of xoring them.
If they are differing lengths, null is returned.

### repeatingKeyXor
This takes a given buffer and a key string and returns a buffer which is repeating xored with the key.

### englishFreqDiff
This takes a string and returns a number showing how far it varies from the normal distribution of characters for english.
Larger numbers mean less likely to be english.

### englishScore
This takes a string and returns a number counting how many common english characters are in it.
Larger numbers mean more likely to be english.

### decodeSingleByteXor
This takes a buffer and brute force tries every single byte to decode.  It returns the decoded text and key,
based on the best english score.

### hammingDistance
This takes two buffers and returns a number equal to the differing number of bits between the two.

### getRepeatingXorKeyLength
This takes a buffer and returns the top four most likely key lengths for repeating Xor.
> **NOTE WELL:**
> 
>This is based on statistical analysis and is inacurate for key lengths below 10 characters.

###  decodeRepeatingXor
This takes a buffer and returns the most likely decrypted text and key for repeating Xor.
> **NOTE WELL:**
>
>This is based on statistical analysis and is inacurate for key lengths below 10 characters or over 40 characters.

### decodeAES128ECB
This takes an AES 128 ECB encrypted buffer and a string as a key, and returns an decrypted buffer.

### encodeAES128ECB
This takes a buffer and a string as a key, and returns an AES 128 ECB encrypted buffer.

### likelyAES128ECB
This takes a buffer and returns a boolean indicating true if it is likely AES 128 ECB encrypted.
> **NOTE WELL:**
> 
> This is based on looking for repeating blocks, so the original text must also have repeating sets of characters in it
