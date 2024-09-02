#include "pch.h"
#include "Encryption.h"



std::string Encryption::encrypt(std::string iv, std::string key, Mode mode)
{
    //not yet implemented
    return "Nc1WYnk2ULIzE0lN0ulLCimuqZRvnWtazOCNN2FyvPI0AjPW1/IX2c/wckhwmw1d";
}


/**
* Encrypt the input string using the given key and mode
* 
* @param input The input vector of unsigned chars to encrypt
* @param key The key vector of unsigned chars to use for encryption
*/
std::vector<unsigned char> Encryption::encrypt(std::vector<unsigned char>& input, std::vector<unsigned char>& key, Mode mode)
{
	std::vector<std::vector<unsigned char>> keySchedule = keyExpansion(key, mode);
	std::vector<std::vector<unsigned char>> state = convertToMatrix(input);

	cipher(state, keySchedule, mode);

    std::vector<unsigned char> ret = convertToVector(state);
	return ret;
}


std::string Encryption::decrypt(std::string iv, std::string key, Mode mode)
{
    //not yet implemented
    return "The quick brown fox jumped over the lazy dog";
}

/**
* Dencrypt the input string using the given key and mode
*
* @param input The input vector of unsigned chars to encrypt
* @param key The key vector of unsigned chars to use for encryption
*/
std::vector<unsigned char> Encryption::decrypt(std::vector<unsigned char>& input, std::vector<unsigned char>& key, Mode mode)
{
    std::vector<std::vector<unsigned char>> keySchedule = keyExpansion(key, mode);
    std::vector<std::vector<unsigned char>> state = convertToMatrix(input);

    invCipher(state, keySchedule, mode);

    std::vector<unsigned char> ret = convertToVector(state);
    return ret;
}

/**
* Print the matrix to the console
* 
* @brief The function prints the matrix to the console in a human-readable format with each byte in hexadecimal format
* and in column major order so it can be compared to the FIPS 197 AES specification
*/
void Encryption::printMatrix(std::vector<std::vector<unsigned char>>& matrix)
{
	for (int row = 0; row < 4; row++) {
		for (int col = 0; col < 4; col++) {
			std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)matrix[col][row] << " ";
		}
		std::cout << std::endl;
	}
	std::cout << std::endl;
}




/**
* Generate Cipher Text for AES encryption
* 
* @brief The function performs the Cipher Text generation for AES encryption using the input vector of unsigned chars,
* the number of rounds to perform, the key schedule to use for the encryption, and the mode to use for the encryption
* 
* @param state The state to use for the encryption
* @param keySchedule The key schedule to use for the encryption
* @param mode The mode to use for the encryption (AES128, AES192, or AES256)
* 
*/
void Encryption::cipher(std::vector<std::vector<unsigned char>>& state, std::vector<std::vector<unsigned char>>& keySchedule, Mode mode)
{
    int Nr = mode;
    int round = 0;

#ifdef _DEBUG
    std::cout << "Start of Round: " << std::endl;
    printMatrix(state);
#endif
    
    addRoundKey(state, keySchedule, round);
    round++;
    for (round; round < Nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, keySchedule, round);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, keySchedule, Nr);
}

/**
* Generate Inverse Cipher Text for AES encryption
* 
* @brief The function performs the Inverse Cipher Text generation for AES encryption using the input vector of unsigned chars,
* the number of rounds to perform, the key schedule to use for the encryption, and the mode to use for the encryption
* 
* @param state The state to use for the encryption
* @param keySchedule The key schedule to use for the encryption
* @param mode The mode to use for the encryption (AES128, AES192, or AES256)
*/
void Encryption::invCipher(std::vector<std::vector<unsigned char>>& state, std::vector<std::vector<unsigned char>>& keySchedule, Mode mode)
{
    int Nr = mode;
    int round = Nr;

#ifdef _DEBUG
    std::cout << "Start of Round: " << std::endl;
	printMatrix(state);
#endif

	addRoundKey(state, keySchedule, round);
	round--;
	for (round; round > 0; round--) {
		invShiftRows(state);
		invSubBytes(state);
		addRoundKey(state, keySchedule, round);
		invMixColumns(state);
	}
	invShiftRows(state);
	invSubBytes(state);
	addRoundKey(state, keySchedule, 0);
}


/**
* Generate the key schedule for AES encryption
* 
* @brief The function generates the key schedule for AES encryption using the input key and mode
* 
* @param key The key to use for the key schedule
* @param mode The mode to use for the key schedule (AES128, AES192, or AES256)
* @return The key schedule for the input key (vector of vectors of unsigned chars)
*/
std::vector<std::vector<unsigned char>> Encryption::keyExpansion(const std::vector<unsigned char>& key, Mode mode)
{
    int Nr = mode;
    int Nk = 0;
    //check the input key size to make sure it is correct
    switch (mode) {
    case AES128:
        if (key.size() != 16)
            throw std::invalid_argument("Key size must be 16 bytes for AES128");
        Nk = 4;
        break;
    case AES192:
        if (key.size() != 24)
            throw std::invalid_argument("Key size must be 24 bytes for AES192");
        Nk = 6;
        break;
    case AES256:
        if (key.size() != 32)
            throw std::invalid_argument("Key size must be 32 bytes for AES256");
        Nk = 8;
        break;
    default:
        throw std::invalid_argument("Invalid mode: Mode must be one of AES128, AES192, or AES256");
        break;
    }

    // Create a vector to hold the key schedule with size 4*(Nr+1)
    std::vector<std::vector<unsigned char>> w(4 * (Nr + 1), std::vector<unsigned char>(4));

    // Copy the initial key into the initial words of 'w' based on the mode
    for (int i = 0; i < Nk; i++) {
        for (int j = 0; j < 4; j++) {
            w[i][j] = key[4 * i + j];
        }
    }

    // Expand the key
    for (int i = Nk; i <= 4 * Nr + 3; i++) {
        std::vector<unsigned char> temp = w[i - 1];
        if (i % Nk == 0) {
            temp = subWord(rotWord(temp)); // Apply RotWord and SubWord
            temp[0] = temp[0] ^ Rcon[i / Nk - 1]; // XOR Rcon
        } else if (Nk > 6 && i % Nk == 4) {
            temp = subWord(temp); // Apply SubWord
        }
        for (int j = 0; j < 4; j++) {
            w[i][j] = w[i - Nk][j] ^ temp[j]; // XOR with the word Nk positions earlier
        }
    }
    return w;
}

/**
* Add the round key to the state
* 
* @brief The function adds the round key to the state by XORing the round key with the state
* 
* @param state The state to add the round key to
* @param key The key to add to the state
* @param round The round to add the key for
*/
void Encryption::addRoundKey(std::vector<std::vector<unsigned char>>& state, std::vector<std::vector<unsigned char>>& key, int round)
{
#ifdef _DEBUG
    std::cout << "Round Key Value: " << std::endl;
    //build matrix key[ 4 * round .. 4 * round + 3]
    std::vector<std::vector<unsigned char>> keyMatrix(4, std::vector<unsigned char>(4, 0));
    for (int col = 0; col < 4; col++) {
		for (int row = 0; row < 4; row++) {
			keyMatrix[col][row] = key[4 * round + col][row];
		}
	}
    printMatrix(keyMatrix);
#endif

    for (int col = 0; col < 4; col++) 
    {
        for (int row = 0; row < 4; row++) 
		{
			state[col][row] = state[col][row] ^ key[4 * round + col][row];
		}
    }

#ifdef _DEBUG
    std::cout << "Start of Round: " << std::endl;
    printMatrix(state);
#endif
}


/**
* Shift the rows in the state
*
* @brief The function shifts the rows in the state by a certain number of bytes
* The first row is not shifted
* The second row is shifted by 1 byte to the left
* The third row is shifted by 2 bytes to the left
* The fourth row is shifted by 3 bytes to the left
*
* @param state The state to shift the rows for
*/
void Encryption::shiftRows(std::vector<std::vector<unsigned char>>& state)
{
    std::vector<unsigned char> temp(4);
    for (int row = 1; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            temp[col] = state[(col + row) % 4][row];
        }
        for (int col = 0; col < 4; col++) {
            state[col][row] = temp[col];
        }
    }

#ifdef _DEBUG
    std::cout << "After Shift rows: " << std::endl;
    printMatrix(state);
#endif
}

/**
* Inverse Shift the rows in the state
* 
* @brief the inverse of shiftRows (see above)
* 
* @param state The state to shift the rows for
*/
void Encryption::invShiftRows(std::vector<std::vector<unsigned char>>& state)
{
    std::vector<unsigned char> temp(4);
	for (int row = 1; row < 4; row++) {
		for (int col = 0; col < 4; col++) {
			temp[(col + row) % 4] = state[col][row];
		}
		for (int col = 0; col < 4; col++) {
			state[col][row] = temp[col];
		}
	}

#ifdef _DEBUG
    std::cout << "After Inv Shift rows: " << std::endl;
    printMatrix(state);
#endif
}



/**
* Substitute the bytes in the state using the SBox
* 
* @brief The function substitutes the bytes in the state using the SBox
* The SBox is a 16x16 matrix that substitutes each byte in the state with a new byte.
* The new byte is determined by splitting the byte into two parts and using the SBox to get the new value
* The upper 4 bits of the byte are used to get the row and the lower 4 bits are used to get the column
* 
* @param state The state to substitute the bytes for
*/
void Encryption::subBytes(std::vector<std::vector<unsigned char>>& state)
{
    for (int col = 0; col < 4; col++) 
	{
		for (int row = 0; row < 4; row++) 
		{
			state[col][row] = subByte(state[col][row]);
		}
	}

#ifdef _DEBUG
    std::cout << "After Sub bytes: " << std::endl;
	printMatrix(state);
#endif
}

/**
* Inverse Substitute the bytes in the state using the inverse SBox
* 
* @brief The inverse of subBytes (see above)
* 
* @param state The state to substitute the bytes for
*/
void Encryption::invSubBytes(std::vector<std::vector<unsigned char>>& state)
{
	for (int col = 0; col < 4; col++) {
		for (int row = 0; row < 4; row++) {
			state[col][row] = invSubByte(state[col][row]);
		}
	}

#ifdef _DEBUG
	std::cout << "After Inv Sub bytes: " << std::endl;
	printMatrix(state);
#endif
}


/**
* Mix the columns in the state
* 
* @brief The function mixes the columns in the state by multiplying the columns by a fixed matrix
* The matrix is fixed and is used to mix the columns in the state. The columns are multiplied by the matrix
* to get the new value for each byte in the column. 
* 
* Galios Field Matrix:
* | 02 03 01 01 |
* | 01 02 03 01 |
* | 01 01 02 03 |
* | 03 01 01 02 |
* 
* See page 8, 9 & 15 of the FIPS 197 AES specification for more details
* 
* @param state The state to mix the columns for
* 
*/
void Encryption::mixColumns(std::vector<std::vector<unsigned char>>& state)
{
    unsigned char temp[4];
    for (int col = 0; col < 4; col++) {  // iterate over each column
        temp[0] = xTimes(state[col][0], 0x02) ^ xTimes(state[col][1], 0x03) ^ state[col][2] ^ state[col][3];
        temp[1] = state[col][0] ^ xTimes(state[col][1], 0x02) ^ xTimes(state[col][2], 0x03) ^ state[col][3];
        temp[2] = state[col][0] ^ state[col][1] ^ xTimes(state[col][2], 0x02) ^ xTimes(state[col][3], 0x03);
        temp[3] = xTimes(state[col][0], 0x03) ^ state[col][1] ^ state[col][2] ^ xTimes(state[col][3], 0x02);

        for (int row = 0; row < 4; row++) {
            state[col][row] = temp[row];
        }
    }

#ifdef _DEBUG
    std::cout << "After Mix columns: " << std::endl;
    printMatrix(state);
#endif
}


/**
* Inverse Mix the columns in the state
* 
* @brief The inverse of mixColumns (see above)
* 
* @param state The state to mix the columns for
*/
void Encryption::invMixColumns(std::vector<std::vector<unsigned char>>& state)
{
    unsigned char temp[4];
	for (int col = 0; col < 4; col++) {  // iterate over each column
		temp[0] = xTimes(state[col][0], 0x0E) ^ xTimes(state[col][1], 0x0B) ^ xTimes(state[col][2], 0x0D) ^ xTimes(state[col][3], 0x09);
		temp[1] = xTimes(state[col][0], 0x09) ^ xTimes(state[col][1], 0x0E) ^ xTimes(state[col][2], 0x0B) ^ xTimes(state[col][3], 0x0D);
		temp[2] = xTimes(state[col][0], 0x0D) ^ xTimes(state[col][1], 0x09) ^ xTimes(state[col][2], 0x0E) ^ xTimes(state[col][3], 0x0B);
		temp[3] = xTimes(state[col][0], 0x0B) ^ xTimes(state[col][1], 0x0D) ^ xTimes(state[col][2], 0x09) ^ xTimes(state[col][3], 0x0E);

		for (int row = 0; row < 4; row++) {
			state[col][row] = temp[row];
		}
	}

#ifdef _DEBUG
    std::cout << "After Inv Mix columns: " << std::endl;
	printMatrix(state);
#endif
}

/**
* Rotate the word
* 
* @brief The function rotates the word by shifting the bytes to the left
* The first byte is moved to the end of the word and the rest of the bytes are shifted to the left
* 
* @param word The word to rotate
*/
std::vector<unsigned char> Encryption::rotWord(std::vector<unsigned char>& word)
{
    std::vector<unsigned char> rotatedWord = word;
    std::rotate(rotatedWord.begin(), rotatedWord.begin() + 1, rotatedWord.end());
    return rotatedWord;
}

// SubWord function: Applies S-box substitution to each byte of the input word.

/**
* Substitute the bytes in a given word using the SBox
*
* @brief The function substitutes the bytes in the state using the SBox
* The SBox is a 16x16 matrix that substitutes each byte in the state with a new byte.
* The new byte is determined by splitting the byte into two parts and using the SBox to get the new value
* The upper 4 bits of the byte are used to get the row and the lower 4 bits are used to get the column
*
* @param state The word to substitute the bytes for
*/

std::vector<unsigned char> Encryption::subWord(const std::vector<unsigned char>& word)
{
    std::vector<unsigned char> subbedWord(word.size());
    for (size_t i = 0; i < word.size(); i++) {
        subbedWord[i] = SBox[word[i]]; // Substitute each byte using the S-box
    }
    return subbedWord;
}

/**
* Pad the last block with PKCS7 padding
* 
* @brief The function pads the last block with PKCS7 padding to make it a multiple of the block size. PCKS7 padding
* is a method to pad the last block of a plaintext to make it a multiple of the block size. All padding bytes have the same
* value as the number of padding bytes required to make the block a multiple of the block size
* 
* @param ret A reference to the vector of strings to pad
* @param splitLength A reference to the split length
*/
void Encryption::padblock(std::vector<std::string>& ret, int& splitLength)
{
    // Pad the last block with PKCS7 padding
    if (ret.back().size() < splitLength) {
        size_t padding = splitLength - ret.back().size();
        ret.back().append(padding, static_cast<char>(padding));
    }
}

/**
* Split the string into 16 byte blocks (128 bits)
* 
* @brief The function splits the string into 16 byte blocks (128 bits) and pads the last block with PKCS7 padding
* to make it a multiple of the block size
* 
* @param str The string to split
* @param splitLength The length to split the string into (default is 16)
* @return The vector of strings with the string split into 16 byte blocks (128 bits)
*/
std::vector<std::string> Encryption::split(const std::string& str, int splitLength)
{
    if (splitLength <= 0) {
        throw std::invalid_argument("splitLength must be greater than 0");
    }

    std::vector<std::string> ret;
    size_t size = str.size();
    ret.reserve((size + splitLength - 1) / splitLength);

    for (size_t i = 0; i < size; i += splitLength) {
        ret.push_back(str.substr(i, splitLength));
    }

    // Pad the last block with PKCS7 padding
    padblock(ret, splitLength);

    return ret;
}


/**
* Convert a string into matrices of 16 bytes in column major order
* 
* @brief The function takes a string and converts it into matrices of 16 bytes in column major order
* 
* @param str The string to convert
* @return The matrices of 16 bytes in column major order (vector of vectors of vectors of unsigned chars)
*/
std::vector<std::vector<std::vector<unsigned char>>> Encryption::convertTo16ByteArrays(const std::string& str)
{
    std::vector<std::string> splitStr = split(str, 16);

    std::vector<std::vector<std::vector<unsigned char>>> ret;

    for (size_t i = 0; i < splitStr.size(); ++i) {
        ret.push_back(convertToMatrix(std::vector<unsigned char>(splitStr[i].begin(), splitStr[i].end())));
    }
    return ret;
}


/**
* Convert a 16 byte vector of unsigned chars into a 4*4 column major order matrix
* 
* @brief The function takes a 16 byte vector of unsigned chars and converts it into a 4*4 column major order matrix
* 
* @param in The 16 byte vector of unsigned chars
* @return The 4*4 column major order matrix (vector of vectors of unsigned chars)
*/
std::vector<std::vector<unsigned char>> Encryption::convertToMatrix(std::vector<unsigned char> in)
{
    // change the above to column major order
    std::vector<std::vector<unsigned char>> ret(4);
    for (int col = 0; col < 4; col++) {
        ret[col].reserve(4);
        for (int row = 0; row < 4; row++) {
            ret[col].push_back(in[col * 4 + row]); //TODO: check why this is warning
        }
    }
#ifdef DEBUG
    printMatrix(ret);
#endif
    return ret;
}

std::vector<unsigned char> Encryption::convertToVector(std::vector<std::vector<unsigned char>> in)
{
    std::vector<unsigned char> ret(16);
	for (int col = 0; col < 4; col++) {
		for (int row = 0; row < 4; row++) {
			ret[col * 4 + row] = in[col][row];
		}
	}
	return ret;


}



/**
* Get the value from the SBox for the given byte.
* 
* @brief The value is determined by splitting the byte into two parts and using the SBox to get the new value
* The upper 4 bits of the byte are used to get the row and the lower 4 bits are used to get the column
* 
* @param byte The byte to get the value for (unsigned char)
* @return The value from the SBox for the given byte
*/
unsigned char Encryption::subByte(unsigned char byte)
{
    //split byte into two parts
    unsigned char upper = (byte >> 4) & 0x0F;
    unsigned char lower = byte & 0x0F;

    //get the new value from the SBox
    return SBox[upper * 16 + lower];
}


/**
* Get the value from the inverse SBox for the given byte.
* 
* @brief The value is determined by splitting the byte into two parts and using the inverse SBox to get the new value
* The upper 4 bits of the byte are used to get the row and the lower 4 bits are used to get the column
* 
* @param byte The byte to get the value for (unsigned char)
* @return The value from the inverse SBox for the given byte
*/
unsigned char Encryption::invSubByte(unsigned char byte)
{
	//split byte into two parts
	unsigned char upper = (byte >> 4) & 0x0F;
	unsigned char lower = byte & 0x0F;

	//get the new value from the inverse SBox
	return InvSBox[upper * 16 + lower];
}


/**
* Double the byte in the Galois Field (GF(2^8))
* 
* @brief The function doubles the byte by multiplying it by 2 in the Galois Field (GF(2^8))
* which is equivalent to shifting the byte left by 1 and XORing with 0x1B if the high bit is set
* 
* @param byte The byte to double (unsigned char)
* @return The doubled byte (unsigned char)
*/
unsigned char Encryption::xTime(unsigned char byte)
{
    return (byte << 1) ^ ((byte & 0x80) ? 0x1B : 0x00);
 
}


/**
* Multiply two bytes in the Galois Field (GF(2^8))
* 
* @brief The function multiplies two bytes in the Galois Field (GF(2^8))
* to get the product of the two bytes. The multiplication is done by
* multiplying the two bytes as polynomials and reducing the result modulo
* the irreducible polynomial x^8 + x^4 + x^3 + x + 1
* 
* @param a The first byte to multiply (unsigned char)
* @param b The second byte to multiply (unsigned char) - The coefficient from the galois field
*/
unsigned char Encryption::xTimes(unsigned char byte, unsigned char coefficient) {
    
    if (coefficient == 0) {
        return 0; // Multiplication by 0 in any field is 0
    }
    else if (coefficient == 1) {
        return byte;
    }

    unsigned char result = 0;
    while (coefficient > 0) {
        if (coefficient % 2 == 1) { // Check if the lowest bit is 1
            result ^= byte; // Add (XOR) the current power of xTime to result
        }
        byte = xTime(byte); // Double the byte (multiply by {02})
        coefficient >>= 1; // Shift the coefficient right to divide by 2
    }
    return result;
}
