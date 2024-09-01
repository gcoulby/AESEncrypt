#include "pch.h"
#include "CppUnitTest.h"
#include "Encryption.h"
#include <iostream>
#include <iomanip>


using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace AESEncryptionTest
{
	TEST_CLASS(AESEncryptionTesting)
	{
	public:
		
		TEST_METHOD(EncryptionIsCorrect)
		{
			std::string key = "supersecretkey";
			std::string iv = "The quick brown fox jumped over the lazy dog";
			std::string expected = "Nc1WYnk2ULIzE0lN0ulLCimuqZRvnWtazOCNN2FyvPI0AjPW1/IX2c/wckhwmw1d";

			std::string encrypted = Encryption::encrypt(iv, key);
			Assert::AreEqual(expected, encrypted);
		}

		TEST_METHOD(DecryptionIsCorrect)
		{
			std::string key = "supersecretkey";
			std::string iv = "Nc1WYnk2ULIzE0lN0ulLCimuqZRvnWtazOCNN2FyvPI0AjPW1/IX2c/wckhwmw1d";
			std::string expected = "The quick brown fox jumped over the lazy dog";

			std::string decrypted = Encryption::decrypt(iv, key);
			Assert::AreEqual(expected, decrypted);
		}

		TEST_METHOD(SplitIsCorrect)
		{
			std::string str = "The quick brown fox jumped over the lazy dog";

			std::vector<std::string> actual = Encryption::split(str,16);

			std::vector<std::string> expected = {
				{'T', 'h', 'e', ' ', 'q', 'u', 'i', 'c', 'k', ' ', 'b', 'r', 'o', 'w', 'n', ' ',},
				{'f', 'o', 'x', ' ', 'j', 'u', 'm', 'p', 'e', 'd', ' ', 'o', 'v', 'e', 'r', ' ',},
				{'t', 'h', 'e', ' ', 'l', 'a', 'z', 'y', ' ', 'd', 'o', 'g', 0x04, 0x04, 0x04, 0x04} //PKCS7 padding 
			};

			for (size_t i = 0; i < actual.size(); ++i) {
				Assert::AreEqual(expected[i], actual[i], L"String elements do not match.");
				Assert::IsTrue(actual[i].size() % 16 == 0, L"The split string is not a multiple of 16.");
			}
		}

		TEST_METHOD(ConvertToMatrixIsCorrect)
		{
			const std::string inputStr = "The quick brown fox jumped over the lazy dog";

			//convert to column-major
			std::vector<std::vector<std::vector<unsigned char>>> expected =
			{
				{
					{ 'T', 'h', 'e', ' ' },
					{ 'q', 'u', 'i', 'c' },
					{ 'k', ' ', 'b', 'r' },
					{ 'o', 'w', 'n', ' ' }
				},
				{
					{ 'f', 'o', 'x', ' ' },
					{ 'j', 'u', 'm', 'p' },
					{ 'e', 'd', ' ', 'o' },
					{ 'v', 'e', 'r', ' ' }
				},
				{
					{ 't', 'h', 'e', ' ' },
					{ 'l', 'a', 'z', 'y' },
					{ ' ', 'd', 'o', 'g' },
					{ 0x04, 0x04, 0x04, 0x04 }
				}
			};

			std::vector<std::vector<std::vector<unsigned char>>> byteArray = Encryption::convertTo16ByteArrays(inputStr);

			for (size_t i = 0; i < byteArray.size(); ++i) {
				for (size_t j = 0; j < byteArray[i].size(); ++j) {
					for (size_t k = 0; k < byteArray[i][j].size(); ++k) {
						Assert::AreEqual(expected[i][j][k], byteArray[i][j][k], L"Byte elements do not match.");
					}
				}
			}

		}


		TEST_METHOD(RoundKeySubstitutionSuccessful)
		{
			const std::string inputStr = "The quick brown fox jumped over the lazy dog";
			std::vector<std::vector<std::vector<unsigned char>>> inV = Encryption::convertTo16ByteArrays(inputStr);

			std::vector<std::vector<unsigned char>> state = inV[0];

			std::vector<unsigned char> key = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

			std::vector<std::vector<unsigned char>> keySchedule = Encryption::keyExpansion(key, AES256);
			

			int Nr = AES256;
			int round = 0;

			Encryption::addRoundKey(state, keySchedule, round);

			std::vector<std::vector<unsigned char>> expected = {
				{ 0x34, 0x55, 0x8E, 0x30 },
				{ 0x64, 0xBF, 0x18, 0xDD },
				{ 0x40, 0x53, 0xCC, 0x82 },
				{ 0xEA, 0x0A, 0x19, 0xA1 }
			};

			for (size_t i = 0; i < state.size(); ++i) {
				for (size_t j = 0; j < state[i].size(); ++j) {
					Assert::AreEqual(expected[i][j], state[i][j], L"Byte elements do not match.");
				}
			}
		}


		TEST_METHOD(CorrectValuesChosenFromSBox)
		{
			unsigned char input = 0x63;

			unsigned char expected = 0xFB;

			unsigned char actual = Encryption::subByte(input);

			Assert::AreEqual(expected, actual, L"Byte elements do not match.");
		}

		TEST_METHOD(CorrectlyShiftedRows)
		{
			std::vector<std::vector<unsigned char>> state = {
				{ 0xD4, 0x27, 0x11, 0xAE},
				{ 0xE0, 0xBF, 0x98, 0xF1},
				{ 0xB8, 0xB4, 0x5D, 0xE5},
				{ 0x1E, 0x41, 0x52, 0x30}
			};

			Encryption::shiftRows(state);

			std::vector<std::vector<unsigned char>> expected = {
				{ 0xD4, 0xBF, 0x5D, 0x30 },
				{ 0xE0, 0xB4, 0x52, 0xAE },
				{ 0xB8, 0x41, 0x11, 0xF1 },
				{ 0x1E, 0x27, 0x98, 0xE5 }
			};

			for (size_t i = 0; i < state.size(); ++i) {
				for (size_t j = 0; j < state[i].size(); ++j) {
					Assert::AreEqual(expected[i][j], state[i][j], L"Byte elements do not match.");
				}
			}
		}

		TEST_METHOD(CorrectlyMixedColumns)
		{
			std::vector<std::vector<unsigned char>> state = {
				{ 0xD4, 0xBF, 0x5D, 0x30 },
				{ 0xE0, 0xB4, 0x52, 0xAE },
				{ 0xB8, 0x41, 0x11, 0xF1 },
				{ 0x1E, 0x27, 0x98, 0xE5 }

			};
			std::vector<std::vector<unsigned char>> state2 = state;

			Encryption::mixColumns(state);

			std::vector<std::vector<unsigned char>> expected = {
				{ 0x04, 0x66, 0x81, 0xE5 },
				{ 0xE0, 0xCB, 0x19, 0x9A },
				{ 0x48, 0xF8, 0xD3, 0x7A },
				{ 0x28, 0x06, 0x26, 0x4C }
				
			};

			for (size_t i = 0; i < state.size(); ++i) {
				for (size_t j = 0; j < state[i].size(); ++j) {
					Assert::AreEqual(expected[i][j], state[i][j], L"Byte elements do not match.");
				}
			}
		}

		TEST_METHOD(CorrectCipherCreated)
		{
			std::vector<unsigned char> input = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
			std::vector<unsigned char> key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

			std::vector<std::vector<unsigned char>> keySchedule = Encryption::keyExpansion(key, AES128);

			std::vector<std::vector<unsigned char>> state = Encryption::convertToMatrix(input);

			Encryption::cipher(state, keySchedule, AES128);

			std::vector<unsigned char> expected = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
			std::vector<unsigned char> actual = Encryption::convertToVector(state);

			for (size_t i = 0; i < actual.size(); ++i) {
				Assert::AreEqual(expected[i], actual[i], L"Byte elements do not match.");
			}
		}

		TEST_METHOD(CorrectInverseCipherCreated)
		{
			std::vector<unsigned char> input = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
			std::vector<unsigned char> key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

			std::vector<std::vector<unsigned char>> keySchedule = Encryption::keyExpansion(key, AES128);

			std::vector<std::vector<unsigned char>> state = Encryption::convertToMatrix(input);

			Encryption::invCipher(state, keySchedule, AES128);

			std::vector<unsigned char> expected = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

			std::vector<unsigned char> actual = Encryption::convertToVector(state);

			for (size_t i = 0; i < actual.size(); ++i) {
				Assert::AreEqual(expected[i], actual[i], L"Byte elements do not match.");
			}
		}
	};
}
