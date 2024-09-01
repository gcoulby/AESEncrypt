#include "pch.h"
#include "CppUnitTest.h"
#include "Encryption.h"
#include <iostream>
#include <iomanip>


using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace AESEncryptionTest
{
	TEST_CLASS(KeyExpansionTesting)
	{
	public:
		TEST_METHOD(AES128KeyExpansionIsCorrect)
		{
			std::vector<unsigned char> key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

			std::vector<std::vector<unsigned char>> expandedKey = Encryption::keyExpansion(key, AES128);

			//expected final word
			std::vector<unsigned char> expectedFinalWord = { 0xB6, 0x63, 0x0C, 0xA6 };

			//expected expanded key
			Assert::AreEqual((int)expandedKey.size(), 44, L"Expanded key size is not correct.");
			Assert::AreEqual((int)expandedKey[43].size(), 4, L"Expanded key final word size is not correct.");

			for (size_t i = 0; i < expandedKey[43].size(); ++i)
			{
				Assert::AreEqual(expectedFinalWord[i], expandedKey[43][i], L"Expanded key final word is not correct.");
			}
		}

		TEST_METHOD(AES192KeyExpansionIsCorrect)
		{
			std::vector<unsigned char> key = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };

			std::vector<std::vector<unsigned char>> expandedKey = Encryption::keyExpansion(key, AES192);

			//expected final word
			std::vector<unsigned char> expectedFinalWord = { 0x01, 0x00, 0x22, 0x02 };

			//expected expanded key
			Assert::AreEqual((int)expandedKey.size(), 52, L"Expanded key size is not correct.");
			Assert::AreEqual((int)expandedKey[51].size(), 4, L"Expanded key final word size is not correct.");

			for (size_t i = 0; i < expandedKey[51].size(); ++i)
			{
				Assert::AreEqual(expectedFinalWord[i], expandedKey[51][i], L"Expanded key final word is not correct.");
			}
		}

		TEST_METHOD(AES256KeyExpansionIsCorrect)
		{
			std::vector<unsigned char> key = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

			std::vector<std::vector<unsigned char>> expandedKey = Encryption::keyExpansion(key, AES256);

			//expected final word
			std::vector<unsigned char> expectedFinalWord = { 0x70, 0x6C, 0x63, 0x1E };

			//expected expanded key
			Assert::AreEqual((int)expandedKey.size(), 60, L"Expanded key size is not correct.");
			Assert::AreEqual((int)expandedKey[59].size(), 4, L"Expanded key final word size is not correct.");

			for (size_t i = 0; i < expandedKey[59].size(); ++i)
			{
				Assert::AreEqual(expectedFinalWord[i], expandedKey[59][i], L"Expanded key final word is not correct.");
			}
		}
	};

}