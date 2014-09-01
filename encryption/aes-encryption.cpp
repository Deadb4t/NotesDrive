/*
 * NotesDrive: Encrypted remote note storage.
 * Copyright (C) 2014  Deadb4t Deadb4t@googlemail.com
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#include "aes-encryption.h"

#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include "hex.h"
#include "cryptlib.h"
#include "filters.h"
#include "aes.h"
#include "gcm.h"
#include "assert.h"
#include "secblock.h"
#include "osrng.h"

#include "utils-encryption.h"

using namespace std;
using namespace CryptoPP;

std::string AESEncryptor::Encrypt(std::string plainText, std::string keyStr)
{
    SecByteBlock key = UtilsEncryption::HexToBytes(keyStr);
    SecByteBlock iv = MakeIV();
    GCM< AES >::Encryption encryptor;
    encryptor.SetKeyWithIV(key.BytePtr(),
                           key.SizeInBytes(),
                           iv.BytePtr(),
                           iv.SizeInBytes());
    string cipher, encoded;
    StringSource( plainText, true,
        new AuthenticatedEncryptionFilter( encryptor,
            new StringSink( cipher ), false, TAG_SIZE
        )
    );
    encoded = UtilsEncryption::EncodeToHex(cipher); 
    encoded = PrependEncryptionVars(encoded, iv);
    return encoded;
    
}

SecByteBlock AESEncryptor::MakeIV()
{
    const unsigned int IVSIZE = AES::BLOCKSIZE;
    byte ivScratch[ IVSIZE ];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock( ivScratch, IVSIZE );
    SecByteBlock iv(IVSIZE);
    CryptoPP::ArraySource ss(ivScratch, sizeof(ivScratch), true,
        new CryptoPP::ArraySink(iv, sizeof(iv)
            )
    );
    return iv;
}
string AESEncryptor::PrependEncryptionVars(string encoded, SecByteBlock iv)
{
    string ivHex = UtilsEncryption::BytesToHex(iv);
    SecByteBlock ivBB = UtilsEncryption::HexToBytes(ivHex);
    encoded = ivHex + "\n" + encoded;
    return encoded;
}



std::string AESEncryptor::Decrypt(std::string cipherText, std::string keyStr)
{
    SecByteBlock key = UtilsEncryption::HexToBytes(keyStr);
    string plainText = "";
    string retrieved;
    try
    {
        DecryptionData decryptionData = GetDecryptionData(cipherText);
        GCM< AES >::Decryption decryptor;
        decryptor.SetKeyWithIV(key.BytePtr(),
                               key.SizeInBytes(),
                               decryptionData.iv.BytePtr(), 
                               decryptionData.iv.SizeInBytes());
        AuthenticatedDecryptionFilter decryptionFilter( decryptor,
            new StringSink( retrieved ),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE);
            StringSource( decryptionData.CipherText, true,
                new Redirector( decryptionFilter ));
        bool b = decryptionFilter.GetLastResult();
        if(b)
        {
            plainText = retrieved;
        }
        else
        {
            throw runtime_error("Failed to retrive plain text.");
        }
    }
    catch(std::exception &e)
    {
        throw runtime_error(e.what());
    }
    return plainText;
}

DecryptionData AESEncryptor::GetDecryptionData(string cipherText)
{
    string ivStr;
    string AAData;
    stringstream msgReader(cipherText);
    getline(msgReader, ivStr);
    string strippedCipherText = "";
    getline(msgReader, strippedCipherText);
    DecryptionData decryptionData;
    decryptionData.CipherText = UtilsEncryption::DecodeFromHex(strippedCipherText);
    decryptionData.iv = UtilsEncryption::HexToBytes(ivStr);
    string ivCheck = UtilsEncryption::BytesToHex(decryptionData.iv);
    return decryptionData;
}