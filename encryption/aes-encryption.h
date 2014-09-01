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

#ifndef AESENCRYPTION_H
#define AESENCRYPTION_H

#include <string>

#include "cryptlib.h"
#include "secblock.h"

struct DecryptionData
{
    std::string CipherText;
    CryptoPP::SecByteBlock iv;
};

class AESEncryptor
{
    enum {TAG_SIZE = 16};
    
    public:
        static std::string Encrypt(std::string plainText, std::string keyStr);
        static std::string Decrypt(std::string cipherText, std::string keyStr);
    private:
        static CryptoPP::SecByteBlock MakeIV();
        static std::string PrependEncryptionVars(std::string encoded, 
                                                 CryptoPP::SecByteBlock iv);
        
        static DecryptionData GetDecryptionData(std::string cipherText);
};

#endif // AESENCRYPTION_H
