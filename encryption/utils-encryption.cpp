/*
 * NotesDrive Server: Encrypted remote note storage.
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

#include "utils-encryption.h"

#include <string>
#include <iostream>

#include <hex.h>
#include <filters.h>
#include <secblock.h>

using namespace std;

std::string UtilsEncryption::EncodeToHex(std::string toEncode)
{
    string encoded = "";
    byte toEncodeBytes[toEncode.length()];
    memcpy(toEncodeBytes, toEncode.data(), toEncode.length());
    CryptoPP::StringSource ss(toEncodeBytes, sizeof(toEncodeBytes), true,
    new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
        )
    );
    return encoded;
}
std::string UtilsEncryption::DecodeFromHex(std::string toDecode)
{
    string decoded = "";
    byte toDecodeBytes[toDecode.length()];
    memcpy(toDecodeBytes, toDecode.data(), toDecode.length());
    CryptoPP::StringSource ss(toDecodeBytes, sizeof(toDecodeBytes), true,
    new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(decoded)
        )
    );
    return decoded;
}

CryptoPP::SecByteBlock UtilsEncryption::HexToBytes(string hexStr)
{
    CryptoPP::SecByteBlock decoded(hexStr.length() / 2);
    CryptoPP::StringSource(hexStr, true, 
    new CryptoPP::HexDecoder(
        new CryptoPP::ArraySink(decoded.BytePtr(), decoded.SizeInBytes())
        )
    );
    return decoded;
}
string UtilsEncryption::BytesToHex(CryptoPP::SecByteBlock bytesBlock)
{
    string output;
    CryptoPP::ArraySource(bytesBlock.BytePtr(), bytesBlock.SizeInBytes(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(output)
        )
    );
    return output;
}