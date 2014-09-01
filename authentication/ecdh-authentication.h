/*
 * <one line to give the program's name and a brief idea of what it does.>
 * Copyright (C) 2014  <copyright holder> <email>
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

#ifndef ECDH_H
#define ECDH_H

#include "cryptopp/secblock.h"

struct ECDHKeyPair
{
    CryptoPP::SecByteBlock PublicKey;
    CryptoPP::SecByteBlock PrivateKey;
};

class ECDHAuthentication
{
    public:
        static ECDHKeyPair GenerateKeyPair();
        static std::string MakeShared(ECDHKeyPair clientKeyPair,
                                      ECDHKeyPair serverKeyPair);
        
        static std::string PublicKeyToString(CryptoPP::SecByteBlock publicKey);
        static ECDHKeyPair StringToPublicKey(std::string publicKey);
};

#endif // ECDH_H
