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

#include "ecdh-authentication.h"

#include <string>
#include <iostream>
#include <stdexcept>

#include <osrng.h>
#include <aes.h>
#include <eccrypto.h>
#include <secblock.h>
#include <oids.h>
#include <asn.h>
#include <integer.h>
#include <hex.h>
#include <filters.h>

#include "../hashing/sha3-hashing.h"
#include "../encryption/utils-encryption.h"

using namespace std;

using namespace CryptoPP::ASN1;
using namespace CryptoPP;

ECDHKeyPair ECDHAuthentication::GenerateKeyPair()
{
    ECDHKeyPair keyPair;
    OID CURVE = secp256r1();
    AutoSeededX917RNG<AES> rng;
    CryptoPP::ECDH < ECP >::Domain ecdh(CURVE);
    keyPair.PrivateKey = SecByteBlock(ecdh.PrivateKeyLength());
    keyPair.PublicKey = SecByteBlock(ecdh.PublicKeyLength());
    ecdh.GenerateKeyPair(rng, keyPair.PrivateKey, keyPair.PublicKey);
    return keyPair;
}
std::string ECDHAuthentication::MakeShared(ECDHKeyPair clientKeyPair, ECDHKeyPair serverKeyPair)
{
    string sharedSecret = "";
    OID CURVE = secp256r1();
    AutoSeededX917RNG<AES> rng;
    CryptoPP::ECDH < ECP >::Domain ecdh(CURVE);
    SecByteBlock shared(ecdh.AgreedValueLength());
    const bool accepted = ecdh.Agree(shared, clientKeyPair.PrivateKey, serverKeyPair.PublicKey);
    if(!accepted)
        throw runtime_error("Could not agree on shared secret with server.");
    string sharedStr = UtilsEncryption::BytesToHex(shared);
    return sharedStr;
}

std::string ECDHAuthentication::PublicKeyToString(SecByteBlock publicKey)
{
    string publicKeyStr;    
    StringSource ss(publicKey.BytePtr(), sizeof(publicKey.BytePtr()), true,
        new HexEncoder(
            new StringSink(publicKeyStr)
        )
    );
    return publicKeyStr;
}
ECDHKeyPair ECDHAuthentication::StringToPublicKey(string publicKey)
{
    OID CURVE = secp256r1();
    CryptoPP::ECDH < ECP >::Domain ecdh(CURVE);
    ECDHKeyPair keyPair;
    keyPair.PublicKey = SecByteBlock(ecdh.PublicKeyLength());
    ArraySource(publicKey.data(), true, 
        new HexDecoder(new ArraySink(keyPair.PublicKey, keyPair.PublicKey.size())));
    return keyPair;
}

