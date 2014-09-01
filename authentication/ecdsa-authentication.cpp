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

#include "ecdsa-authentication.h"

#include <string>
#include <iostream>
#include <stdexcept>

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/concept_check.hpp>

#include <osrng.h>
#include <aes.h>
#include <sha3.h>
#include <filters.h>
#include <files.h>
#include <eccrypto.h>
#include <oids.h>

#include "../encryption/utils-encryption.h"
#include "../hashing/sha3-hashing.h"

using namespace std;
using namespace boost;
using namespace CryptoPP;

ECDSAKeyPair ECDSAAuthentication::GenerateKeyPair()
{
    ECDSAKeyPair keyPair;
    AutoSeededX917RNG<AES> prng;
    OID oid = ASN1::secp521r1();
    keyPair.PrivateKey.Initialize(prng, oid);
    keyPair.PrivateKey.MakePublicKey(keyPair.PublicKey);
    if(keyPair.PublicKey.Validate(prng, 5) &&
       keyPair.PrivateKey.Validate(prng, 5))
    {
        return keyPair;
    }
    else
    {
        throw runtime_error("Could not validate generated ECDSA keys");
    }
}

std::string ECDSAAuthentication::SignString(std::string toSign, ECDSAKeyPair keyPair)
{
    AutoSeededX917RNG<AES> prng;
    string signature;
    StringSource( toSign, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA3_512>::Signer(keyPair.PrivateKey),
            new StringSink( signature )
        )
    );
    signature = UtilsEncryption::EncodeToHex(signature);
    return signature;
}
bool ECDSAAuthentication::SignatureValid(std::string signature, std::string plainText, ECDSAPublicKey publicKey)
{
    bool result = false;
    signature = UtilsEncryption::DecodeFromHex(signature);
    StringSource( signature+plainText, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,SHA3_512>::Verifier(publicKey),
            new ArraySink( (byte*)&result, sizeof(result) )
        )
    );
    return result;
}

string ECDSAAuthentication::MakeKeySignature(ECDSAPublicKey publicKey)
{
    string keyStr;
    publicKey.Save( StringSink( keyStr ).Ref() );
    string keyHash = SHA3Hashing::HashString(keyStr);
    return keyHash;
}

string ECDSAAuthentication::PublicKeyToString(ECDSAPublicKey publicKey)
{
    string publicKeyStr;
    publicKey.Save( StringSink( publicKeyStr ).Ref() );
    return publicKeyStr;
}
ECDSAPublicKey ECDSAAuthentication::StringToPublicKey(string publicKeyStr)
{
    ECDSAPublicKey publicKey;
    publicKey.Load( StringSource( publicKeyStr.c_str(), publicKeyStr.size()).Ref() );
    if(!ValidPublicKey(publicKey))
    {
        throw runtime_error("Could not validate public key.");
    }
    return publicKey;
}

void ECDSAAuthentication::SaveKeyPair(ECDSAKeyPair keyPair, 
                                      std::string privateKeyFileName, 
                                      std::string publicKeyFileName, 
                                      std::string path)
{
    filesystem::path keyPairPath(path);
    filesystem::path privateKeyPath(path + "/" + privateKeyFileName);
    filesystem::path publicKeyPath(path + "/" + publicKeyFileName);
    if(filesystem::exists(keyPairPath) && filesystem::is_directory(keyPairPath))
    {
        WritePrivateKey(keyPair.PrivateKey, privateKeyPath.generic_string());
        WritePublicKey(keyPair.PublicKey, publicKeyPath.generic_string());
    }
    else
    {
        filesystem::create_directory(keyPairPath);
        SaveKeyPair(keyPair, privateKeyFileName, publicKeyFileName, path);
    }
}
void ECDSAAuthentication::SavePublicKey(ECDSAPublicKey publicKey, std::string publicKeyFileName, std::string path)
{
    filesystem::path keyPath(path);
    filesystem::path publicKeyPath(path + "/" + publicKeyFileName);
    if(filesystem::exists(keyPath) && filesystem::is_directory(keyPath))
    {
        WritePublicKey(publicKey, publicKeyPath.generic_string());
    }
    else
    {
        filesystem::create_directory(keyPath);
        SavePublicKey(publicKey, publicKeyFileName, path);
    }
}

ECDSAKeyPair ECDSAAuthentication::LoadKeyPair(std::string privateKeyFileName, 
                                              std::string publicKeyFileName, 
                                              std::string path)
{
    filesystem::path keyPairPath(path);
    filesystem::path privateKeyPath(path + "/" + privateKeyFileName);
    filesystem::path publicKeyPath(path + "/" + publicKeyFileName);
    if(filesystem::exists(privateKeyPath) && filesystem::is_regular_file(privateKeyPath) &&
        filesystem::exists(publicKeyPath) && filesystem::is_regular_file(publicKeyPath))
    {
        ECDSAKeyPair keyPair;
        keyPair.PrivateKey = ReadPrivateKey(privateKeyPath.generic_string());
        keyPair.PublicKey = ReadPublicKey(publicKeyPath.generic_string());
        if(ValidKeyPair(keyPair))
        {
            return keyPair;
        }
        else
        {
            throw runtime_error("Could not validate ECDSA loaded keys.");
        }
    }
    else
    {
        throw runtime_error("ECDSA keys do not exist.");
    }
}
ECDSAPublicKey ECDSAAuthentication::LoadPublicKey(std::string publicKeyFileName, std::string path)
{
    filesystem::path keyPairPath(path);
    filesystem::path publicKeyPath(path + "/" + publicKeyFileName);
    if(filesystem::exists(publicKeyPath) && filesystem::is_regular_file(publicKeyPath))
    {
        
        ECDSAPublicKey publicKey;
        publicKey = ReadPublicKey(publicKeyPath.generic_string());
        if(ValidPublicKey(publicKey))
        {
            return publicKey;
        }
        else
        {
            throw runtime_error("Could not validate ECDSA public key.");
        }
    }
    else
    {
        throw runtime_error("ECDSA public key does not exist.");
    }
}


bool ECDSAAuthentication::ValidKeyPair(ECDSAKeyPair keyPair)
{
    AutoSeededX917RNG<AES> prng;
    if(keyPair.PublicKey.Validate(prng, 5) &&
       keyPair.PrivateKey.Validate(prng, 5))
    {
        return true;
    }
    else
    {
        return false;
    }
}
bool ECDSAAuthentication::ValidPublicKey(ECDSAPublicKey publicKey)
{
    AutoSeededX917RNG<AES> prng;
    if(publicKey.Validate(prng, 5))
    {
        return true;
    }
    else
    {
        return false;
    }
}

void ECDSAAuthentication::WritePrivateKey(ECDSAAuthentication::ECDSAPrivateKey privateKey, string path)
{
    privateKey.Save( FileSink( path.c_str(), true /*binary*/ ).Ref() );
}
void ECDSAAuthentication::WritePublicKey(ECDSAPublicKey publicKey, std::string fullPath)
{
    publicKey.Save( FileSink( fullPath.c_str(), true /*binary*/ ).Ref() );
}

ECDSAAuthentication::ECDSAPrivateKey ECDSAAuthentication::ReadPrivateKey(std::string fullPath)
{
    ECDSAPrivateKey privateKey;
    privateKey.Load( FileSource( fullPath.c_str(), true /*pump all*/ ).Ref() );
    return privateKey;
}
ECDSAPublicKey ECDSAAuthentication::ReadPublicKey(std::string fullPath)
{
    ECDSAPublicKey publicKey;
    publicKey.Load( FileSource( fullPath.c_str(), true /*pump all*/ ).Ref() );
    return publicKey;
}
