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

#include "rsa-encryption.h"

#include <string>
#include <iostream>

#include <cryptlib.h>
#include <osrng.h>
#include <rsa.h>
#include <files.h>
#include <sha3.h>
#include <pssr.h>
#include <hex.h>

using namespace std;
using namespace CryptoPP;

std::string RSAEncryption::RSAEncrypt(RSAKeyPair keyPair, std::string plainText)
{
    string cipherText;
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor encryptor(keyPair.PublicKey);
    StringSource strSourceEncrypt(plainText, true,
                                  new PK_EncryptorFilter(rng, encryptor, new StringSink(cipherText))
                                 );
    return cipherText;
}
std::string RSAEncryption::RSADecrypt(RSAKeyPair keyPair, std::string cipherText)
{
    string plainText;
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Decryptor decryptor(keyPair.PrivateKey);
    StringSource StrSourceDecrypt(cipherText, true,
                                  new PK_DecryptorFilter(rng, decryptor, new StringSink(plainText))
                                 );
    return plainText;
}

string RSAEncryption::SignString(RSAKeyPair keyPair, std::string plainText)
{
    AutoSeededRandomPool rng;
    RSASS<PSS, SHA3_512>::Signer signer(keyPair.PrivateKey);
    string signature;
    StringSource ss1(plainText, true, 
        new SignerFilter(rng, signer,
            new StringSink(signature)
        )
    );
    return signature;
}

bool RSAEncryption::VerifySignature(RSAKeyPair keyPair, string plainText, string signature)
{
    string recovered;
    RSASS<PSS, SHA3_512>::Verifier verifier(keyPair.PublicKey);
    try
    {
        StringSource ss2(plainText+signature, true,
            new SignatureVerificationFilter(
                verifier,
                new StringSink(recovered),
                SignatureVerificationFilter::THROW_EXCEPTION |
                SignatureVerificationFilter::PUT_MESSAGE
            )
        );
        return true;
    }
    catch(std::exception &e)
    {
        cout << e.what() << endl;
        return false;
    }
}

RSAKeyPair RSAEncryption::GenerateKeys()
{
    RSAKeyPair keyPair;
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 4096);
    keyPair.PrivateKey = RSA::PrivateKey(params);
    keyPair.PublicKey = RSA::PublicKey(params);
    return keyPair;
}

void RSAEncryption::SaveKeys(RSAKeyPair keyPair, 
                          string privateKeyFileName,
                          string publicKeyFileName)
{
    SavePrivateKey(keyPair.PrivateKey, privateKeyFileName);
    SavePublicKey(keyPair.PublicKey, publicKeyFileName);
}
void RSAEncryption::SavePrivateKey(RSA::PrivateKey key, string fileName)
{
    ByteQueue queue;
    key.Save(queue);
    BufferedTransformation& bt = queue;
    FileSink file(fileName.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}
void RSAEncryption::SavePublicKey(RSA::PublicKey key, string fileName)
{
    ByteQueue queue;
    key.Save(queue);
    BufferedTransformation& bt = queue;
    FileSink file(fileName.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

RSAKeyPair RSAEncryption::LoadKeys(string privateKeyFileName, string publicKeyFileName)
{
    RSAKeyPair keyPair;
    keyPair.Loaded = true;
    keyPair.Validated = false;
    keyPair = LoadPrivateKey(keyPair, privateKeyFileName);
    LoadPublicKey(keyPair, publicKeyFileName);
    if(keyPair.Loaded)
    {
        ValidateKeyPair(keyPair);
    }
    return keyPair;
}
RSAKeyPair RSAEncryption::LoadPrivateKey(RSAKeyPair keyPair, string fileName)
{
    try
    {
        ByteQueue queue;
        FileSource file(fileName.c_str(), true /*pumpAll*/);
        BufferedTransformation& bt = queue;
        file.TransferTo(bt);
        bt.MessageEnd();
        keyPair.PrivateKey.Load(queue);
        return keyPair;
    }
    catch(std::exception &e)
    {
        keyPair.Loaded = false;
        cout << "Error loading private key: " << e.what() << endl;
    }
}
void RSAEncryption::LoadPublicKey(RSAKeyPair keyPair, string fileName)
{
    ByteQueue queue;
    FileSource file(fileName.c_str(), true /*pumpAll*/);
    BufferedTransformation& bt = queue;
    file.TransferTo(bt);
    bt.MessageEnd();
    keyPair.PublicKey.Load(queue);
}
bool RSAEncryption::ValidatePublicKey(RSA::PublicKey key)
{
    AutoSeededRandomPool rng;
    if(!key.Validate(rng, 3))
    {
        return false;
    }
    else
    {
        return true;
    }
}

RSAKeyPair RSAEncryption::ValidateKeyPair(RSAKeyPair keyPair)
{
    AutoSeededRandomPool rng;
    keyPair.Validated = true;
    if(!keyPair.PrivateKey.Validate(rng, 3))
    {
        cout << "Private key failed to validate." << endl;
        keyPair.Validated = false;
    }
    if(!keyPair.PublicKey.Validate(rng, 3))
    {
        cout << "Public key failed to validate." << endl;
        keyPair.Validated = false;
    }
    return keyPair;
}






