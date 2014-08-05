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

#include "rsa-encryption.h"

#include <string>
#include <iostream>

#include <cryptlib.h>
#include <osrng.h>
#include <rsa.h>
#include <files.h>

using namespace std;
using namespace CryptoPP;

std::string Encryption::RSAEncrypt(RSAKeyPair keyPair, std::string plainText)
{
    string cipherText;
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor encryptor(keyPair.PublicKey);
    StringSource strSourceEncrypt(plainText, true,
                                  new PK_EncryptorFilter(rng, encryptor, new StringSink(cipherText))
                                 );
    return cipherText;
}
std::string Encryption::RSADecrypt(RSAKeyPair keyPair, std::string cipherText)
{
    string plainText;
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Decryptor decryptor(keyPair.PrivateKey);
    StringSource StrSourceDecrypt(cipherText, true,
                                  new PK_DecryptorFilter(rng, decryptor, new StringSink(plainText))
                                 );
    return plainText;
}

RSAKeyPair Encryption::RSAGenerateKeys()
{
    RSAKeyPair keyPair;
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 4096);
    keyPair.PrivateKey = RSA::PrivateKey(params);
    keyPair.PublicKey = RSA::PublicKey(params);
}

bool Encryption::SaveKeys(RSAKeyPair keyPair, 
                          string privateKeyFileName,
                          string publicKeyFileName)
{
    if(SavePrivateKey(keyPair.PrivateKey, privateKeyFileName) &&
       SavePublicKey(keyPair.PublicKey, publicKeyFileName)
    )
    {
        return true;
    }
    else
    {
        return false;
    }
}
bool Encryption::SavePrivateKey(RSA::PrivateKey key, string fileName)
{
    try
    {
        ByteQueue queue;
        key.Save(queue);
        BufferedTransformation& bt = queue;
        FileSink file(fileName.c_str());
        bt.CopyTo(file);
        file.MessageEnd();
    }
    catch(std::exception &e)
    {
        cout << "Error saving private key: " << e.what() << endl;
        return false;
    }
}
bool Encryption::SavePublicKey(RSA::PublicKey key, string fileName)
{
    try
    {
        ByteQueue queue;
        key.Save(queue);
        BufferedTransformation& bt = queue;
        FileSink file(fileName.c_str());
        bt.CopyTo(file);
        file.MessageEnd();
    }
    catch(std::exception &e)
    {
        cout << "Error saving public key: " << e.what() << endl;
        return false;
    }
}

RSAKeyPair Encryption::LoadKeys(string privateKeyFileName, string publicKeyFileName)
{
    RSAKeyPair keyPair;
    keyPair.Loaded = true;
    keyPair.Validated = false;
    keyPair = LoadPrivateKey(keyPair, privateKeyFileName);
    keyPair = LoadPublicKey(keyPair, publicKeyFileName);
    if(keyPair.Loaded)
    {
        ValidateKeyPair(keyPair);
    }
    return keyPair;
}
RSAKeyPair Encryption::LoadPrivateKey(RSAKeyPair keyPair, string fileName)
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
RSAKeyPair Encryption::LoadPublicKey(RSAKeyPair keyPair, string fileName)
{
    try
    {
        ByteQueue queue;
        FileSource file(fileName.c_str(), true /*pumpAll*/);
        BufferedTransformation& bt = queue;
        file.TransferTo(bt);
        bt.MessageEnd();
        keyPair.PublicKey.Load(queue);
        return keyPair;
    }
    catch(std::exception &e)
    {
        keyPair.Loaded = false;
        cout << "Error locading public key: " << e.what() << endl;
    }
}
RSAKeyPair Encryption::ValidateKeyPair(RSAKeyPair keyPair)
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






