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

#ifndef ECDSAAUTHENTICATION_H
#define ECDSAAUTHENTICATION_H

#include <string>

#include <sha3.h>
#include <eccrypto.h>

struct ECDSAKeyPair
{
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_512>::PrivateKey PrivateKey;
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_512>::PublicKey PublicKey;
};

typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_512>::PublicKey ECDSAPublicKey;

class ECDSAAuthentication
{
    public:        
        static ECDSAKeyPair GenerateKeyPair();
        
        static std::string SignString(std::string toSign, ECDSAKeyPair keyPair);
        static bool SignatureValid(std::string signature, std::string plainText, ECDSAPublicKey publicKey);
        
        static std::string MakeKeySignature(ECDSAPublicKey publicKey);
        
        static std::string PublicKeyToString(ECDSAPublicKey publicKey);
        static ECDSAPublicKey StringToPublicKey(std::string publicKeyStr);
        
        static void SaveKeyPair(ECDSAKeyPair keyPair,
                                std::string privateKeyFileName,
                                std::string publicKeyFileName,
                                std::string path = "keys"
                               );
        static void SavePublicKey(ECDSAPublicKey publicKey,
                                  std::string publicKeyFileName,
                                  std::string path
                                 );
        
        static ECDSAKeyPair LoadKeyPair(std::string privateKeyFileName, 
                                        std::string publicKeyFileName,
                                        std::string path = "keys"
                                       );
        static ECDSAPublicKey LoadPublicKey(std::string publicKeyFileName,
                                            std::string path
                                           );
    private: 
        typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA3_512>::PrivateKey ECDSAPrivateKey;
        
        static bool ValidKeyPair(ECDSAKeyPair keyPair);
        static bool ValidPublicKey(ECDSAPublicKey publicKey);
        
        static void WritePrivateKey(ECDSAPrivateKey privateKey, std::string path);
        static void WritePublicKey(ECDSAPublicKey publicKey, std::string path);
        
        static ECDSAPrivateKey ReadPrivateKey(std::string path);
        static ECDSAPublicKey ReadPublicKey(std::string path);
        
};

#endif // ECDSAAUTHENTICATION_H
