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

#ifndef NETWORKING_H
#define NETWORKING_H

#include <string>

#include <boost/asio/ip/tcp.hpp>

#include "../authentication/ecdsa-authentication.h"

class Networking
{
    enum {max_header_size = 256};
    
    public:        
        static void SendPTMsg(std::string toSend, 
                              boost::asio::ip::tcp::socket* socket);
        static std::string GetPTMsg(boost::asio::ip::tcp::socket* socket);
        
        static ECDSAPublicKey GetPublicKey(boost::asio::ip::tcp::socket* socket);
        
        static void SendSignedMsg(std::string toSend,
                                     ECDSAKeyPair clientKeyPair,
                                     boost::asio::ip::tcp::socket* socket);
        static std::string GetSignedMsg(ECDSAPublicKey publicKey, boost::asio::ip::tcp::socket* socket);
        
        static void SendAESMsg(std::string toSend,
                               std::string sessionKey,
                               ECDSAKeyPair clientKeyPair,
                               boost::asio::ip::tcp::socket* socket);
        static std::string GetAESMsg(std::string sessionKey, ECDSAPublicKey publicKey, boost::asio::ip::tcp::socket* socket);
        
    private:
        static void SendString(std::string toSend, 
                              boost::asio::ip::tcp::socket* socket);
        static void SendHeader(std::string toSend, 
                              boost::asio::ip::tcp::socket* socket);
        static void SendBody(std::string toSend, 
                              boost::asio::ip::tcp::socket* socket);
        
        static std::string GetString(boost::asio::ip::tcp::socket* socket);
        static int GetHeader(boost::asio::ip::tcp::socket* socket);
        static std::string GetBody(int bodySize,
                                   boost::asio::ip::tcp::socket* socket);
        
        static void TimeStampMsg(std::string &input);
        static bool StripAndValidateTimeStamp(std::string &input);
        
        static void SignMsg(ECDSAKeyPair keyPair, std::string &input);
        static bool StripAndValidateSignature(ECDSAPublicKey publicKey, std::string& input);
        
        static void AESEncryptMsg(std::string sessionKey, std::string &input);
        static void AESDecryptMsg(std::string sessionKey, std::string &input);
};

#endif // NETWORKING_H
