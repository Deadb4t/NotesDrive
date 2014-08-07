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

#include "../encryption/rsa-encryption.h"
#include <boost/asio/ip/tcp.hpp>

struct MsgHeader
{
    int MsgSize;
    int SignatureSize;
};

class Networking
{    
    enum {max_header_size = 256};
    
    public:
        static bool SendRSAMsg(RSAKeyPair cliKeyPair,
                                    RSAKeyPair srvKeyPair,
                                    std::string toSend,
                                    boost::asio::ip::tcp::socket *socket);

        static std::string GetRSAMsg(RSAKeyPair cliKeyPair,
                                     RSAKeyPair srvKeyPair,
                                     boost::asio::ip::tcp::socket *socket);
        
    private:
        static std::string MakeDateTimeStamp();
        
        static void SendHeader(MsgHeader header, boost::asio::ip::tcp::socket *socket);
        static void SendCTMsg(std::string msg, boost::asio::ip::tcp::socket *socket);
        static void SendMsgSignature(std::string signature, boost::asio::ip::tcp::socket *socket);
        
        static MsgHeader GetHeader(boost::asio::ip::tcp::socket *socket);
        static std::string GetCTMsg(MsgHeader header, boost::asio::ip::tcp::socket *socket);
        static std::string GetMsgSignature(MsgHeader header, boost::asio::ip::tcp::socket *socket);
        
        static bool ValidTimeStamp(std::string msg);
};

#endif // NETWORKING_H
