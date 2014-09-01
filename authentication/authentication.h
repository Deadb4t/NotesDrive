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

#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <string>
#include <boost/asio/ip/tcp.hpp>

#include "ecdsa-authentication.h"
#include "ecdh-authentication.h"

struct AuthenticationData
{
    std::string userName;
    std::string sessionKey;
    ECDSAPublicKey ServerPublicKey;
    ECDSAKeyPair ClientECDSAKeyPair;
    ECDHKeyPair ClientECDHKeyPair;
};

class Authentication
{
    public:
        AuthenticationData AuthenticateWithServer(AuthenticationData authData, boost::asio::ip::tcp::socket* socket);
        
    private:
        static void SendUsername(AuthenticationData authData, 
                                 boost::asio::ip::tcp::socket *socket);
        
        static bool UserNameAccepted(boost::asio::ip::tcp::socket *socket);
        
        static ECDSAPublicKey GetServerPublicKey(boost::asio::ip::tcp::socket *socket);
        static ECDSAPublicKey FetchServerPublicKey(boost::asio::ip::tcp::socket* socket);
        static bool ServerPublicKeyExists(std::string serverName);
        static ECDSAPublicKey LoadServerPublicKey(std::string serverName);
        static bool ConfirmPublicKeySignature(ECDSAPublicKey publicKey, boost::asio::ip::tcp::socket* socket);
        
        static ECDHKeyPair GetServerECDHKey(ECDSAPublicKey publicKey, boost::asio::ip::tcp::socket* socket);
        static void HandleServerKeyReqest(AuthenticationData authData, boost::asio::ip::tcp::socket *socket);
        
        static void SendClientPublicKey(AuthenticationData authData, 
                                        boost::asio::ip::tcp::socket *socket);
        static void SendClientPublicKeySig(AuthenticationData authData, 
                                           boost::asio::ip::tcp::socket *socket);
        static void SendClientECDHKey(AuthenticationData authData, 
                                      boost::asio::ip::tcp::socket *socket);
        
        static void SendAuthenticationFinsihed(AuthenticationData authData, boost::asio::ip::tcp::socket *socket);
        static bool AuthenticationSuccessful(AuthenticationData authData, boost::asio::ip::tcp::socket* socket);
};

#endif // AUTHENTICATION_H
