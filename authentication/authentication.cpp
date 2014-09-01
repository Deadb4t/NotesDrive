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

#include "authentication.h"

#include <string>
#include <stdexcept>

#include "secblock.h"

#include <boost/asio/ip/tcp.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/concept_check.hpp>

#include "ecdh-authentication.h"
#include "../networking/networking.h"

using namespace std;


AuthenticationData Authentication::AuthenticateWithServer(AuthenticationData authData, boost::asio::ip::tcp::socket* socket)
{
    authData.ClientECDHKeyPair = ECDHAuthentication::GenerateKeyPair();
    SendUsername(authData, socket);
    if(!UserNameAccepted(socket))
    {
        throw runtime_error("Username not accepted.");
    }
    authData.ServerPublicKey = GetServerPublicKey(socket);
    ECDHKeyPair serverECDHKeyPair = GetServerECDHKey(authData.ServerPublicKey, socket);
    HandleServerKeyReqest(authData, socket);
    SendClientECDHKey(authData, socket);
    authData.sessionKey = ECDHAuthentication::MakeShared(authData.ClientECDHKeyPair, serverECDHKeyPair);
    SendAuthenticationFinsihed(authData, socket);
    if(AuthenticationSuccessful(authData, socket))
    {
        return authData;
    }
    else
    {
        throw runtime_error("Communication authentication rejected.");
    }
}


void Authentication::SendUsername(AuthenticationData authData, boost::asio::ip::tcp::socket* socket)
{
    Networking::SendPTMsg(authData.userName, socket);
}
bool Authentication::UserNameAccepted(boost::asio::ip::tcp::socket* socket)
{
    string reply = Networking::GetPTMsg(socket);
    if(reply == "USR_NAME_ACCEPTED")
    {
        return true;
    }
    else
    {
        return false;
    }
}


ECDSAPublicKey Authentication::GetServerPublicKey(boost::asio::ip::tcp::socket* socket)
{
    string serverName = socket->remote_endpoint().address().to_string();
    if(ServerPublicKeyExists(serverName))
    {
        ECDSAPublicKey publicKey = LoadServerPublicKey(serverName);
        bool keyConfirmed = ConfirmPublicKeySignature(publicKey, socket);
        if(keyConfirmed)
        {
            return publicKey;
        }
        else
        {
            throw runtime_error("Could not verify server's public key.");
        }
    }
    else
    {
        ECDSAPublicKey publicKey = FetchServerPublicKey(socket);
        ECDSAAuthentication::SavePublicKey(publicKey, "ec.public.key", "keys/" + serverName);
        return publicKey;
    }
}
bool Authentication::ServerPublicKeyExists(string serverName)
{
    boost::filesystem::path publicKeyFilePath("keys/" + serverName + "/ec.public.key");
    if(boost::filesystem::exists(publicKeyFilePath) && boost::filesystem::is_regular_file(publicKeyFilePath))
    {
        return true;
    }
    else
    {
        return false;
    }
}
ECDSAPublicKey Authentication::LoadServerPublicKey(string serverName)
{
    ECDSAPublicKey loadedKey = ECDSAAuthentication::LoadPublicKey("ec.public.key", "keys/" + serverName);
    return loadedKey;
}
bool Authentication::ConfirmPublicKeySignature(ECDSAPublicKey publicKey, boost::asio::ip::tcp::socket* socket)
{
    string keySig = ECDSAAuthentication::MakeKeySignature(publicKey);
    Networking::SendPTMsg("REQ_PK_SIG", socket);
    string serverKeySig = Networking::GetSignedMsg(publicKey, socket);
    if(serverKeySig == keySig)
    {
        Networking::SendPTMsg("PK_OK", socket);
        return true;
    }
    else
    {
        Networking::SendPTMsg("PK_BAD", socket);
        return false;
    }
}
ECDSAPublicKey Authentication::FetchServerPublicKey(boost::asio::ip::tcp::socket* socket)
{
    Networking::SendPTMsg("REQ_PK", socket);
    string keySignature = Networking::GetPTMsg(socket);
    string keyStr = Networking::GetPTMsg(socket);
    ECDSAPublicKey publicKey = ECDSAAuthentication::StringToPublicKey(keyStr);
    if(ECDSAAuthentication::SignatureValid(keySignature, keyStr, publicKey))
    {
        return publicKey;
    }
    else
    {
        throw runtime_error("Could not validate key signature");
    }
}


ECDHKeyPair Authentication::GetServerECDHKey(ECDSAPublicKey publicKey, boost::asio::ip::tcp::socket* socket)
{
    ECDHKeyPair keyPair;
    string keyString = Networking::GetSignedMsg(publicKey, socket);
    keyPair = ECDHAuthentication::StringToPublicKey(keyString);
    return keyPair;
}

void Authentication::HandleServerKeyReqest(AuthenticationData authData, boost::asio::ip::tcp::socket* socket)
{
    string keyReq = Networking::GetPTMsg(socket);
    if(keyReq == "REQ_PK_SIG")
    {
        SendClientPublicKeySig(authData, socket);
    }
    else if(keyReq == "REQ_PK")
    {
        SendClientPublicKey(authData, socket);
    }
    else
    {
        throw runtime_error("Bad response from server.");
    }
}

void Authentication::SendClientPublicKey(AuthenticationData authData, boost::asio::ip::tcp::socket* socket)
{
    string keyStr = ECDSAAuthentication::PublicKeyToString(authData.ClientECDSAKeyPair.PublicKey);
    string keySig = ECDSAAuthentication::SignString(keyStr, authData.ClientECDSAKeyPair);
    Networking::SendPTMsg(keySig, socket);
    Networking::SendPTMsg(keyStr, socket);
    string response = Networking::GetPTMsg(socket);
    if(response == "PK_OK")
    {
        return;
    }
    else
    {
        throw runtime_error("Server did not accept ECDSA key.");
    }
}
void Authentication::SendClientPublicKeySig(AuthenticationData authData, boost::asio::ip::tcp::socket* socket)
{
    string keySig = ECDSAAuthentication::MakeKeySignature(authData.ClientECDSAKeyPair.PublicKey);
    Networking::SendSignedMsg(keySig, authData.ClientECDSAKeyPair, socket);
    string response = Networking::GetPTMsg(socket);
    if(response == "PK_OK")
    {
        return;
    }
    else
    {
        throw runtime_error("Server did not accept ECDSA key.");
    }
}
void Authentication::SendClientECDHKey(AuthenticationData authData, boost::asio::ip::tcp::socket* socket)
{
    string keyString = ECDHAuthentication::PublicKeyToString(authData.ClientECDHKeyPair.PublicKey);
    Networking::SendSignedMsg(keyString, authData.ClientECDSAKeyPair, socket);
}

void Authentication::SendAuthenticationFinsihed(AuthenticationData authData, boost::asio::ip::tcp::socket* socket)
{
    string authFinishedMsg = "AUTH_FINISHED";
    Networking::SendAESMsg(authFinishedMsg, authData.sessionKey, authData.ClientECDSAKeyPair, socket);
}
bool Authentication::AuthenticationSuccessful(AuthenticationData authData, boost::asio::ip::tcp::socket* socket)
{
    string authResponse = Networking::GetAESMsg(authData.sessionKey, authData.ServerPublicKey, socket);
    if(authResponse == "AUTH_FINISHED")
    {
        return true;
    }
    else
    {
        return false;
    }
}