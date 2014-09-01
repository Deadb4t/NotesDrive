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

#include "networking.h"

#include <string>

#include <boost/lexical_cast.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio.hpp>

#include <secblock.h>

#include "../authentication/utils-authentication.h"
#include "../authentication/ecdh-authentication.h"
#include "../authentication/ecdsa-authentication.h"
#include "../encryption/aes-encryption.h"
#include "../encryption/utils-encryption.h"

using namespace std;

void Networking::SendPTMsg(std::string toSend, boost::asio::ip::tcp::socket* socket)
{
    SendString(toSend, socket);
}
std::string Networking::GetPTMsg(boost::asio::ip::tcp::socket* socket)
{
    return GetString(socket);
}

void Networking::SendSignedMsg(std::string toSend, ECDSAKeyPair clientKeyPair, boost::asio::ip::tcp::socket* socket)
{
    TimeStampMsg(toSend);
    SignMsg(clientKeyPair, toSend);
    SendString(toSend, socket);
}
std::string Networking::GetSignedMsg(ECDSAPublicKey publicKey, boost::asio::ip::tcp::socket* socket)
{
    string recived = GetString(socket);
    bool validSig = StripAndValidateSignature(publicKey, recived);
    bool validTimeStamp = StripAndValidateTimeStamp(recived);
    if(validSig && validTimeStamp)
    {
        return recived;
    }
    else
    {
        throw runtime_error("Could not validate signature or time stamp.");
    }
}

void Networking::SendAESMsg(std::string toSend, std::string sessionKey, ECDSAKeyPair clientKeyPair, boost::asio::ip::tcp::socket* socket)
{
    TimeStampMsg(toSend);
    SignMsg(clientKeyPair, toSend);
    AESEncryptMsg(sessionKey, toSend);
    SendString(toSend, socket);
}
std::string Networking::GetAESMsg(std::string sessionKey, ECDSAPublicKey publicKey, boost::asio::ip::tcp::socket* socket)
{
    string recived = GetString(socket);
    AESDecryptMsg(sessionKey, recived);
    bool validSig = StripAndValidateSignature(publicKey, recived);
    bool validTimeStamp = StripAndValidateTimeStamp(recived);
    if(validSig && validTimeStamp)
    {
        return recived;
    }
    else
    {
        throw runtime_error("Could not validate signature or time stamp.");
    }
}


void Networking::SendString(std::string toSend, boost::asio::ip::tcp::socket* socket)
{
    SendHeader(toSend, socket);
    SendBody(toSend, socket);
}
void Networking::SendHeader(std::string toSend, boost::asio::ip::tcp::socket* socket)
{
    string header = boost::lexical_cast<string>(toSend.size());
    size_t length = max_header_size;
    boost::asio::write(*socket, boost::asio::buffer(header.c_str(), length));
}
void Networking::SendBody(std::string toSend, boost::asio::ip::tcp::socket* socket)
{
    size_t length = toSend.size();
    boost::asio::write(*socket, boost::asio::buffer(toSend.c_str(), length));
}

std::string Networking::GetString(boost::asio::ip::tcp::socket* socket)
{
    int bodySize = GetHeader(socket);
    return GetBody(bodySize, socket);
}
int Networking::GetHeader(boost::asio::ip::tcp::socket* socket)
{
    size_t length = max_header_size;
    char headerChar[length];
    boost::asio::read(*socket,  boost::asio::buffer(headerChar, length));
    string header = headerChar;
    return boost::lexical_cast<int>(header);
}
std::string Networking::GetBody(int bodySize, boost::asio::ip::tcp::socket* socket)
{
    size_t length = bodySize;
    char bodyChar[length];
    boost::asio::read(*socket,  boost::asio::buffer(bodyChar, length));
    string body = bodyChar;
    return body;
}

void Networking::TimeStampMsg(string& input)
{
    string timeStamp = UtilsAuthentication::MakeDateTimeStamp();
    input = timeStamp + "\n" + input;
}
bool Networking::StripAndValidateTimeStamp(string& input)
{
    string timeStamp;
    stringstream msgReader(input);
    getline(msgReader, timeStamp);
    bool validTimeStamp = UtilsAuthentication::ValidTimeStamp(timeStamp);
    string line;
    string stripedInput = "";
    getline(msgReader, stripedInput);
    while(getline(msgReader, line))
    {
        stripedInput += "\n" + line;
    }
    input = stripedInput;
    return validTimeStamp;
}

void Networking::SignMsg(ECDSAKeyPair keyPair, string& input)
{
    string signature = ECDSAAuthentication::SignString(input, keyPair);
    input = signature + "\n" + input;
}
bool Networking::StripAndValidateSignature(ECDSAPublicKey publicKey, string& input)
{
    string signature;
    istringstream msgReader(input);
    getline(msgReader, signature);
    string line;
    string stripedInput = "";
    getline(msgReader, stripedInput);
    while(getline(msgReader, line))
    {
        stripedInput += "\n" + line;
    }
    bool validSignature = ECDSAAuthentication::SignatureValid(signature, stripedInput, publicKey);
    input = stripedInput;
    return validSignature;
}

void Networking::AESEncryptMsg(string sessionKey, string& input)
{
    input = AESEncryptor::Encrypt(input, sessionKey);
}
void Networking::AESDecryptMsg(string sessionKey, string& input)
{
    input = AESEncryptor::Decrypt(input, sessionKey);
}

