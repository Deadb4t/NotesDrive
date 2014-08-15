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

#include "../encryption/rsa-encryption.h"

#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/time_parsers.hpp>
#include <boost/date_time/posix_time/time_formatters.hpp>
#include <boost/date_time/posix_time/ptime.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>

using namespace std;

bool Networking::KeysExchanged(boost::asio::ip::tcp::socket* socket)
{
    string serverAddress = socket->remote_endpoint().address().to_string();
    if(HasServerKey(serverAddress))
    {
	RSAKeyPair cliKeyPair = RSAEncryption::LoadKeys("./keys/RSA-Private.key",
	    "RSA-Public.key");
	RSAKeyPair servKeyPair;
	string servKeyPath = "./keys/" + serverAddress + "/RSA-Public.key";
	RSAEncryption::LoadPublicKey(servKeyPair, "./keys/");
	return KeyCheck(cliKeyPair, servKeyPair, socket);
    }
    else
    {
	return false;
    }
}
bool Networking::HasServerKey(string serverAddress)
{
    boost::filesystem::path p("./keys/ " + serverAddress + "/RSA-Public.key");
    if(boost::filesystem::exists(p) && boost::filesystem::is_regular(p))
    {
	return true;
    }
    else
    {
	return false;
    }
}
bool Networking::KeyCheck(RSAKeyPair cliKeyPair, RSAKeyPair srvKeyPair, boost::asio::ip::tcp::socket* socket)
{
    if(!SendRSAMsg(cliKeyPair, srvKeyPair, "Ping", socket))
	return false;
    string reply = GetRSAMsg(cliKeyPair, srvKeyPair, socket);
    if(reply == "Pong")
    {
	return true;
    }
    else
    {
	return false;
    }
}

void Networking::DoKeyExchange(RSAKeyPair& srvKeyPair, boost::asio::ip::tcp::socket* socket)
{
    RequestServPublicKey(socket);
    int keyFileSize = GetServPublicKeyHeader(socket);
    srvKeyPair = GetServPublicKey(keyFileSize, socket);
    
    if(!RSAEncryption::ValidatePublicKey(srvKeyPair.PublicKey))
    {
	throw;
	return;
    }
    
    string keyFileData = LoadPublicKeyFileData();
    GetRequestForClientPublicKey(socket);
    SendClientPublicKeyHeader(keyFileData, socket);
    SendClientPublicKey(keyFileData, socket);
}
void Networking::RequestServPublicKey(boost::asio::ip::tcp::socket* socket)
{
    size_t length = max_key_request_size;
    string msg = "REQPK";
    boost::asio::write(*socket, boost::asio::buffer(msg.c_str(), length));
}
int Networking::GetServPublicKeyHeader(boost::asio::ip::tcp::socket* socket)
{
    size_t length = max_key_request_size;
    char headerChar[length];
    size_t header_length = boost::asio::read(*socket,  boost::asio::buffer(headerChar, length));
    string headerStr = headerChar;
    return boost::lexical_cast<int>(headerStr);
}
RSAKeyPair Networking::GetServPublicKey(int keyFileSize, boost::asio::ip::tcp::socket* socket)
{
    RSAKeyPair servKeyPair;
    size_t length = keyFileSize;
    char keyFileChar[length];
    boost::asio::read(*socket,  boost::asio::buffer(keyFileChar, length));
    string keyFileStr = keyFileChar;
    string serverName = socket->remote_endpoint().address().to_string();
    boost::filesystem::path keyPath("./keys/" + serverName + "/RSA-Public.key");
    SaveKeyToFile(keyFileStr, serverName);
    RSAEncryption::LoadPublicKey(servKeyPair, keyPath.relative_path().generic_string());
    return servKeyPair;
}
void Networking::SaveKeyToFile(string keyData, string serverName)
{
    boost::filesystem::path keyDir("./keys/" + serverName);
    if(!boost::filesystem::is_directory(keyDir) && !boost::filesystem::exists(keyDir))
    {
	boost::filesystem::create_directory(keyDir);
    }
    boost::filesystem::path keyPath("./keys/" + serverName + "/RSA-Public.key");
    ofstream keyFileStream;
    keyFileStream.open(keyPath.relative_path().generic_string().c_str());
    keyFileStream << keyData;
    keyFileStream.close();
}
void Networking::GetRequestForClientPublicKey(boost::asio::ip::tcp::socket* socket)
{
    size_t length = max_key_request_size;
    char requestChar[length];
    size_t reqestSize = boost::asio::read(*socket,  boost::asio::buffer(requestChar, length));
    string requestStr = requestChar;
    if(requestStr == "REQPK")
    {
	return;
    }
    else
    {
	throw;
    }
}
string Networking::LoadPublicKeyFileData()
{
    boost::filesystem::path keyFilePath("keys/RSA-Public.key");
    ifstream keyFileStream(keyFilePath.relative_path().generic_string().c_str(),
	ios::in|ios::binary|ios::ate
    );
    string keyFileData;
    streampos size;
    char* memblock;
    if(keyFileStream.is_open())
    {
	size = keyFileStream.tellg();
	memblock = new char[size];
	keyFileStream.seekg (0, ios::beg);
	keyFileStream.read (memblock, size);
	keyFileStream.close();
    }
    keyFileData = memblock;
    return keyFileData;
}
void Networking::SendClientPublicKeyHeader(string keyFileData, boost::asio::ip::tcp::socket* socket)
{
    string headerStr = boost::lexical_cast<string>(keyFileData.size());
    size_t length = max_header_size;
    boost::asio::write(*socket, boost::asio::buffer(headerStr.c_str(), length));
}
void Networking::SendClientPublicKey(string keyFileData, boost::asio::ip::tcp::socket* socket)
{
    size_t length = keyFileData.size();
    boost::asio::write(*socket, boost::asio::buffer(keyFileData.c_str(), length));
}


bool Networking::SendRSAMsg(RSAKeyPair cliKeyPair,
                            RSAKeyPair srvKeyPair,
                            std::string toSend,
                            boost::asio::ip::tcp::socket *socket)
{
    string DateTimeString = MakeDateTimeStamp();
    toSend = DateTimeString + "\n" + toSend;
    string signature = RSAEncryption::SignString(cliKeyPair, toSend);
    toSend = RSAEncryption::RSAEncrypt(srvKeyPair, toSend);
    try
    {
        MsgHeader header;
        header.MsgSize = toSend.length();
        header.SignatureSize = signature.length();
        SendHeader(header, socket);
        SendCTMsg(toSend, socket);
        SendMsgSignature(signature, socket);
        return true;
    }
    catch(std::exception &e)
    {
        cout << "Failed to send message to the server: " << e.what() << endl;
        return false;
    }
}

std::string Networking::GetRSAMsg(RSAKeyPair cliKeyPair, RSAKeyPair srvKeyPair, boost::asio::ip::tcp::socket *socket)
{
    try
    {
        MsgHeader header = GetHeader(socket);
        string msgCT = GetCTMsg(header, socket);
        string signature = GetMsgSignature(header, socket);
        string msgPT = RSAEncryption::RSADecrypt(cliKeyPair, msgCT);
        bool isValidSig = RSAEncryption::VerifySignature(srvKeyPair, msgPT, signature);
        bool isValidTimeStamp = ValidTimeStamp(msgPT);
        if(isValidSig && isValidTimeStamp)
        {
            return msgPT;
        }
        else
        {
            cout << "Could no verify message from server" << endl;
            return "";
        }
    }
    catch(std::exception &e)
    {
        cout << "Error fetching response from server: " << e.what() << endl;
        return "";
    }
}

string Networking::MakeDateTimeStamp()
{
    boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
    return to_iso_string(now);
}
bool Networking::ValidTimeStamp(string msg)
{
    string line;
    istringstream msgReader(msg);
    getline(msgReader, line);
    boost::posix_time::ptime timeStamp(boost::posix_time::from_iso_string(line));
    boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
    boost::posix_time::time_duration td = now - timeStamp;
    if(td.seconds() <= 15 && 
       td.minutes() == 0 && td.hours() == 0 &&
       timeStamp.date() == now.date())
    {
        return true;
    }
    else
    {
        return false;
    }
}

void Networking::SendHeader(MsgHeader header, boost::asio::ip::tcp::socket* socket)
{
    string headerStr = header.MsgSize + ":" + header.SignatureSize;
    size_t length = max_header_size;
    boost::asio::write(*socket, boost::asio::buffer(headerStr.c_str(), length));
}
void Networking::SendCTMsg(string msg, boost::asio::ip::tcp::socket *socket)
{
    size_t length = msg.size();
    boost::asio::write(*socket, boost::asio::buffer(msg.c_str(), length));
}
void Networking::SendMsgSignature(string signature, boost::asio::ip::tcp::socket *socket)
{
    size_t length = signature.size();
    boost::asio::write(*socket, boost::asio::buffer(signature.c_str(), length));
}

MsgHeader Networking::GetHeader(boost::asio::ip::tcp::socket* socket)
{
    MsgHeader header;
    size_t length = max_header_size;
    char headerChar[length];
    size_t header_length = boost::asio::read(*socket,  boost::asio::buffer(headerChar, length));
    string headerStr = headerChar;
    vector<string> headerVals;
    boost::split(headerVals, headerStr, boost::is_any_of(":"));
    header.MsgSize = boost::lexical_cast<int>(headerVals[0]);
    header.SignatureSize = boost::lexical_cast<int>(headerVals[1]);
    return header;
}
string Networking::GetCTMsg(MsgHeader header, boost::asio::ip::tcp::socket *socket)
{
    size_t length = header.MsgSize;
    char msgChar[length];
    size_t msg_length = boost::asio::read(*socket,  boost::asio::buffer(msgChar, length));
    string msg = msgChar;
    return msg;
}
string Networking::GetMsgSignature(MsgHeader header, boost::asio::ip::tcp::socket *socket)
{
    size_t length = header.SignatureSize;
    char sigChar[length];
    size_t sig_length = boost::asio::read(*socket,  boost::asio::buffer(sigChar, length));
    string sig = sigChar;
    return sig;
}

