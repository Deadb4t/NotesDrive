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

#ifndef NOTESDRIVE_MAINFRAME_H
#define NOTESDRIVE_MAINFRAME_H

#include <map>

#include <wx/wxprec.h>
#include <wx/richtext/richtextbuffer.h>
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include <boost/asio/ip/address.hpp> 
#include <boost/asio/ip/tcp.hpp>
#include <boost/filesystem.hpp>

#include "notesdrive_connectdialog.h"
#include "../encryption/rsa-encryption.h"

struct ServerConnection
{
    bool Authenticated;
    boost::asio::ip::address ServerAddress;
    int Port;
};

class NotesDrive_MainFrame : public wxFrame
{
    public:
        NotesDrive_MainFrame(const wxString& title, const wxPoint& pos, const wxSize& size);
        ~NotesDrive_MainFrame();
        
    private:
        void OnConnect(wxCommandEvent &event);
        void OnExit(wxCommandEvent &event);
        void OnAbout(wxCommandEvent &event);
        void OnNewNote(wxCommandEvent &event);
        void OnRemoveNote(wxCommandEvent &event);
        wxDECLARE_EVENT_TABLE();
        
        wxMenu *menuFile;
        wxListBox *fileListBox;
        wxTextCtrl *editorTxtBox;
        wxFlexGridSizer *mainFlexGrid;
        wxBoxSizer *borderBox;
        NotesDrive_ConnectDialog* ConnectDialog;
        
        ServerConnection Connection;
        boost::asio::ip::tcp::socket* Socket;
        
        RSAKeyPair KeyPair;
        
        void InitElements();
        void SetupMenuBar();
        void SetupStatusBar();
        void SetupSizer();
        void SetupFileTree();
        void SetupTxtBox();
        
        void InitKeys();
        bool KeysExist(boost::filesystem::path priaveKeyPath, boost::filesystem::path publicKeyPath);
        bool KeyFolderExists(boost::filesystem::path keyFolderPath);
        
        void ConnectToServer(ConnectionData *data);
        
        bool AuthenticateWithServer(std::string userName, std::string password, std::string yubiKeyOTP);
        bool SendUserName(std::string userName);
        // bool SendPassword(std::string password);
        bool SendYubiKeyOTP(std::string yubiKeyOTP);
        bool IsAuthenticationAccepted();
        
        void EnableServerCtrlGUI();
        
        void UpdateFileList();
        std::map<int, std::string> GetFileList();
        std::map<int, std::string> PhraseFileList(std::string rawData);
        void UpdateFileListGUI(std::map<int, std::string> fileList);
        
        void DownloadFile(int FileID);
};

#endif // NOTESDRIVE_MAINFRAME_H