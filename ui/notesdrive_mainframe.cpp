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

#include "notesdrive_mainframe.h"

#include <string>
#include <iostream>
#include <map>

#include <wx/wxprec.h>
#include <wx/richtext/richtextbuffer.h>
#include <wx/chartype.h>
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

using namespace std;
using namespace boost::asio::ip;

enum
{
    ID_CONNECT = 1,
    ID_NEWNOTE = 2,
    ID_REMOVENOTE = 3,
    ID_ENCSETTINGS = 4,
    ID_LISTBOX = 3,
    ID_TEXTBOX = 4
};

enum {max_user_name_size = 128};
enum {max_ykotp_size = 48};

wxBEGIN_EVENT_TABLE(NotesDrive_MainFrame, wxFrame)
EVT_MENU(ID_CONNECT, NotesDrive_MainFrame::OnConnect)
EVT_MENU(wxID_EXIT, NotesDrive_MainFrame::OnExit)
EVT_MENU(wxID_ABOUT, NotesDrive_MainFrame::OnAbout)
wxEND_EVENT_TABLE()

NotesDrive_MainFrame::NotesDrive_MainFrame(const wxString& title, const wxPoint& pos, const wxSize& size) 
    : wxFrame(NULL, wxID_ANY, title, pos, size)
{
    InitElements();
}

NotesDrive_MainFrame::~NotesDrive_MainFrame()
{

}

void NotesDrive_MainFrame::InitElements()
{
    SetupMenuBar();
    SetupStatusBar();
    SetupSizer();
    SetupFileTree();
    SetupTxtBox();
}

void NotesDrive_MainFrame::SetupMenuBar()
{
    menuFile = new wxMenu;
    menuFile->Append(ID_CONNECT, "&Connect", "Connect to NotesDrive Server");
    menuFile->AppendSeparator();
    menuFile->Append(ID_NEWNOTE, "&New Note", "Add a New Note.");
    menuFile->Enable(ID_NEWNOTE, false);
    menuFile->Append(ID_REMOVENOTE, "&Remove Note", "Remove a Note.");
    menuFile->Enable(ID_REMOVENOTE, false);
    menuFile->AppendSeparator();
    menuFile->Append(wxID_EXIT);
    wxMenu *menuHelp = new wxMenu;
    menuHelp->Append(wxID_ABOUT);
    wxMenuBar *menuBar = new wxMenuBar;
    menuBar->Append( menuFile, "&File" );
    menuBar->Append( menuHelp, "&Help" );
    SetMenuBar( menuBar );
}

void NotesDrive_MainFrame::SetupStatusBar()
{
    CreateStatusBar();
    SetStatusText( "Welcome to NotesDrive!" );
}

void NotesDrive_MainFrame::SetupSizer()
{
    borderBox = new wxBoxSizer(wxHORIZONTAL);
    mainFlexGrid = new wxFlexGridSizer(1, 2, 0, 5);
    mainFlexGrid->AddGrowableRow(0, 100);
    mainFlexGrid->AddGrowableCol(0, 50);
    mainFlexGrid->AddGrowableCol(1, 100);
    borderBox->Add(mainFlexGrid, 100, wxEXPAND | wxALL, 5);
    SetSizer(borderBox);
}

void NotesDrive_MainFrame::SetupFileTree()
{
    fileListBox = new wxListBox(this, ID_LISTBOX, wxPoint(-1,-1), wxSize(-1,-1));
    mainFlexGrid->Add(fileListBox, 1, wxEXPAND);
}

void NotesDrive_MainFrame::SetupTxtBox()
{
    editorTxtBox = new wxTextCtrl(this, ID_TEXTBOX, wxEmptyString, wxPoint(-1,-1), wxSize(-1,-1), wxTE_PROCESS_ENTER | wxTE_PROCESS_TAB | wxTE_MULTILINE);
    mainFlexGrid->Add(editorTxtBox, 2, wxEXPAND);
}

void NotesDrive_MainFrame::OnAbout(wxCommandEvent& event)
{
    wxMessageBox( "This is a secure note sharing application\nV0.0.0",
                  "NotesDrive", wxOK | wxICON_INFORMATION );
}
void NotesDrive_MainFrame::OnExit(wxCommandEvent& event)
{
    Close( true );
}
void NotesDrive_MainFrame::OnConnect(wxCommandEvent& event)
{
    ConnectDialog = new NotesDrive_ConnectDialog();
    if (ConnectDialog->ShowModal() == wxID_OK) 
    {
        SetStatusText("Connecting... Please wait.");
        ConnectToServer(ConnectDialog->DialogData);
    }
}
void NotesDrive_MainFrame::OnNewNote(wxCommandEvent& event)
{

}
void NotesDrive_MainFrame::OnRemoveNote(wxCommandEvent& event)
{

}

void NotesDrive_MainFrame::ConnectToServer(ConnectionData* data)
{
    menuFile->Enable(ID_CONNECT, false);
    Connection.Authenticated = false;
    Connection.ServerAddress = address::from_string(data->IP);
    Connection.Port = 8080;
    boost::asio::io_service io_service;
    tcp::resolver resolver(io_service);
    tcp::endpoint endpoint = tcp::endpoint(Connection.ServerAddress, Connection.Port);
    SetStatusText("Opening Connection...");
    Socket = new tcp::socket(io_service);
    try
    {
        SetStatusText("Connecting...");
        Socket->connect(endpoint);
        if(AuthenticateWithServer(data->UserName, data->Password, data->YubiOTP))
        {
            SetStatusText("Authenticated with server.");
            GetFileList();
        }
        else
        {
            SetStatusText("Connection failed...");
            menuFile->Enable(ID_CONNECT, true);
        }
    }
    catch(boost::system::system_error er)
    {
        SetStatusText("Connection failed...");
    }
}

bool NotesDrive_MainFrame::AuthenticateWithServer(string userName, string password, string yubiKeyOTP)
{
    if(SendUserName(userName) == false)
    {
        return false;
    }
    if(SendYubiKeyOTP(yubiKeyOTP) == false)
    {
        return false;
    }
    if(IsAuthenticationAccepted())
    {
        cout << "Authentication accepted." << endl;
        return true;
    }
}
bool NotesDrive_MainFrame::SendUserName(string userName)
{
    cout << "Sending username." << endl;
    try
    {
        size_t length = max_user_name_size;
        boost::asio::write(*Socket, boost::asio::buffer(userName.c_str(), length));
        return true;
    }
    catch(std::exception& e)
    {
        std::cerr << "Exception in sending User Name: " << e.what() << "\n";
        SetStatusText("Connection failed...");
        wxMessageDialog *dial = new wxMessageDialog(this, wxString("Error sending User Name.\nSee console output for details."), wxString("Error"), wxOK | wxICON_ERROR);
        dial->ShowModal();
        return false;
    }
}
bool NotesDrive_MainFrame::SendYubiKeyOTP(string yubiKeyOTP)
{
    cout << "Sending YubiKey OTP." << endl;
    if(yubiKeyOTP.length() != 0)
    {
        try
        {
            size_t length = max_ykotp_size;
            boost::asio::write(*Socket, boost::asio::buffer(yubiKeyOTP.c_str(), length));
            return true;
        }
        catch(std::exception& e)
        {
            std::cerr << "Exception in sending Yubi Key OTP: " << e.what() << "\n";
            SetStatusText("Connection failed...");
            wxMessageDialog *dial = new wxMessageDialog(NULL, wxString("Error sending Yubi Key OTP.\nSee console output for details."), wxString("Error"), wxOK | wxICON_ERROR);
            dial->ShowModal();
            return false;
        }
    }
}
bool NotesDrive_MainFrame::IsAuthenticationAccepted()
{
    cout << "Checking if authentication was accepted." << endl;
    try
    {
        char reply[32];
        size_t reply_length = boost::asio::read(*Socket,  boost::asio::buffer(reply, 32));
        string replyStr = reply;
        if(replyStr == "+")
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    catch(std::exception& e)
    {
        std::cerr << "Exception in getting server response: " << e.what() << "\n";
        SetStatusText("Connection failed...");
        wxMessageDialog *dial = new wxMessageDialog(NULL, wxString("Error in getting server response.\nSee console output for details."), wxString("Error"), wxOK | wxICON_ERROR);
        dial->ShowModal();
        return false;
    }
}

void NotesDrive_MainFrame::EnableServerCtrlGUI()
{
    menuFile->Enable(ID_NEWNOTE, true);
    menuFile->Enable(ID_REMOVENOTE, true);
}

void NotesDrive_MainFrame::UpdateFileList()
{
    SetStatusText("Updating file list...");
    map<int, string> fileList = GetFileList();
    if(fileList.size() != 0)
    {
        UpdateFileListGUI(fileList);
        SetStatusText("File list updated.");
    }
    else
    {
        SetStatusText("No files found.");
    }
}
map<int, string> NotesDrive_MainFrame::GetFileList()
{
    map<int, string> fileList;
    try
    {
        string request = "ls\n";
        size_t length = request.length();
        boost::asio::write(*Socket, boost::asio::buffer(request.c_str(), length));
        size_t reply_size = 65536;
        char reply[reply_size];
        size_t reply_length = boost::asio::read(*Socket,  boost::asio::buffer(reply, reply_size));
        string replyStr = reply;
        fileList = PhraseFileList(replyStr);
    }
    catch(std::exception& e)
    {
        std::cerr << "Exception in getting file list: " << e.what() << "\n";
        SetStatusText("Could not retrive file list...");
        wxMessageDialog *dial = new wxMessageDialog(NULL, wxString("Could not retrive file list.\nSee console output for details."), wxString("Error"), wxOK | wxICON_ERROR);
        dial->ShowModal();
        return fileList;
    }
}
map< int, string > NotesDrive_MainFrame::PhraseFileList(string rawData)
{

}
void NotesDrive_MainFrame::UpdateFileListGUI(map<int, string> fileList)
{
    
}

void NotesDrive_MainFrame::DownloadFile(int FileID)
{

}
