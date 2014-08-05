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

#include "notesdrive_connectdialog.h"

#include <wx/wxprec.h>
#include <wx/richtext/richtextbuffer.h>
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include <boost/asio/ip/address.hpp>

using namespace std;

enum
{
    ID_CONNECTBTN = 1,
    ID_CANCELCONNECTIONBTN = 2
};

NotesDrive_ConnectDialog::NotesDrive_ConnectDialog()
: wxDialog(NULL, -1, "Connect to server", wxDefaultPosition, wxSize(250, 230))
{
    DialogData = new ConnectionData;
    DialogData->DataLoaded = false;
    InitElements();
}

NotesDrive_ConnectDialog::~NotesDrive_ConnectDialog()
{
    delete DialogData;
}

void NotesDrive_ConnectDialog::InitElements()
{
    InitSizer();
    InitTxtBoxes();
    InitButtons();
}

void NotesDrive_ConnectDialog::InitSizer()
{
    borderBox = new wxBoxSizer(wxVERTICAL);
    mainFlexGrid = new wxFlexGridSizer(5, 2, 5, 5);
    mainFlexGrid->AddGrowableRow(4, 100);
    mainFlexGrid->AddGrowableCol(1, 100);
    borderBox->Add(mainFlexGrid, 1, wxEXPAND | wxALL, 5);
    SetSizer(borderBox);
}

void NotesDrive_ConnectDialog::InitTxtBoxes()
{
    IPLabel = new wxStaticText(this, wxID_ANY, wxT("IP:"), wxPoint(-1, -1));
    mainFlexGrid->Add(IPLabel);
    IPTxtBx = new wxTextCtrl(this, -1, wxT(""), wxPoint(70, -1), wxSize(-1,-1));
    mainFlexGrid->Add(IPTxtBx, 1, wxALL | wxEXPAND);
    UserNameLabel = new wxStaticText(this, wxID_ANY, wxT("User Name:"), wxPoint(-1, -1));
    mainFlexGrid->Add(UserNameLabel);
    UserNameTxtBx = new wxTextCtrl(this, -1, wxT(""), wxPoint(100, -1), wxSize(-1,-1));
    mainFlexGrid->Add(UserNameTxtBx, 1, wxALL | wxEXPAND);
    PasswordLabel = new wxStaticText(this, wxID_ANY, wxT("Password:"), wxPoint(-1, -1));
    mainFlexGrid->Add(PasswordLabel);
    PasswordTxtBx = new wxTextCtrl(this, -1, wxT(""), wxPoint(100, -1), wxSize(-1,-1), wxTE_PASSWORD);
    mainFlexGrid->Add(PasswordTxtBx, 1, wxALL | wxEXPAND);
    YubiOTPLabel = new wxStaticText(this, wxID_ANY, wxT("YubiKey OTP:"), wxPoint(-1, -1));
    mainFlexGrid->Add(YubiOTPLabel);
    YubiOTPTxtBx = new wxTextCtrl(this, -1, wxT(""), wxPoint(100, -1), wxSize(-1,-1), wxTE_PASSWORD);
    mainFlexGrid->Add(YubiOTPTxtBx, 1, wxALL | wxEXPAND);
}

void NotesDrive_ConnectDialog::InitButtons()
{
    CancelBtn = new wxButton(this, ID_CANCELCONNECTIONBTN, wxT("Cancel"), wxPoint(-1, -1));
    Connect(ID_CANCELCONNECTIONBTN, wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler(NotesDrive_ConnectDialog::OnCancel));
    mainFlexGrid->Add(CancelBtn, 1, wxALL | wxEXPAND);
    ConnectBtn = new wxButton(this, ID_CONNECTBTN, wxT("Connect"), wxPoint(-1, -1));
    Connect(ID_CONNECTBTN, wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler(NotesDrive_ConnectDialog::OnConnect));
    mainFlexGrid->Add(ConnectBtn, 1, wxALL | wxEXPAND);
}

void NotesDrive_ConnectDialog::OnCancel(wxCommandEvent& event)
{
    Destroy();
}

void NotesDrive_ConnectDialog::OnConnect(wxCommandEvent& event)
{
    string validationResults = ValidateArgs();
    if(validationResults.length() == 0)
    {
        DialogData->IP = IPTxtBx->GetValue();
        DialogData->UserName = UserNameTxtBx->GetValue();
        DialogData->Password = PasswordTxtBx->GetValue();
        DialogData->YubiOTP = YubiOTPTxtBx->GetValue();
        DialogData->OTPSentToServer = false;
        DialogData->DataLoaded = true;
        EndModal(wxID_OK);
        Close();
    }
    else
    {
        wxMessageDialog *dial = new wxMessageDialog(NULL, wxT("Invalid connection arguments." + validationResults), wxT("Error"), wxOK | wxICON_ERROR);
        dial->ShowModal();
    }
}
string NotesDrive_ConnectDialog::ValidateArgs()
{
    string results = "";
    boost::asio::ip::address ipChecker;
    boost::system::error_code ec;
    ipChecker.from_string(IPTxtBx->GetValue(), ec);
    if(ec)
    {
        results += "\n- Invalid IP.";
    }
    if(UserNameTxtBx->GetValue().length() == 0)
    {
        results += "\n- No username.";
    }
    if(PasswordTxtBx->GetValue().length() == 0)
    {
        results += "\n- No password.";
    }
    return results;
}