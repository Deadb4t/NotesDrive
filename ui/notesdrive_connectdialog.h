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

#ifndef NOTESDRIVE_CONNECTDIALOG_H
#define NOTESDRIVE_CONNECTDIALOG_H

#include <wx/wxprec.h>
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

struct ConnectionData
{
    bool DataLoaded;
    std::string IP;
    std::string UserName;
    std::string Password;
    std::string YubiOTP;
    bool OTPSentToServer;
};

class NotesDrive_ConnectDialog : public wxDialog
{
    public:
        NotesDrive_ConnectDialog();
        ~NotesDrive_ConnectDialog();
        ConnectionData* DialogData;
        
    private:
        void InitElements();
        void InitSizer();
        void InitTxtBoxes();
        void InitButtons();
               
        
        wxStaticText *IPLabel;
        wxTextCtrl *IPTxtBx;
        
        wxStaticText *UserNameLabel;
        wxTextCtrl *UserNameTxtBx;
        
        wxStaticText *PasswordLabel;
        wxTextCtrl *PasswordTxtBx;
        
        wxStaticText *YubiOTPLabel;
        wxTextCtrl *YubiOTPTxtBx;
        
        wxFlexGridSizer *mainFlexGrid;
        wxBoxSizer *borderBox;
        
        wxButton *CancelBtn;
        void OnCancel(wxCommandEvent &event);
        wxButton *ConnectBtn;
        void OnConnect(wxCommandEvent &event);
        
        
        std::string ValidateArgs();
};

#endif // NOTESDRIVE_CONNECTDIALOG_H
