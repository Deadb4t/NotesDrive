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

#include "notesdrive_app.h"

#include <wx/wxprec.h>
#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include "notesdrive_mainframe.h"

NotesDrive_App::NotesDrive_App()
{

}

NotesDrive_App::~NotesDrive_App()
{

}

bool NotesDrive_App::OnInit()
{
    NotesDrive_MainFrame *frame = new NotesDrive_MainFrame( "NotesDrive", wxPoint(50, 50), wxSize(450, 340) );
    frame->Show( true );
    return true;
}

