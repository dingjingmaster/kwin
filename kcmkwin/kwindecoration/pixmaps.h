/* 
	This is the new kwindecoration kcontrol module

	Copyright (c) 2004, Sandro Giessl <sandro@giessl.com>
	Copyright (c) 2001
		Karol Szwed <gallium@kde.org>
		http://gallium.n3.net/

	Supports new kwin configuration plugins, and titlebar button position
	modification via dnd interface.

	Based on original "kwintheme" (Window Borders) 
	Copyright (C) 2001 Rik Hemsley (rikkus) <rik@kde.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
  
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
  
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Cambridge, MA 02110-1301, USA.

*/

// Button icon bitmap data which is hopefully generic enough to be recognized by everyone.

// close.xbm:
#define close_width 12
#define close_height 12
static unsigned char close_bits[] = {
   0x00, 0x00, 0x06, 0x06, 0x0e, 0x07, 0x9c, 0x03, 0xf8, 0x01, 0xf0, 0x00,
   0xf0, 0x00, 0xf8, 0x01, 0x9c, 0x03, 0x0e, 0x07, 0x06, 0x06, 0x00, 0x00 };

// help.xbm:
#define help_width 12
#define help_height 12
static unsigned char help_bits[] = {
   0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0xfc, 0x01, 0x8c, 0x01, 0xc0, 0x01,
   0xe0, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00, 0x00 };

// keepaboveothers.xbm:
#define keepaboveothers_width 12
#define keepaboveothers_height 12
static unsigned char keepaboveothers_bits[] = {
   0x00, 0x00, 0x60, 0x00, 0xf0, 0x00, 0xf8, 0x01, 0x60, 0x00, 0xfe, 0x07,
   0xfe, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// keepbelowothers.xbm:
#define keepbelowothers_width 12
#define keepbelowothers_height 12
static unsigned char keepbelowothers_bits[] = {
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07,
   0xfe, 0x07, 0x60, 0x00, 0xf8, 0x01, 0xf0, 0x00, 0x60, 0x00, 0x00, 0x00 };

// maximize.xbm:
#define maximize_width 12
#define maximize_height 12
static unsigned char maximize_bits[] = {
   0x00, 0x00, 0xfe, 0x07, 0xfe, 0x07, 0x02, 0x04, 0x02, 0x04, 0x02, 0x04,
   0x02, 0x04, 0x02, 0x04, 0x02, 0x04, 0x02, 0x04, 0xfe, 0x07, 0x00, 0x00 };

// menu.xbm:
#define menu_width 12
#define menu_height 12
static unsigned char menu_bits[] = {
   0x00, 0x00, 0xfc, 0x03, 0xf4, 0x02, 0x04, 0x02, 0xf4, 0x02, 0x04, 0x02,
   0xf4, 0x02, 0x04, 0x02, 0xf4, 0x02, 0x04, 0x02, 0xfc, 0x03, 0x00, 0x00 };

// minimize.xbm:
#define minimize_width 12
#define minimize_height 12
static unsigned char minimize_bits[] = {
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07, 0xfe, 0x07, 0x00, 0x00 };

// onalldesktops.xbm:
#define onalldesktops_width 12
#define onalldesktops_height 12
static unsigned char onalldesktops_bits[] = {
   0x00, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xfe, 0x07,
   0xfe, 0x07, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x00, 0x00 };

// resize.xbm:
#define resize_width 12
#define resize_height 12
static unsigned char resize_bits[] = {
   0x00, 0x00, 0xfe, 0x07, 0x42, 0x04, 0x42, 0x04, 0x42, 0x04, 0x42, 0x04,
   0x7e, 0x04, 0x02, 0x04, 0x02, 0x04, 0x02, 0x04, 0xfe, 0x07, 0x00, 0x00 };

// shade.xbm:
#define shade_width 12
#define shade_height 12
static unsigned char shade_bits[] = {
   0x00, 0x00, 0xfe, 0x07, 0xfe, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// spacer.xbm:
#define spacer_width 12
#define spacer_height 12
static unsigned char spacer_bits[] = {
   0x00, 0x00, 0x04, 0x02, 0x04, 0x02, 0x04, 0x02, 0x04, 0x02, 0x54, 0x03,
   0xac, 0x02, 0x04, 0x02, 0x04, 0x02, 0x04, 0x02, 0x04, 0x02, 0x00, 0x00 };

// vim: ts=4
