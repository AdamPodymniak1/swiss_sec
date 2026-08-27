// DisplayManager.h
#ifndef DISPLAY_MANAGER_H
#define DISPLAY_MANAGER_H

#include <U8g2lib.h>
#include <SPI.h>

// Global declaration for the U8g2 display object so it can be accessed in other files
extern U8G2_SSD1306_128X32_UNIVISION_F_4W_SW_SPI u8g2;

void showDisplayMessage(int lines, String text1, String text2 = "", unsigned long timeoutMs = 10000);

#endif // DISPLAY_MANAGER_H