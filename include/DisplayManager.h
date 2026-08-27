#ifndef DISPLAY_MANAGER_H
#define DISPLAY_MANAGER_H

#include <U8g2lib.h>
#include <SPI.h>

// Shared OLED instance guarded by displayMutex.
extern U8G2_SSD1306_128X32_UNIVISION_F_4W_SW_SPI u8g2;

void showDisplayMessage(int lines, String text1, String text2 = "", unsigned long timeoutMs = 10000);

#endif 
