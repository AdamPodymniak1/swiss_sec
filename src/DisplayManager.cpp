// DisplayManager.cpp
#include "DisplayManager.h"

// Initialize the U8g2 object with your specific SPI pins
// SCK: 12, MOSI: 11, CS: 10, DC: 9, RST: 13
U8G2_SSD1306_128X32_UNIVISION_F_4W_SW_SPI u8g2(U8G2_R0, 12, 11, 10, 9, 13);