// DisplayManager.cpp
#include "DisplayManager.h"
#include "Globals.h"

// Initialize the U8g2 object with your specific SPI pins
// SCK: 12, MOSI: 11, CS: 10, DC: 9, RST: 13
U8G2_SSD1306_128X32_UNIVISION_F_4W_SW_SPI u8g2(U8G2_R0, 12, 11, 10, 9, 13);

void showDisplayMessage(int lines, String text1, String text2, unsigned long timeoutMs) {
    xSemaphoreTake(displayMutex, portMAX_DELAY);
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_ncenB08_tr);
    
    if (lines == 1) {
        u8g2.drawStr(0, 15, text1.c_str());
    } else if (lines >= 2) {
        u8g2.drawStr(0, 14, text1.c_str());
        u8g2.drawStr(0, 28, text2.c_str());
    }
    
    u8g2.sendBuffer();
    xSemaphoreGive(displayMutex);
    
    // Handle timeout outside of mutex lock if a delay is requested
    if (timeoutMs > 0) {
        vTaskDelay(timeoutMs / portTICK_PERIOD_MS);
    }
}