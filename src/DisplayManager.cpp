#include "DisplayManager.h"
#include "Globals.h"

// SPI pin map for the 128x32 SSD1306 OLED.
U8G2_SSD1306_128X32_UNIVISION_F_4W_SW_SPI u8g2(U8G2_R0, 12, 11, 10, 9, 13);

// Shared variables for the background task
static String activeLine1 = "";
static String activeLine2 = "";
static unsigned long animStartMs = 0;
static TaskHandle_t displayTaskHandle = NULL;

// Background task that continuously renders the OLED frames
void displayRenderTask(void *pvParameters) {
    const int DISPLAY_WIDTH = 128;
    
    while (1) {
        xSemaphoreTake(displayMutex, portMAX_DELAY);
        
        // Copy strings to local variables for safe measuring/rendering
        String t1 = activeLine1;
        String t2 = activeLine2;
        unsigned long startMs = animStartMs;
        
        u8g2.setFont(u8g2_font_ncenB08_tr);
        int w1 = u8g2.getStrWidth(t1.c_str());
        int w2 = u8g2.getStrWidth(t2.c_str());
        
        unsigned long elapsedMs = millis() - startMs;
        
        // Helper lambda to calculate smooth ping-pong offset based on elapsed time
        auto getXOffset = [](int width, unsigned long elapsed) -> int {
            if (width <= DISPLAY_WIDTH) return 0; 
            
            int maxScroll = width - DISPLAY_WIDTH;
            unsigned long speed = 25;       
            unsigned long scrollDuration = maxScroll * speed;
            unsigned long pauseStart = 400; 
            unsigned long pauseEnd = 500;   
            unsigned long cycle = pauseStart + scrollDuration + pauseEnd + scrollDuration;

            unsigned long t = elapsed % cycle;

            if (t < pauseStart) return 0;
            if (t < pauseStart + scrollDuration) return -((int)(t - pauseStart) / (int)speed);
            if (t < pauseStart + scrollDuration + pauseEnd) return -maxScroll;
            return -maxScroll + ((int)(t - (pauseStart + scrollDuration + pauseEnd)) / (int)speed);
        };

        int x1 = getXOffset(w1, elapsedMs);
        int x2 = getXOffset(w2, elapsedMs);

        // Draw the frame
        u8g2.clearBuffer();
        if (t1.length() > 0) u8g2.drawStr(x1, 15, t1.c_str());
        if (t2.length() > 0) u8g2.drawStr(x2, 28, t2.c_str());
        u8g2.sendBuffer();
        
        xSemaphoreGive(displayMutex);

        // Yield to maintain ~33 FPS without starving the system
        vTaskDelay(30 / portTICK_PERIOD_MS);
    }
}

// Function called by your CLI and Setup routines
void showDisplayMessage(int lines, String text1, String text2, unsigned long timeoutMs) {
    // 1. Lazy-initialize the animation task on Core 1 the very first time this is called
    if (displayTaskHandle == NULL) {
        xTaskCreatePinnedToCore(displayRenderTask, "DispTask", 4096, NULL, 1, &displayTaskHandle, 1);
    }

    // 2. Safely update the shared text variables
    xSemaphoreTake(displayMutex, portMAX_DELAY);
    if (activeLine1 != text1 || activeLine2 != text2) {
        activeLine1 = text1;
        activeLine2 = (lines >= 2) ? text2 : "";
        animStartMs = millis();
    }
    xSemaphoreGive(displayMutex);

    // 3. Handle blocking delay if the caller requested it
    if (timeoutMs > 0) {
        vTaskDelay(timeoutMs / portTICK_PERIOD_MS);
    }
}