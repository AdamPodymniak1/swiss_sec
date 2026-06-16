#pragma once

#define LGFX_USE_V1
#include <LovyanGFX.hpp>

// Color macro definitions
#define TFT_BLACK       0x0000
#define TFT_WHITE       0xFFFF
#define TFT_RED         0xF800
#define TFT_DARKGREEN   0x03E0
#define TFT_NAVY        0x000F
#define TFT_YELLOW      0xFFE0

class LGFX : public lgfx::LGFX_Device {
    lgfx::Panel_ST7789  _panel_instance;
    lgfx::Bus_SPI       _bus_instance;

public:
    LGFX(void); // Constructor declaration
};

// Expose the global instance to main.cpp and FingerprintManager.cpp
extern LGFX tft;