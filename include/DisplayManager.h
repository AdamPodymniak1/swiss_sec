// DisplayManager.h
#pragma once
#define LGFX_USE_V1
#include <LovyanGFX.hpp>

#define TFT_BLACK       0x0000
#define TFT_WHITE       0xFFFF

class LGFX : public lgfx::LGFX_Device {
    lgfx::Panel_SSD1306 _panel_instance;
    lgfx::Bus_SPI       _bus_instance;

public:
    LGFX(void);
};

extern LGFX tft;