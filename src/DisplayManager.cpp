#include "DisplayManager.h"

// FIX: Corrected constructor scope resolution
LGFX::LGFX(void) {
    {
        auto cfg = _bus_instance.config();
        cfg.spi_host = SPI2_HOST;     // Use ESP32-S3 SPI2 Hardware Host
        cfg.spi_mode = 0;
        cfg.freq_write = 40000000;    // Stable 40MHz clock cycle speed
        cfg.pin_sclk = 12;            // SCL Pin
        cfg.pin_mosi = 11;            // SDA / MOSI Pin
        cfg.pin_miso = -1;
        cfg.pin_dc   = 9;             // DC Pin
        _bus_instance.config(cfg);
        _panel_instance.setBus(&_bus_instance);
    }
    {
        auto cfg = _panel_instance.config();
        cfg.pin_cs           = 10;    // CS Pin
        cfg.pin_rst          = 14;    // RST Pin
        cfg.panel_width      = 240;
        cfg.panel_height     = 320;
        cfg.offset_x         = 0;
        cfg.offset_y         = 0;
        _panel_instance.config(cfg);
    }
    setPanel(&_panel_instance);
}

// Instantiate the global tft object here so it allocates memory once
LGFX tft;