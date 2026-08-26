#include "DisplayManager.h"

LGFX::LGFX(void) {
    {
        auto cfg = _bus_instance.config();
        cfg.spi_host = SPI2_HOST;
        cfg.spi_mode = 0;
        cfg.freq_write = 40000000;
        cfg.pin_sclk = 12;
        cfg.pin_mosi = 11;
        cfg.pin_miso = -1;
        cfg.pin_dc   = 9;
        _bus_instance.config(cfg);
        _panel_instance.setBus(&_bus_instance);
    }
    {
        auto cfg = _panel_instance.config();
        cfg.pin_cs           = 10;
        cfg.pin_rst          = 13;
        cfg.panel_width      = 128;
        cfg.panel_height     = 32;
        cfg.offset_x         = 0;
        cfg.offset_y         = 0;
        _panel_instance.config(cfg);
    }
    setPanel(&_panel_instance);
}

LGFX tft;