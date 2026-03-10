#include "drm/hardware_id.hpp"
#include <windows.h>
#include <sstream>

std::string getHardwareID() {

    DWORD serial = 0;
    GetVolumeInformationW(
        L"C:\\",
        NULL,
        0,
        &serial,
        NULL,
        NULL,
        NULL,
        0
    );

    std::stringstream ss;
    ss << serial;

    return ss.str();
}