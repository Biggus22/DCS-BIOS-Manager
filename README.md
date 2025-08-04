DCS-BIOS Manager is intended to be an alternative to SOCAT to simply the connection of microcontrollers to DCS BIOS.

It is based upon Justin's original dcs_bios_bridge.py script used for connecting RP2350s to DCS BIOS using his Pico-SDK focused fork of DCS BIOS, but I have added support for other microcontrollers.
This is still very early in development but it appears to be working adequately on my system.

Place the executable in a convenient directory.  It will generate a configuration file and likely a log file if you enable that function.

To add a new device, click on the Add New Device button.  A new window will open up.  Select a microcontroller type that matches your device.  Give it a name in the name field and find it's com port.
The baud rate will automatically populate (but the user can change the baudrate if desired).

There is a function to record inputs.  This only records digital inputs and is used as a method of verifying that Windows has not switched com ports around unexpectedly.  The program checks inputs
coming from your device against a known list of commands, so it is advisable to log all digital inputs.  This is an alternative to logging VID and PID of each device, as many cheaper devices have
identical values.  It should raise a warning if there appears to be unexpected digital inputs coming from a com port that has not previously sent them.  This is a work in progress and you may elect
to ignore logging those input values if you so choose.

Save your device profile, and to enable it, populate the check box beside it in the profiles box.

There are options to log to an external file, to start when Windows starts, minimizing to system tray on close and starting minimized.

The application log box will show you the digital inputs coming from your devices.


Note:
Analog inputs are currently untested and will be checked shortly.
