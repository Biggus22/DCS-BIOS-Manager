DCS BIOS Serial Manager

A standalone Python application with a graphical user interface (GUI) for managing multiple serial devices and bridging data from DCS-BIOS.

DCS-BIOS Manager is intended to be an alternative to SOCAT to simplify the connection of microcontrollers to DCS-BIOS. It is based upon Justin's original dcs_bios_bridge.py script, which was used for connecting RP2350s to DCS-BIOS using his Pico-SDK focused fork of DCS-BIOS. This project extends that work to add support for other microcontrollers.

This is still very early in development, but it appears to be working adequately on my system.
Features

    GUI-based Configuration: Add, edit, and remove devices through a simple and intuitive interface.

    Multiple Device Support: Configure and manage multiple serial devices simultaneously.

    Automated COM Port Detection: Automatically detects available COM ports, making device setup straightforward.

    Input Fingerprinting: A unique feature to help identify devices based on their output, which is useful when COM ports change unexpectedly.

    System Integration: Options to start the application with Windows and minimize it to the system tray.

    Logging: Built-in logging to track application activity and troubleshoot issues.

Installation
From Executable (Recommended)

You can download the latest compiled executable from the GitHub Releases page. This does not require a Python installation.

The executable and the Python script are located in the main directory.
From Source

If you prefer to run the application from the Python source code, you will need to install the required dependencies first.

    Clone the repository:

    git clone https://github.com/Biggus22/DCS-BIOS-Manager.git
    cd DCS-BIOS-Manager

    Install the required Python libraries using pip:

    pip install -r requirements.txt

        Note: The requirements.txt file should contain:

        pyserial
        pystray
        pillow
        pyinstaller

    Run the application:

    python dcs_bios_serial_manager.py

Usage

    Launch the application. Place the executable in a convenient directory; it will generate a configuration file and a log file if you enable that function.

    To add a new device, click on the Add New Device button. A new window will open up.

    Select a microcontroller type that matches your device. Give it a name in the name field and find its COM port. The baud rate will automatically populate (but can be changed if desired).

    There is a function to Record Inputs. This only records digital inputs and is used as a method of verifying that Windows has not switched COM ports around unexpectedly. The program checks inputs coming from your device against a known list of commands, so it is advisable to log all digital inputs. This is an alternative to logging the VID and PID of each device, as many cheaper devices have identical values. It should raise a warning if there appear to be unexpected digital inputs coming from a COM port that has not previously sent them. This is a work in progress, and you may elect to ignore logging those input values if you so choose.

    Save your device profile. To enable it, check the box beside it in the profiles box.

    There are options to log to an external file, start when Windows starts, minimize to the system tray on close, and start minimized. The application log box will show you the digital inputs coming from your devices.

Current Status & Notes

    Analog inputs are currently untested and will be checked shortly.
    This software is to be used at your own risk.

License

This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgements

This software makes use of the following open-source libraries:

    pyserial: For serial communication with devices.

    pystray: For system tray integration (requires Pillow).

    Pillow (PIL): For generating the system tray icon image.

    PyInstaller: For packaging the application into a standalone executable.

    tkinter: The standard Python library for GUI development.

    configparser: A standard Python library used for handling the configuration file.

The core functionality is built upon the concepts of bridging DCS-BIOS UDP exports, for which credit goes to the developers of the DCS-BIOS project, as well as the original dcs_bios_bridge.py script by Justin.
