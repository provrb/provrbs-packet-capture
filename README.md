# ProCapture Packet Capture

A packet capture program built using C for the backend (with Npcap) and C++ with wxWidgets for the frontend. This application allows users to capture network packets on Windows systems, providing real-time analysis with a  graphical interface.

![Example](/procapture.png)

## Table of Contents
1. [Overview](#overview) - an overview of the project
2. [Features](#features) - what features this project contains
3. [Installation](#installation) - how to install the application and source code
4. [Building](#building-the-project) - how to build the application from source
5. [Contributing](#contributing) - contributing to the project
6. [License](#license) - the license this project is under

## Overview

This packet capture program provides a user-friendly interface for capturing and analyzing network packets on Windows. The backend utilizes Npcap, a packet capture library, for low-level network packet interception, while the frontend is built with wxWidgets to display the captured packets in a structured and easy-to-navigate graphical interface.

### Features
- Capture live network packets from multiple network interfaces.
- Display packet details such as source/destination IP, protocol, and timestamp.
- Filter packets by protocol, IP address, and more.
- Export packet data for further analysis or logging.
- Analyze hex-dumps of raw packet data.
- Start, stop, pause, and resume packet capture. 

## Installation
You can either download the source code or the actual application to run. The application ships with the necessary DLL's, so no additional dependencies are required.

### To download the application:
1. Navigate to the [GitHub repositories release page](https://github.com/provrb/provrbs-packet-capture/releases).
2. Donwload 'procapture.rar' from the lastest release.
3. Extract the folder and its contents
4. Run procapture.exe to start the application.

### To download the source code:
Open a command prompt or terminal and clone the GitHub repository using:

```bash
> git clone https://github.com/provrb/provrbs-packet-capture.git
> cd provrbs-packet-capture
```

You can also download the source code from the [GitHub repositories release page](https://github.com/provrb/provrbs-packet-capture/releases).


## Building the Project
To build the project:
1. Download the source code using the instructions above
2. Open the Visual Studio Solution file
3. Click the build configuration, can be CLI (command-line interface) instead of GUI or
Release (GUI).
4. Navigate to Build > Build Solution.
5. The outputted .exe will be located at solution_dir/out/

## Contributing

Contributions to improve this project are welcome! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Push to the branch (git push origin feature-name).
5. Open a Pull Request for review.

Be sure to include detail in your submitted pull request.

## License

This project is licensed under the GNU General Public License v2.0 (GPL-2.0) License - see the LICENSE file for details.
    [License](LICENSE)

![Logo](src/rsrc/gui_icon.ico)
