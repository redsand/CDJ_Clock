/*
CDJ_Clock Edition Pro-Link MIDI Synchronization
Copyright (C) 2019  Alex Godbehere, Georg Ziegler, Anthony Lauzon

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "CdjClock.hpp"
#include "Inih.hpp"


#ifdef _WIN32

#include <pcap.h>

void list_interfaces(void) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		std::cerr << "Error in pcap_findalldevs_ex: " << errbuf << std::endl;
		return;
	}

	std::cout << "Available pcap interfaces:" << std::endl;

	/* Print the list */
	for (d = alldevs; d != NULL; d = d->next)
	{
		std::cout << "\tInterface #" << ++i << " " << d->name << " (" << ( d->description ? d->description : "Unknown" ) << ")" << std::endl;
	}

	if (i == 0)
	{
		std::cerr << "No interfaces found! Make sure WinPcap is installed" << std::endl;
		return;
	}

	/* We don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
}

#endif

int main(int argc, const char** argv) {
    std::string netDevice;
    int songPointerUp;
    int songPointerDown;
    int songPointerShiftUp;
    int songPointerShiftDown;
    int midiChannelIn;
    int midiKeyContinue;
    int midiKeyStop;
    int midiDeviceIn;
    int midiDeviceOut;

#ifdef _WIN32
	if (argc == 1) {
		list_interfaces();
		return 1;
	}
#endif

    if (argc != 2) {
        std::cerr << "CONFIG_PARAMETER_MISSING" << std::endl;
        return 1;
    } 

    std::string configPath(argv[1]);

    INIReader r(configPath);

    if (r.ParseError() != 0) {
      std::cout << "CONFIG_ERROR: " << configPath << std::endl;
      return 1;
    }

    netDevice = r.Get("cdjclock", "device", "en0");
    songPointerUp = r.GetInteger("cdjclock", "songPointerUp", 0);
    songPointerDown = r.GetInteger("cdjclock", "songPointerDown", 0);
    songPointerShiftUp = r.GetInteger("cdjclock", "songPointerShiftUp", 0);
    songPointerShiftDown = r.GetInteger("cdjclock", "songPointerShiftDown", 0);
    midiChannelIn = r.GetInteger("cdjclock", "midiChannelIn", 0);
    midiKeyContinue = r.GetInteger("cdjclock", "midiKeyContinue", 0);
    midiKeyStop = r.GetInteger("cdjclock", "midiKeyStop", 0);
    midiDeviceIn = r.GetInteger("cdjclock", "midiDeviceIn", -1);
    midiDeviceOut = r.GetInteger("cdjclock", "midiDeviceOut", -1);

    CdjClock cdjClock(songPointerUp, 
                      songPointerDown,
                      songPointerShiftUp,
                      songPointerShiftDown,
                      midiChannelIn,
                      midiKeyContinue,
                      midiKeyStop,
                      midiDeviceIn,
                      midiDeviceOut,
                      netDevice);

    return cdjClock.Run();
}