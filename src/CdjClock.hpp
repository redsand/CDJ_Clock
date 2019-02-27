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

#ifndef _CDJ_CLOCK_INCLUDE
#define _CDJ_CLOCK_INCLUDE

#include <RtMidi.hpp>
#include <net/bpf.h>
#include <pcap.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#define PACKETLIST_SIZE 32
#define SNAP_LEN 1518
#define TICK_COUNTS 19.2

class CdjClock {
    public:
        ~CdjClock();
        CdjClock(int songPointerUp, 
                 int songPointerDown,
                 int songPointerShiftUp,
                 int songPointerShiftDown,
                 int midiChannelIn,
                 int midiKeyContinue,
                 int midiKeyStop,
                 int midiDeviceIn,
                 int midiDeviceOut,
                 std::string netDevice);
        int Run();

        void *GotPacket(const struct pcap_pkthdr *header, 
                       const u_char *packet);

        void MidiInCallback(double deltatime, 
                            std::vector<unsigned char> *message);
    private:
        void SongPositionOut();
        void CheckError();
        void SetupMidi();
        void MidiTimer(int i);
        void ProbeMidi();

        int midiOn;
        int midiChannelIn;
        int midiKeyStart;
        int midiKeyContinue;
        int midiKeyStop;
        int midiDeviceIn;
        int midiDeviceOut;
        int noCount;
        int songPointerUp;
        int songPointerDown;
        int songPointerShiftUp;
        int songPointerShiftDown;
        int songPositionPointer;
        int midiSource;
        int cdjSync;
        int cdjStart;
        int clockCounter;

        double cdjTime;
        double lastCdjTime;
        double calculatedBpm;
        double midiTime;
        double lastBpm;
        double bpmDiff;
        double cdjDiff;
        double lastCdjDiff;
        double tickCounts;

        struct itimerval it_val;

        const std::vector<unsigned char> midiClock {0xF8};
        const std::vector<unsigned char> midiStart {0xFA};
        const std::vector<unsigned char> midiContinue {0xFB};
        const std::vector<unsigned char> midiStop {0xFC};

        RtMidiOut *midiOut;
        RtMidiIn *midiIn;

        std::string netDevice;
};

extern "C" {
    void MidiTimerHandler(int i);
}

struct PcapArgs {
    CdjClock *cdjClock;
    int numPackets;
    pcap_t *handle;
};

int setImmediateMode(int fd);

void GotPacketHandler(u_char *args, 
                      const struct pcap_pkthdr *header, 
                      const u_char *packet);

static void *pcapLoop(void *arg);

void MidiInCallbackHandler(double deltatime, 
                           std::vector<unsigned char> *message, 
                           void *userData);
#endif
