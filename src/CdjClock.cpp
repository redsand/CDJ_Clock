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

std::function<void(int)> CdjClockMidiTimer = NULL;

CdjClock::CdjClock(int songPointerUp, 
                   int songPointerDown,
                   int songPointerShiftUp,
                   int songPointerShiftDown,
                   int midiChannelIn,
                   int midiKeyContinue,
                   int midiKeyStop,
                   int midiDeviceIn,
                   int midiDeviceOut,
                   std::string netDevice) {
        this->midiChannelIn = midiChannelIn;
        this->midiKeyContinue = midiKeyContinue;
        this->midiKeyStop = midiKeyStop;
        this->songPointerUp = songPointerUp;
        this->songPointerDown = songPointerDown;
        this->songPointerShiftUp = songPointerShiftUp;
        this->songPointerShiftDown = songPointerShiftDown;
        this->netDevice = netDevice;
        this->midiDeviceIn = midiDeviceIn;
        this->midiDeviceOut = midiDeviceOut;

        midiOn = 0;
        songPositionPointer = 0;
        midiSource = 0;
        cdjSync = 0;

        midiOut = new RtMidiOut();
        midiIn = new RtMidiIn();
}

CdjClock::~CdjClock() {
    delete midiOut;
    delete midiIn;
}

void CdjClock::SongPositionOut() {
    unsigned char spp_lsb = 0b01111111 & songPositionPointer * 4;
    unsigned char spp_msb = 0b01111111 & songPositionPointer * 4 >> 7;
    
    const std::vector<unsigned char> songPosition {0xF2, spp_lsb, spp_msb};

    midiOut->sendMessage(&songPosition);

    std::cout << "SONG_POSITION_PTR: " <<  songPositionPointer << std::endl;
}

void CdjClock::MidiTimer(int i) {
    it_val.it_value.tv_sec = tickCounts / 1000;
    it_val.it_value.tv_usec = tickCounts * 1000;
    it_val.it_interval = it_val.it_value;

    // set new time for itimer
    if (setitimer(ITIMER_REAL, &it_val, NULL) == -1) {
        std::cerr << "SET_ITIMER_ERR" << std::endl;
    } 
    
    if (clockCounter > 23) {
        struct timeval tv;
        gettimeofday(&tv, NULL);

        midiTime = tv.tv_sec * 1000 + tv.tv_usec * 0.001;
        
        clockCounter  = 0;

        if(cdjStart == 2 && midiOn == 1) {
            songPositionPointer++;
        }
    }

    clockCounter++;

    midiOut->sendMessage(&midiClock);
}

void CdjClock::MidiInCallback(double deltatime, 
                              std::vector<unsigned char> *message) {
    unsigned char midiStatus = message->at(0);
    unsigned char midiChannel = (0x0F & midiStatus) + 1;
    unsigned char midiCommand = midiStatus >> 4;
    
    unsigned char data1 = 0;
    unsigned char data2 = 0;
    
    if (message->size() >= 3) {
        data1 = message->at(1);
        data2 = message->at(2);
    }

    if (midiStatus == midiStart.front()) {
        std::cout << "MIDI_START" << std::endl;
        midiOn = 1; 
    }

    if (midiStatus == midiStop.front())  {
        std::cout << "MIDI_STOP" << std::endl; 
        midiOn = 0; 
    }

    // note-on/off
    if (midiCommand == 0x08 || midiCommand == 0x09) {
        // number |= 1 << x; // set bit
        // number &= ~(1 << x); // clear bit
        // number ^= 1 << x; // toggle bit
        // bit = number & (1 << x); // check bit
        
        if (data1 == midiKeyContinue && 
            midiChannel == midiChannelIn && 
            data2 == 127) {

            if (midiKeyStop == 0 && midiOn == 1) {
                midiOn = 0;
            } else {
                midiOn = 1;
            }
        }
        
        if (data1 == midiKeyStop && 
            midiChannel == midiChannelIn && 
            data2 == 127) {

            if (midiOn == 2) {
                songPositionPointer = 0; 
                SongPositionOut(); 
            } 
            midiOn = 0; 
        }

        // jump 4/4 beat back (1 bar)
        if (data1 == songPointerUp && 
            midiChannel == midiChannelIn && 
            data2 == 127) {
            if(songPositionPointer == (songPositionPointer & ~(0b10))) {
                songPositionPointer = songPositionPointer - 4;
            }

            songPositionPointer &= ~(0b11); // clear bits
            SongPositionOut();
        }

        // jump to next 4/4 beat (1 bar)
        if (data1 == songPointerDown && 
            midiChannel == midiChannelIn && 
            data2 == 127) {

            songPositionPointer &= ~(0b11); // clear bits
            songPositionPointer = songPositionPointer + 4;
            SongPositionOut();
        }
        
        // jump 8 bar back (32 beat)
        if (data1 == songPointerShiftUp && 
            midiChannel == midiChannelIn && 
            data2 == 127) {

            if(songPositionPointer == (songPositionPointer & ~(0b11110))) {
                songPositionPointer = songPositionPointer - 32;
            }

            songPositionPointer &= ~(0b11111); // clear bits
            SongPositionOut();
        }

        // jump to next 8 bar (32 beat)
        if (data1==songPointerShiftDown && 
            midiChannel==midiChannelIn && 
            data2==127) {

            songPositionPointer &= ~(0b11111); // clear bits
            songPositionPointer = songPositionPointer + 32;
            SongPositionOut();
        }
        
        if(midiCommand == 0x08) {
            std::cout << "CHANNEL: "  << midiChannel << " "
                      << "NOTEOFF: "  << data1       << " " 
                      << "VELOCITY: " << data2       << std::endl; 
        }

        if(midiCommand == 0x09) {
            std::cout << "CHANNEL: "  << midiChannel << " "
                      << "NOTEON: "   << data1       << " " 
                      << "VELOCITY: " << data2       << std::endl; 
        }
    } else if (midiCommand > 0x09) {

        if(midiCommand == 0x0A) {
            std::cout << "CHANNEL: "     << midiChannel << " "
                      << "POLYPHONIC: "  << data1       << " " 
                      << "PRESSURE: "    << data2       << std::endl; 
        }
        
        if(midiCommand == 0x0B) {
            std::cout << "CHANNEL: " << midiChannel << " "
                      << "CONTROL: " << data1       << " " 
                      << "DATA: "    << data2       << std::endl; 
        }

        if(midiCommand == 0x0C) {
            std::cout << "CHANNEL: " << midiChannel << " "
                      << "PROGRAM: " << data1       << std::endl;
        }
        
        if(midiCommand == 0x0D) {
            std::cout << "CHANNEL: " << midiChannel << " "
                      << "AFTERTOUCH: " << data1    << std::endl;
        }
        
        if(midiCommand == 0x0E) {
            std::cout << "CHANNEL: "           << midiChannel << " "
                      << "PITCHWHEEL_LSBYTE: " << data1       << " " 
                      << "PITCHWHEEL_MSBYTE: " << data2       << std::endl;
        } 
    } else {
        std::cout << "CHANNEL: " << midiChannel << " "
                  << "BYTE1: "   << data1       << " " 
                  << "BYTE2: "   << data2       << std::endl; 
    }
}

void CdjClock::SetupMidi() {
    midiIn->openPort(midiDeviceIn);
    std::string midiInName = midiIn->getPortName(midiDeviceIn);
    midiIn->setCallback(&MidiInCallbackHandler, this);
    midiIn->ignoreTypes(false, false, false);
    std::cout << "MIDI_DEVICE_IN: " << midiInName << std::endl;
    
    midiOut->openPort(midiDeviceOut);
    std::string midiOutName = midiOut->getPortName(midiDeviceOut);
    std::cout << "MIDI_DEVICE_OUT: " << midiOutName << std::endl;
}

void CdjClock::ProbeMidi() {
    unsigned int nPorts = midiIn->getPortCount();
    std::cout << "NUM_MIDI_INPUT_PORTS: " << nPorts << std::endl;
    std::string portName;
    for (unsigned int i = 0; i < nPorts; i++) {
        try {
          portName = midiIn->getPortName(i);
        } catch ( RtMidiError &error ) {
            std::cerr << error.getMessage() << std::endl;
        }
        std::cout << "INPUT_PORT_" << i << ": " << portName << std::endl;
    }

    nPorts = midiOut->getPortCount();
    std::cout << "NUM_MIDI_OUTPUT_PORTS: " << nPorts << std::endl;
    for ( unsigned int i=0; i<nPorts; i++ ) {
        try {
          portName = midiOut->getPortName(i);
        } catch (RtMidiError &error) {
            std::cerr << error.getMessage() << std::endl;
        }
        std::cout << "OUTPUT_PORT_" << i << ": " << portName << std::endl;
    }
}

void *CdjClock::GotPacket(const struct pcap_pkthdr *header, 
                          const u_char *packet) {
    if (packet[75] >= 1 && packet[75] <= 4) {
        noCount = 0;

        if (cdjStart == 0) {
            cdjStart = 1;
        }

        if (cdjSync == packet[75] && cdjSync == 9) {
            return 0;
        }

    } else if (packet[75] == 33 && !(packet[74] == 0 && cdjSync == 0)) {
         // sync on DJM2000
        return 0;

    } else if (packet[75] != 0) {
        return 0;
    }

    cdjTime = header->ts.tv_sec * 1000 + header->ts.tv_usec * 0.001;

    // compare to half beat
    cdjDiff = (cdjTime - (cdjTime - lastCdjTime) / 2 - midiTime); 
    
    tickCounts = (cdjTime - lastCdjTime) / 24 + cdjDiff / 48;
    
    if (tickCounts < 10) {
        tickCounts=10;
    } else if (tickCounts > 50) {
        tickCounts = 50;
    }    

    calculatedBpm = 60000 / (cdjTime - lastCdjTime);

    if(calculatedBpm > 200) {
        return 0;
    } 
    
    lastCdjTime = cdjTime;

    bpmDiff = calculatedBpm - lastBpm;

    std::cout << "NOBEAT: "  << noCount       << " " 
              << "BPM: "     << calculatedBpm << " " 
              << "Tick: "    << tickCounts    << " "
              << "CDJDiff: " << cdjDiff       << " "
              << "BPMDiff: " << bpmDiff       << std::endl;

    lastBpm = calculatedBpm;

    if(bpmDiff > 20 || bpmDiff < -20) {
        return 0;
    }
    
    // start MIDI
    if(cdjStart == 1 && midiOn == 1) { 
        unsigned char spp_lsb = 0b01111111 & songPositionPointer * 4;
        unsigned char spp_msb = 0b01111111 & songPositionPointer * 4 >> 7;
        const std::vector<unsigned char> songPosition {0xF2, spp_lsb, spp_msb};

        midiOut->sendMessage(&songPosition);
        midiOut->sendMessage(&midiContinue);

        cdjStart = 2;

        std::cout << "MIDI_CLOCK_START" << std::endl;
        
        return 0;
    }

    noCount++;

    // stop midi if no CDJ is sending
    if((noCount > 70 || midiOn == 0)) 
    {
        midiOut->sendMessage(&midiStop);

        std::cout << "MIDI_CLOCK_STOP" << std::endl;

        // clear bits (set to last 4/4 beat)
        songPositionPointer &= ~(0b11); 
        SongPositionOut();

        noCount = 0;
        cdjStart = 0;
        midiOn = 2;

        return 0;
    }

    return 0;
}

int CdjClock::Run() {
    if (midiDeviceIn == -1|| midiDeviceOut == -1) {
        ProbeMidi();
        return 1;
    }

    SetupMidi();

    char errBuf[PCAP_ERRBUF_SIZE];      // error buffer
    pcap_t *handle;                     // packet capture handle
    char filterExp[] = "port 50001";    // filter expression
    struct bpf_program fp;              // compiled filter program
    bpf_u_int32 mask;                   // subnet mask
    bpf_u_int32 net;                    // ip
    int numPackets = 0;                 // number of capture packets
    int immediateModeOn = 1;

    char *device = new char[netDevice.size() + 1];
    std::copy(netDevice.begin(), netDevice.end(), device);
    device[netDevice.size()] = '\0';

    if (device == NULL) {
        device = pcap_lookupdev(errBuf);
        if (device == NULL) {
            std::cerr << "DEVICE_ALLOC_ERR: " << errBuf << std::endl;
            return 1;
        }
    }

    if (pcap_lookupnet(device, &net, &mask, errBuf) == -1) {
        std::cerr << "NETMASK_ERR: " << device << " " << errBuf << std::endl;
        net = 0; 
        mask = 0;
    }

    std::cout << "CAPTURE_DEVICE: " << device << std::endl;
    std::cout << "FILTER: " << filterExp << std::endl;

    if (cdjSync == 9) {
        std::cout << "SYNC_CDJ_1_4" << std::endl;
    } else if (cdjSync != 0) {
        std::cout << "SYNC_CDJ" << cdjSync << std::endl;
    } else {
        std::cout << "SYNC_DJM" << std::endl;
    }

    std::cerr << "MIDI_SYNC_START_STOP_CHAN: " << midiChannelIn      << " " 
              << "START: "                     << midiKeyContinue    << " "
              << "STOP: "                      << midiKeyStop        << " "
              << "UP: "                        << songPointerUp      << " "
              << "DOWN: "                      << songPointerDown    << " "
              << "SHIFT_UP: "                  << songPointerShiftUp << " "
              << "SHIFT_DOWN: "                << songPointerShiftDown 
              << std::endl;    

    handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errBuf);

    if (handle == NULL) {
        std::cerr << "DEVICE_OPEN_ERR:" << device << " " << errBuf << std::endl;
        return 1;
    } else {
        int fd = pcap_fileno(handle);

        if (fd == -1) {
            std::cerr << "FD_FILE_DESCRIPTOR_GET_ERROR" << std::endl;
            return 2; 
        }

        if (ioctl(fd, BIOCIMMEDIATE, &immediateModeOn) == -1) {
            std::cerr << "BIOCIMMEDIATE_ERR: " << errBuf << std::endl;
            return 2;
        }
    }

    // Ethernet device capture
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "NOT_ETHERNET_ERR: " << device << std::endl;
        return 1;
    }
    
    // filter expression
    if (pcap_compile(handle, &fp, filterExp, 0, net) == -1) {
        std::cerr << "PARSE_FILTER_ERR: " << filterExp << std::endl;
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "INSTALL_FILTER_ERR: " << filterExp << std::endl;
        return 1;
    }
    
    // SIGALRM calls MIDItimer()
    CdjClockMidiTimer = std::bind(&CdjClock::MidiTimer, 
                                 this, 
                                 std::placeholders::_1); 

    if (signal(SIGALRM, MidiTimerHandler) == SIG_ERR) {
        std::cerr << "SIGALRM_ERR" << std::endl;
    }

    it_val.it_value.tv_sec = tickCounts / 1000;
    it_val.it_value.tv_usec = tickCounts * 1000;
    it_val.it_interval = it_val.it_value;

    if (setitimer(ITIMER_REAL, &it_val, NULL) == -1) {
        std::cerr << "TIMER_SET_ERR" << std::endl;
    }


    pthread_t loopThread;

    int iret;
    
    PcapArgs pcapArgs;
    pcapArgs.cdjClock = this;
    pcapArgs.numPackets = numPackets;
    pcapArgs.handle = handle;

    iret = pthread_create(&loopThread, 
                          NULL, 
                          pcapLoop,
                          &pcapArgs);

    pthread_join(loopThread, NULL);

    pcap_freecode(&fp); 
    pcap_close(handle);
    delete[] device;

    return iret;
}

void GotPacketHandler(u_char *args, 
                      const struct pcap_pkthdr *header, 
                      const u_char *packet) {
    ((CdjClock*) args)->GotPacket(header, packet);
}

static void *pcapLoop(void *arg) { 
    PcapArgs *pcapArgs = (PcapArgs *) arg;

    pcap_loop(pcapArgs->handle, 
              pcapArgs->numPackets, 
              GotPacketHandler, 
              (u_char *) pcapArgs->cdjClock);

    return NULL;
}

void MidiTimerHandler(int i){
    CdjClockMidiTimer(i);
    return;
}

void MidiInCallbackHandler(double deltatime, 
                           std::vector<unsigned char> *message, 
                           void *args) {
    ((CdjClock*) args)->MidiInCallback(deltatime, message);
}
