project (cdjclock)

set (CMAKE_CXX_STANDARD 11)

include_directories(src)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

find_package(PCAP REQUIRED)

add_executable(cdjclock
               src/main.cpp
               src/CdjClock.cpp 
               src/RtMidi.cpp)

IF (APPLE)
  add_compile_definitions(__MACOSX_CORE__)

  find_library(audioToolbox AudioToolbox)
  find_library(audioUnit AudioUnit)
  find_library(coreAudio CoreAudio)
  find_library(coreMidi CoreMIDI)
  find_library(coreFoundation CoreFoundation)

  set(systemLibs
      ${audioToolbox}
      ${audioUnit}
      ${coreAudio}
      ${coreMidi}
      ${coreFoundation})


  target_link_libraries(cdjclock  
                        ${coreAudio} 
                        ${audioToolbox}
                        ${coreMidi} 
                        ${coreFoundation}
                        ${PCAP_LIBRARY})
                        
ENDIF (APPLE)

IF (LINUX)
  add_compile_definitions(__LINUX_ALSA__ )
  
  find_package(ALSA REQUIRED)

  if (ALSA_FOUND)
    include_directories(${ALSA_INCLUDE_DIRS})                  
    target_link_libraries (cdjClock ${ALSA_LIBRARIES})
  ENDIF (ALSA_FOUND)

ENDIF (LINUX)

