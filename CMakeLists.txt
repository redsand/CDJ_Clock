project (cdjclock)

include_directories(src)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

find_package(PCAP REQUIRED)

add_executable(cdjclock src/main.c src/set_immediate_mode.c)

IF (APPLE)
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

