cmake_minimum_required(VERSION 3.0)
project(btle-tools C)
set(MAJOR_VERSION 0)
set(MINOR_VERSION 5)
set(PACKAGE btle-tools)
set(VERSION_STRING ${MAJOR_VERSION}.${MINOR_VERSION})
set(VERSION ${VERSION_STRING})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/modules)

if(MSVC)
# include_directories(getopt)
add_definitions(/D _CRT_SECURE_NO_WARNINGS)
else()
add_definitions(-Wall)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu90")
endif()

# Find needed packages.
MESSAGE(STATUS "Use HACKRF")
find_package(LIBHACKRF REQUIRED)
include_directories(${LIBHACKRF_INCLUDE_DIR})
set(USE_RFBOARD "USE_HACKRF")

CONFIGURE_FILE (
  "${PROJECT_SOURCE_DIR}/include/common.h.in"
  "${PROJECT_SOURCE_DIR}/src/common.h"
)

add_subdirectory(src)

########################################################################
# Create uninstall target
########################################################################

configure_file(
    ${PROJECT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
@ONLY)


add_custom_target(uninstall
    ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)

########################################################################
# Install udev rules
########################################################################
option(INSTALL_UDEV_RULES "Install udev rules for HackRF" OFF)
if (INSTALL_UDEV_RULES)
    install (
        FILES 52-hackrf.rules
        DESTINATION "/etc/udev/rules.d"
        COMPONENT "udev"
        )
else (INSTALL_UDEV_RULES)
    message (STATUS "Udev rules not being installed, install them with -DINSTALL_UDEV_RULES=ON")
endif (INSTALL_UDEV_RULES)