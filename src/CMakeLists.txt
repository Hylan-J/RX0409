set(INSTALL_DEFAULT_BINDIR "bin" CACHE STRING "Appended to CMAKE_INSTALL_PREFIX")

if(MSVC)
add_library(libgetopt_static STATIC
    ../getopt/getopt.c
)
endif()


add_executable(btle_rx btle_rx.c)
install(TARGETS btle_rx RUNTIME DESTINATION ${INSTALL_DEFAULT_BINDIR})


include_directories(${LIBHACKRF_INCLUDE_DIR})
LIST(APPEND TOOLS_LINK_LIBS ${LIBHACKRF_LIBRARIES})

IF(NOT DEFINED C_INLINE)
   ADD_DEFINITIONS("-Dinline=")
ENDIF(NOT DEFINED C_INLINE)

if(MSVC)
LIST(APPEND TOOLS_LINK_LIBS libgetopt_static)
endif()

target_link_libraries(btle_rx ${TOOLS_LINK_LIBS} m)

