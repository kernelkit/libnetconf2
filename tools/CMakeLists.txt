if(NOT LIBNETCONF2_VERSION)
    message(FATAL_ERROR "Please use the root CMakeLists file instead.")
endif()

# use the generated public headers
include_directories(BEFORE "${PROJECT_BINARY_DIR}/include")

add_executable(netconf-subsystem netconf-subsystem.c)
target_link_libraries(netconf-subsystem netconf2)
target_compile_definitions(netconf-subsystem PRIVATE NC_SUBSYSTEM_SOCKET="${NC_SUBSYSTEM_SOCKET}")

install(TARGETS netconf-subsystem DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/libnetconf2)
