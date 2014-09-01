Cmake_minimum_required(VERSION 2.8.12.2)

project(notesdrive)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

add_executable(notesdrive authentication/ecdsa-authentication.cpp encryption/aes-encryption.cpp authentication/ecdh-authentication.cpp authentication/utils-authentication.cpp authentication/authentication.cpp networking/networking.cpp encryption/utils-encryption.cpp hashing/sha3-hashing.cpp ui/notesdrive_connectdialog.cpp ui/notesdrive_mainframe.cpp ui/notesdrive_app.cpp main.cpp)

install(TARGETS notesdrive RUNTIME DESTINATION bin)

SET(wxWidgets_USE_LIBS)
FIND_PACKAGE(wxWidgets REQUIRED)
IF(wxWidgets_FOUND)
    INCLUDE("${wxWidgets_USE_FILE}")
    # and for each of your dependant executable/library targets:
    TARGET_LINK_LIBRARIES(notesdrive ${wxWidgets_LIBRARIES})
    MESSAGE(STATUS "** wxWidgets Include: ${wxWidgets_INCLUDE_DIR}")
    MESSAGE(STATUS "** wxWidgets Libraries: ${wxWidgets_LIBRARIES}")
ELSE(wxWidgets_FOUND)
    # For convenience. When we cannot continue, inform the user
    MESSAGE("wxWidgets not found!")
ENDIF(wxWidgets_FOUND)

FIND_PACKAGE(Boost 1.54 COMPONENTS system thread chrono filesystem date_time REQUIRED)
IF (Boost_FOUND)
    INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})
    ADD_DEFINITIONS( "-DHAS_BOOST" )
    LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})
    target_link_libraries(notesdrive ${Boost_LIBRARIES})
    MESSAGE(STATUS "** Boost Include: ${Boost_INCLUDE_DIR}")
    MESSAGE(STATUS "** Boost Libraries: ${Boost_LIBRARIES}")
ENDIF(Boost_FOUND)

FIND_PACKAGE(CryptoPP REQUIRED)
IF (CRYPTOPP_FOUND)
    INCLUDE_DIRECTORIES(/usr/include/cryptopp)
    LINK_DIRECTORIES(${CRYPTOPP_LIBRARIES})
    target_link_libraries(notesdrive ${CRYPTOPP_LIBRARIES})
    MESSAGE(STATUS "** CryptoPP Include: /usr/include/cryptopp")
    MESSAGE(STATUS "** CryptoPP Libraries: ${CRYPTOPP_LIBRARIES}")
ENDIF(CRYPTOPP_FOUND)