# ngtcp2
#
# Copyright (c) 2016 ngtcp2 contributors
# Copyright (c) 2012 nghttp2 contributors
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


#########################################################################################################
#########################################################################################################
# My code
#########################################################################################################
#########################################################################################################
message(STATUS "************************************************************************************************")
message(STATUS "                                 beginning ngtcp2 config                                        ")
message(STATUS "************************************************************************************************")

cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0063 NEW)

# TODO : strip this down so only include wolfssl in the crypto etc
set(COMPONENT_NAME ngtcp2)


idf_component_register(SRCS
                       SRC_DIRS ./lib ./crypto ./crypto/wolfssl
                       INCLUDE_DIRS ./lib ./lib/includes ./crypto/includes
                       REQUIRES wolfssl)

set(ENABLE_WOLFSSL ON CACHE BOOL "Enable wolfSSL as crypto")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" "${CMAKE_MODULE_PATH}")
include(Version)

include(GNUInstallDirs)
include(CMakeDependentOption)
include(CMakeOptions.txt)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckCXXSymbolExists)
include(CheckIncludeFile)
check_include_file("arpa/inet.h"   HAVE_ARPA_INET_H)
check_include_file("netinet/in.h"  HAVE_NETINET_IN_H)
check_include_file("netinet/ip.h"  HAVE_NETINET_IP_H)
check_include_file("unistd.h"      HAVE_UNISTD_H)
check_include_file("sys/endian.h"  HAVE_SYS_ENDIAN_H)
check_include_file("endian.h"      HAVE_ENDIAN_H)
check_include_file("byteswap.h"    HAVE_BYTESWAP_H)
check_include_file("asm/types.h"   HAVE_ASM_TYPES_H)
check_include_file("linux/netlink.h"   HAVE_LINUX_NETLINK_H)
check_include_file("linux/rtnetlink.h" HAVE_LINUX_RTNETLINK_H)

include(CheckTypeSize)
# Checks for typedefs, structures, and compiler characteristics.
# AC_TYPE_SIZE_T
check_type_size("ssize_t" SIZEOF_SSIZE_T)
if(SIZEOF_SSIZE_T STREQUAL "")
  # ssize_t is a signed type in POSIX storing at least -1.
  # Set it to a pointer-size int.
  set(ssize_t ptrdiff_t)
endif()

if(HAVE_ENDIAN_H)
  check_symbol_exists(be64toh "endian.h" HAVE_DECL_BE64TOH)
endif()
if(NOT HAVE_DECL_BE64TOH AND HAVE_SYS_ENDIAN_H)
  check_symbol_exists(be64toh "sys/endian.h" HAVE_DECL_BE64TOH)
endif()

check_symbol_exists(bswap_64 "byteswap.h" HAVE_DECL_BSWAP_64)
check_symbol_exists(explicit_bzero "string.h" HAVE_EXPLICIT_BZERO)
check_symbol_exists(memset_s "string.h" HAVE_MEMSET_S)


set(WARNCFLAGS)
set(WARNCXXFLAGS)
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
  if(ENABLE_WERROR)
    set(WARNCFLAGS    /WX)
    set(WARNCXXFLAGS  /WX)
  endif()
else()
  if(ENABLE_WERROR)
    set(WARNCFLAGS   "-Werror")
    set(WARNCXXFLAGS "-Werror")
  endif()

  include(PickyWarningsC)
  include(PickyWarningsCXX)
endif()

if(ENABLE_DEBUG)
  set(DEBUGBUILD 1)
endif()

if(ENABLE_WOLFSSL)
  set(WOLFSSL_INCLUDE_DIRS  ${WOLFSSL_INCLUDE_DIR})
  set(HAVE_WOLFSSL TRUE)
  set(HAVE_CRYPTO TRUE)
else()
  set(HAVE_WOLFSSL FALSE)
  set(WOLFSSL_INCLUDE_DIRS  "")
  set(WOLFSSL_LIBRARIES     "")
endif()

add_definitions(-DHAVE_CONFIG_H)
configure_file(cmakeconfig.h.in config.h)
# autotools-compatible names
# Sphinx expects relative paths in the .rst files. Use the fact that the files
# below are all one directory level deep.
file(RELATIVE_PATH top_srcdir   "${CMAKE_CURRENT_BINARY_DIR}/dir" "${CMAKE_CURRENT_SOURCE_DIR}")
file(RELATIVE_PATH top_builddir "${CMAKE_CURRENT_BINARY_DIR}/dir" "${CMAKE_CURRENT_BINARY_DIR}")
set(abs_top_srcdir  "${CMAKE_CURRENT_SOURCE_DIR}")
set(abs_top_builddir "${CMAKE_CURRENT_BINARY_DIR}")
# libngtcp2.pc (pkg-config file)
set(prefix          "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix     "${CMAKE_INSTALL_PREFIX}")
set(libdir          "${CMAKE_INSTALL_FULL_LIBDIR}")
set(includedir      "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set(VERSION         "${PACKAGE_VERSION}")
# For init scripts and systemd service file (in contrib/)
set(bindir          "${CMAKE_INSTALL_FULL_BINDIR}")
set(sbindir         "${CMAKE_INSTALL_FULL_SBINDIR}")
foreach(name
  lib/libngtcp2.pc
  lib/includes/ngtcp2/version.h
)
  configure_file("${name}.in" "${name}" @ONLY)
endforeach()

include_directories(
  "${CMAKE_CURRENT_BINARY_DIR}" # for config.h
)
# For use in src/CMakeLists.txt
set(PKGDATADIR "${CMAKE_INSTALL_FULL_DATADIR}/${CMAKE_PROJECT_NAME}")

add_subdirectory(lib)
add_subdirectory(crypto)
add_subdirectory(third-party)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wno-maybe-uninitialized)
endif()

string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)
message(STATUS "summary of build options:

    Package version: ${VERSION}
    Library version: ${LT_CURRENT}:${LT_REVISION}:${LT_AGE}
    Install prefix:  ${CMAKE_INSTALL_PREFIX}
    Target system:   ${CMAKE_SYSTEM_NAME}
    Compiler:
      Build type:     ${CMAKE_BUILD_TYPE}
      C compiler:     ${CMAKE_C_COMPILER}
      CFLAGS:         ${CMAKE_C_FLAGS_${_build_type}} ${CMAKE_C_FLAGS}
      C++ compiler:   ${CMAKE_CXX_COMPILER}
      CXXFLAGS:       ${CMAKE_CXX_FLAGS_${_build_type}} ${CMAKE_CXX_FLAGS}
      WARNCFLAGS:     ${WARNCFLAGS}
      WARNCXXFLAGS:   ${WARNCXXFLAGS}
    Library:
      Shared:         ${ENABLE_SHARED_LIB}
      Static:         ${ENABLE_STATIC_LIB}
    Test:
      Build Test:     ${BUILD_TESTING}
    Libs:
      OpenSSL:        ${HAVE_OPENSSL} (LIBS='${OPENSSL_LIBRARIES}')
      Libev:          ${HAVE_LIBEV} (LIBS='${LIBEV_LIBRARIES}')
      Libnghttp3:     ${HAVE_LIBNGHTTP3} (LIBS='${LIBNGHTTP3_LIBRARIES}')
      GnuTLS:         ${HAVE_GNUTLS} (LIBS='${GNUTLS_LIBRARIES}')
      BoringSSL:      ${HAVE_BORINGSSL} (LIBS='${BORINGSSL_LIBRARIES}')
      Picotls:        ${HAVE_PICOTLS} (LIBS='${PICOTLS_LIBRARIES}')
      wolfSSL:        ${HAVE_WOLFSSL} (LIBS='${WOLFSSL_LIBRARIES}')
      Jemalloc:       ${HAVE_JEMALLOC} (LIBS='${JEMALLOC_LIBRARIES}')
      Libbrotlienc:   ${HAVE_LIBBROTLIENC} (LIBS='${LIBBROTLIENC_LIBRARIES}')
      Libbrotlidec:   ${HAVE_LIBBROTLIDEC} (LIBS='${LIBBROTLIDEC_LIBRARIES}')
")


message(STATUS "************************************************************************************************")
message(STATUS "                                  finished ngtcp2 config                                        ")
message(STATUS "************************************************************************************************")


#########################################################################################################
#########################################################################################################
# My code
#########################################################################################################
#########################################################################################################



