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
#set(COMPONENT_NAME ngtcp2)

set(ENABLE_WOLFSSL true)
set(PROJECT_VERSION         "0.1.1")
set(PACKAGE_VERSION_NUM     0x000001)
set(PACKAGE_VERSION         "${PROJECT_VERSION}")

message(STATUS "setting idf component register for ngtcp2 component")

# mbedtls can be specified as REQUIRES
idf_component_register(
    SRC_DIRS lib crypto crypto/wolfssl
    INCLUDE_DIRS lib lib/includes crypto crypto/includes
    PRIV_REQUIRES wolfssl 
)

# to help solve circular component issues - DIDNT WORK
# message(STATUS "Component lib is ${COMPONENT_TARGET}")
# set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY LINK_INTERFACE_MULTIPLICITY 4)

# message(STATUS "${COMPONENT_TARGET} and ${CMAKE_SOURCE_DIR}/components/wolfssl/")
#target_include_directories(${COMPONENT_TARGET} PRIVATE ${CMAKE_SOURCE_DIR}/components/wolfssl/wolfssl)

message(STATUS "finished idf component register for ngtcp2 component")

add_compile_definitions(OPENSSL_ALL)
add_compile_definitions(OPENSSL_EXTRA)
add_compile_definitions(OPENSSL_EXTRA_X509_SMALL)

add_compile_definitions(WOLFSSL_AES_128)
add_compile_definitions(WOLFSSL_AES_DIRECT)
add_compile_definitions(WOLFSSL_AES_COUNTER)
add_compile_definitions(WOLFSSL_SHA384)
add_compile_definitions(WOLFSSL_QUIC)
add_compile_definitions(HAVE_AESGCM)
add_compile_definitions(HAVE_AESCCM)
add_compile_definitions(HAVE_EX_DATA)
add_compile_definitions(HAVE_SNI)
add_compile_definitions(HAVE_HKDF)
add_compile_definitions(HAVE_CHACHA)
add_compile_definitions(HAVE_POLY1305)
add_compile_definitions(HAVE_ALPN)
add_compile_definitions(HAVE_STUNNEL)
add_compile_definitions(WOLFSSL_TLS13)
add_compile_definitions(HAVE_ECC)
add_compile_definitions(HAVE_SESSION_TICKET)
add_compile_definitions(WOLFSSL_EARLY_DATA)

add_compile_definitions(WOLFSSL_ALT_CERT_CHAINS)

add_compile_definitions(WC_RSA_PSS)
add_compile_definitions(WOLFSSL_PSS_LONG_SALT)
add_compile_definitions(WOLFSSL_RSA_VFY)
add_compile_definitions(WOLFSSL_ASN)
add_compile_definitions(WC_RSA_NO_PADDING)

add_compile_definitions(WOLFSSL_ENCRYPTED_KEYS)
add_compile_definitions(HAVE_TLS_EXTENSIONS)
add_compile_definitions(HAVE_SUPPORTED_CURVES)

add_compile_definitions(WOLFSSL_SHA512)
add_compile_definitions(HAVE_ED25519)

add_compile_definitions(WOLFSSL_CERT_NAME_ALL)

add_compile_definitions(WOLFSSL_EITHER_SIDE)
add_compile_definitions(WOLFSSL_TICKET_HAVE_ID)
add_compile_definitions(WOLFSSL_ERROR_CODE_OPENSSL)

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



