idf_component_register(SRCS "quic_helper.c" "ngtcp2_port.c" "wifi_connect.c"
                       INCLUDE_DIRS "." "./include")
                

message(STATUS "Configured main component with dependencies")
