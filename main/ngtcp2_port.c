#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <inttypes.h>
#include <quic_init_client.h>
#include "wifi_connect.h"
#include "nvs_flash.h"
#include <esp_log.h>

static const char* TAG = "app_main";

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_ESPIDF
        #warning "Problem with wolfSSL user_settings."
        #warning "Check components/wolfssl/include"
    #endif
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif


void app_main_logic(void) {
    // Initialize wolfSSL library
    esp_err_t ret = 0;

    //ngtcp2_path path = set_ngtcp2_path("192.168.1.2", "192.168.1.1", 12345, 443);
    
    // initialise the flash - used to store wifi credentials
    ESP_ERROR_CHECK(nvs_flash_init());

    // connect to wifi
    ret = wifi_init_sta();
        while (ret != 0) {
            ESP_LOGI(TAG, "Waiting...");
            vTaskDelay(60000 / portTICK_PERIOD_MS);
            ESP_LOGI(TAG, "Trying WiFi again...");
            ret = wifi_init_sta();
        }

    
    /*
    intialise quic client - this currently sets up the quic client object and
    performs a handshake with google.com (as an example)
    */ 

    quic_init_client();    
}

void app_main_task(void *pvParameters) {
    app_main_logic();  // This will call your app_main logic
    vTaskDelete(NULL);
}

#define MAIN_TASK_STACK_SIZE 16384

void app_main(void){
    xTaskCreate(app_main_task, "app_main_task", MAIN_TASK_STACK_SIZE, NULL, 5, NULL);
}
