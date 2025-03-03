#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <ngtcp2/ngtcp2.h>
#include <inttypes.h>
#include "wifi_connect.h"
#include "ngtcp2_port.h"
#include "nvs_flash.h"
#include <esp_log.h>
#include <time.h>
#include <stdlib.h>
#include "esp_sntp.h"
#include <sys/time.h>


#include <quic_init_client.h>
#include <uni_stream.h>

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

TaskHandle_t main_task_handle = NULL;

// set the system time to 2025 - so CA cert is in-date 
void set_system_time() {
    struct timeval tv;
    struct tm tm_time = {
        .tm_year = 2025 - 1900, 
        .tm_mon  = 0,          
        .tm_mday = 1,           
        .tm_hour = 12,          
        .tm_min  = 0,
        .tm_sec  = 0
    };

    tv.tv_sec = mktime(&tm_time);
    tv.tv_usec = 0;

    settimeofday(&tv, NULL); 
    printf("Time manually set to: %s", asctime(&tm_time));
}

void app_main_logic(void) {
    esp_err_t ret = 0;
    
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

    set_system_time();  
    
    //wolfSSL_Debugging_ON();
    //quic_init_client();
    
    uni_stream(main_task_handle);
    
    return;
}

void app_main_task(void *pvParameters) {
    main_task_handle = xTaskGetCurrentTaskHandle();
    app_main_logic();  // calls the main application logic
    vTaskDelete(NULL);
    return;
}


#define MAIN_TASK_STACK_SIZE 35000

void app_main(void){
    xTaskCreate(app_main_task, "app_main_task", MAIN_TASK_STACK_SIZE, NULL, 5, NULL);
}
