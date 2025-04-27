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
#include "esp_sleep.h"

#include <quic_init_client.h>
#include <test_streams.h>
#include <throughput.h>

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

void check_memory_here() {
    size_t total_heap = heap_caps_get_total_size(MALLOC_CAP_8BIT);
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    
    printf("Total heap: %d bytes, Free heap: %d bytes\n", total_heap, free_heap);
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
    

    // to debug wolfssl - uncomment this line
    //wolfSSL_Debugging_ON();
    int num_streams = 3;    
    
    // to run throughput or test streams examples, uncomment either example
    // throughput(main_task_handle, 1, num_streams);
    test_streams(main_task_handle, 1, num_streams);

    ESP_LOGI(TAG, "example complete");
    
    return;
}

void app_main_task(void *pvParameters) {
    main_task_handle = xTaskGetCurrentTaskHandle();
    app_main_logic();  // calls the main application logic
    while(1) { // yield to scheduler - program is finished at this point
        vTaskDelay(1000);
    }
    vTaskDelete(NULL);
    return;
}


#define MAIN_TASK_STACK_SIZE 30000

void app_main(void){
    check_memory_here();
    xTaskCreate(app_main_task, "app_main_task", MAIN_TASK_STACK_SIZE, NULL, 5, NULL);
    return;
}
