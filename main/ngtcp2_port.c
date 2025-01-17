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

void app_main(void) {
    // Initialize wolfSSL library
    wolfSSL_Init();
    esp_err_t ret = 0;

    // Create a wolfSSL context
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (ctx == NULL) {
        printf("wolfSSL_CTX_new error\n");
        wolfSSL_Cleanup();
        return;
    }
    printf("wolfSSL context created successfully.\n");

    /*
    esp_err_t ret = wifi_init_sta();
    while (ret != 0) {
        vTaskDelay(60000 / portTICK_PERIOD_MS);
        ret = wifi_init_sta();
    } 
    */
           
    //ngtcp2_path path = set_ngtcp2_path("192.168.1.2", "192.168.1.1", 12345, 443);
    
    ESP_ERROR_CHECK(nvs_flash_init());
    
    ret = wifi_init_sta();
        while (ret != 0) {
            ESP_LOGI(TAG, "Waiting...");
            vTaskDelay(60000 / portTICK_PERIOD_MS);
            ESP_LOGI(TAG, "Trying WiFi again...");
            ret = wifi_init_sta();
        }

    quic_init_client();

    //quic_client_cleanup();
    
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    printf("wolfSSL cleaned up.\n");
}
