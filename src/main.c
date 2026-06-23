#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_task_wdt.h"
#include "esp_attr.h"
#include "soc/gpio_reg.h"

#define POST_BIT7_PIN    GPIO_NUM_32  // FT5R8
#define POST_BIT6_PIN    GPIO_NUM_33  // FT5R7
#define POST_BIT5_PIN    GPIO_NUM_25  // FT5R6
#define POST_BIT4_PIN    GPIO_NUM_26  // FT5R5
#define POST_BIT3_PIN    GPIO_NUM_27  // FT5R4
#define POST_BIT2_PIN    GPIO_NUM_14  // FT5R3
#define POST_BIT1_PIN    GPIO_NUM_12  // FT5R2
#define POST_BIT0_PIN    GPIO_NUM_13  // FT5R1

#define KERNEL_UART_NUM       UART_NUM_2
#define KERNEL_UART_ESP32_RX  GPIO_NUM_18  // D18 - ESP32 RX (from Xbox TX)
#define KERNEL_UART_ESP32_TX  GPIO_NUM_19  // D19 - ESP32 TX (to Xbox RX) (NOTE: Do not connect the tx as this for some reason makes rx stop working)
#define KERNEL_UART_BUF_SIZE  1024
#define KERNEL_UART_BAUD      115200

// This part does not work yet please stay tuned
#define SMC_UART_NUM          UART_NUM_1
#define SMC_UART_ESP32_RX     GPIO_NUM_21  // D21 - ESP32 RX (from Xbox SMC TX)
#define SMC_UART_ESP32_TX     GPIO_NUM_22  // D22 - ESP32 TX (to Xbox SMC RX)
#define SMC_UART_BUF_SIZE     256
#define SMC_UART_BAUD         115200

#define MAX_CAPTURED_CODES 512

static const char *TAG = "PostReader";

typedef struct {
    uint8_t code;
    const char *stage;
    const char *description;
} post_code_entry_t;

typedef struct {
    uint8_t code;
    int64_t timestamp;
} captured_code_t;

static const post_code_entry_t post_codes[] = {
    // 1BL
    {0x10, "1BL", "1BL started"},
    {0x11, "1BL", "Execute FSB function 1"},
    {0x12, "1BL", "Execute FSB function 2"},
    {0x13, "1BL", "Execute FSB function 3"},
    {0x14, "1BL", "Execute FSB function 4"},
    {0x15, "1BL", "Verify CB offset"},
    {0x16, "1BL", "Copy CB header from NAND"},
    {0x17, "1BL", "Verify CB header"},
    {0x18, "1BL", "Copy CB into protected SRAM"},
    {0x19, "1BL", "Generate CB HMAC key"},
    {0x1A, "1BL", "Initialize CB RC4 decryption key"},
    {0x1B, "1BL", "RC4 decrypt CB"},
    {0x1C, "1BL", "Generate hash of CB for verification"},
    {0x1D, "1BL", "RSA signature check of CB hash"},
    {0x1E, "1BL", "Jump to CB"},
    // 1BL Panics
    {0x81, "1BL PANIC", "Machine check"},
    {0x82, "1BL PANIC", "Data storage"},
    {0x83, "1BL PANIC", "Data segment"},
    {0x84, "1BL PANIC", "Instruction storage"},
    {0x85, "1BL PANIC", "Instruction segment"},
    {0x86, "1BL PANIC", "External"},
    {0x87, "1BL PANIC", "Alignment"},
    {0x88, "1BL PANIC", "Program"},
    {0x89, "1BL PANIC", "FPU unavailable"},
    {0x8A, "1BL PANIC", "Decrementer"},
    {0x8B, "1BL PANIC", "Hypervisor decrementer"},
    {0x8C, "1BL PANIC", "System call"},
    {0x8D, "1BL PANIC", "Trace"},
    {0x8E, "1BL PANIC", "VPU unavailable"},
    {0x8F, "1BL PANIC", "Maintenance"},
    {0x90, "1BL PANIC", "VMX assist"},
    {0x91, "1BL PANIC", "Thermal management"},
    {0x92, "1BL PANIC", "1BL executed on wrong CPU thread"},
    {0x93, "1BL PANIC", "1BL executed on wrong CPU core"},
    {0x94, "1BL PANIC", "CB offset verification failed"},
    {0x95, "1BL PANIC", "CB header verification failed"},
    {0x96, "1BL PANIC", "CB RSA signature verification failed"},
    {0x97, "1BL PANIC", "Non-host resume status"},
    {0x98, "1BL PANIC", "Next stage size out-of-bounds"},
    // CB_A (Slim only)
    {0xD0, "CB_A", "CB_A entry point"},
    {0xD1, "CB_A", "Copy fuses from SoC for CB_B decryption"},
    {0xD2, "CB_A", "Verify CB_B offset"},
    {0xD3, "CB_A", "Copy CB_B header from NAND"},
    {0xD4, "CB_A", "Verify CB_B header"},
    {0xD5, "CB_A", "Copy CB_B into memory"},
    {0xD6, "CB_A", "Generate CB_B hash"},
    {0xD7, "CB_A", "Initialize CB_B RC4"},
    {0xD8, "CB_A", "Decrypt CB_B"},
    {0xD9, "CB_A", "Compute CB_B hash"},
    {0xDA, "CB_A", "Verify CB_B hash (RGH2 glitch point)"},
    {0xDB, "CB_A", "Branch to CB_B"},
    {0x54, "UNK", "Possible RGH3 entry point"},
    // CB_A Panics
    {0xF0, "CB_A PANIC", "CB_B offset verification fail"},
    {0xF1, "CB_A PANIC", "CB_B header verification fail"},
    {0xF2, "CB_A PANIC", "CB_B security hash comparison fail"},
    {0xF3, "CB_A PANIC", "CB_B size check fail"},
    // CB/2BL
    {0x20, "CB", "CB entry point, initialize SoC"},
    {0x21, "CB", "Initialize secopt, verify lockdown fuses"},
    {0x22, "CB", "Initialize security engine"},
    {0x23, "CB", "Initialize EDRAM"},
    {0x24, "CB", "Verify CC offset"},
    {0x25, "CB", "Locate CC"},
    {0x26, "CB", "Fetch CC header from NAND"},
    {0x27, "CB", "Verify CC header"},
    {0x28, "CB", "Copy CC into SRAM"},
    {0x29, "CB", "Compute CC HMAC"},
    {0x2A, "CB", "Initialize CC RC4"},
    {0x2B, "CB", "RC4 decrypt CC"},
    {0x2C, "CB", "Compute CC hash"},
    {0x2D, "CB", "Verify CC signature"},
    {0x2E, "CB", "Hardware initialization"},
    {0x2F, "CB", "Setup TLB, relocate to RAM"},
    {0x30, "CB", "Verify CD offset"},
    {0x31, "CB", "Copy CD header from NAND"},
    {0x32, "CB", "Verify CD header"},
    {0x33, "CB", "Copy CD from NAND"},
    {0x34, "CB", "Create HMAC key for CD decryption"},
    {0x35, "CB", "Initialize CD RC4 key"},
    {0x36, "CB", "RC4 decrypt CD"},
    {0x37, "CB", "Compute hash of CD"},
    {0x38, "CB", "RSA signature check of CD hash"},
    {0x39, "CB", "MemCmp CD hash"},
    {0x3A, "CB", "Setup memory encryption, jump to CD"},
    {0x3B, "CB", "Initialize PCI"},
    // CB Panics
    {0x9B, "CB PANIC", "Secopt fuse verification fail"},
    {0x9C, "CB PANIC", "Secopt fuse verification fail 2"},
    {0x9D, "CB PANIC", "Console type verification fail"},
    {0x9E, "CB PANIC", "Console type verification fail"},
    {0x9F, "CB PANIC", "Console type verification fail"},
    {0xA0, "CB PANIC", "2BL LDV revocation mismatch"},
    {0xA1, "CB PANIC", "Verify Secure ROM 7"},
    {0xA2, "CB PANIC", "Verify Secure ROM 8"},
    {0xA3, "CB PANIC", "Verify Secure ROM 9"},
    {0xA4, "CB PANIC", "Verify SMC HMAC"},
    {0xA5, "CB PANIC", "Verify CC offset fail"},
    {0xA6, "CB PANIC", "Locate CC fail"},
    {0xA7, "CB PANIC", "Verify CC header fail"},
    {0xA8, "CB PANIC", "CC signature verify fail"},
    {0xA9, "CB PANIC", "Hardware init failed"},
    {0xAA, "CB PANIC", "Failed to verify CD offset"},
    {0xAB, "CB PANIC", "Failed to verify CD header"},
    {0xAC, "CB PANIC", "CD signature verify fail"},
    {0xAD, "CB PANIC", "CD security hash comparison fail"},
    {0xAE, "CB PANIC", "Unknown interrupt vector"},
    {0xAF, "CB PANIC", "Unsupported RAM size"},
    {0xB0, "CB PANIC", "Console type verification fail"},
    // CD/4BL
    {0x40, "CD", "CD entry point, setup memory paging"},
    {0x41, "CD", "Verify offset to CE"},
    {0x42, "CD", "Copy CE header from NAND"},
    {0x43, "CD", "Verify CE header"},
    {0x44, "CD", "Read CE from NAND into memory"},
    {0x45, "CD", "Create HMAC key for CE decryption"},
    {0x46, "CD", "Initialize CE RC4 key"},
    {0x47, "CD", "RC4 decrypt CE"},
    {0x48, "CD", "Compute hash of CE"},
    {0x49, "CD", "MemCmp CE hash (RGH1 glitch point)"},
    {0x4A, "CD", "Load CF"},
    {0x4B, "CD", "LZX decompress CE"},
    {0x4C, "CD", "Sweep caches"},
    {0x4D, "CD", "Decode fuses"},
    {0x4E, "CD", "Load CF offset"},
    {0x4F, "CD", "Verify CF offset"},
    {0x50, "CD", "Load CF1/CG1 (patch slot 1)"},
    {0x51, "CD", "Load CF2/CG2 (patch slot 2)"},
    {0x52, "CD", "Startup kernel/hypervisor"},
    {0x53, "CD", "Decrypt and verify HV cert"},
    // CD Panics
    {0xB1, "CD PANIC", "Verify 5BL offset failed"},
    {0xB2, "CD PANIC", "Verify 5BL header failed"},
    {0xB3, "CD PANIC", "5BL signature verify fail"},
    {0xB4, "CD PANIC", "CE LZX decompression failed"},
    {0xB5, "CD PANIC", "CF verification failed"},
    {0xB6, "CD PANIC", "Fuse decryption/check failed"},
    {0xB7, "CD PANIC", "CF decryption failed, patches missing"},
    {0xB8, "CD PANIC", "CF hash auth failed"},
    // CE/CF Panics
    {0xC1, "CE/CF PANIC", "LDICreateDecompression failed"},
    {0xC2, "CE/CF PANIC", "CG size verification failed"},
    {0xC3, "CE/CF PANIC", "Header/patch fragment info check failed"},
    {0xC4, "CE/CF PANIC", "Unexpected LDI fragment type"},
    {0xC5, "CE/CF PANIC", "LDISetWindowData failed"},
    {0xC6, "CE/CF PANIC", "LDIDecompress failed"},
    {0xC7, "CE/CF PANIC", "LDIResetDecompression failed"},
    {0xC8, "CE/CF PANIC", "CG auth failed"},
    // Hypervisor
    {0x58, "HV", "Hypervisor initialization begin"},
    {0x59, "HV", "Initialize SoC MMIO"},
    {0x5A, "HV", "Initialize XEX training"},
    {0x5B, "HV", "Initialize key ring"},
    {0x5C, "HV", "Initialize keys"},
    {0x5D, "HV", "Initialize SoC interrupts"},
    {0x5E, "HV", "Initialization complete"},
    {0x5F, "HV", "[POSSIBLE] Finalize and handoff to kernel"},
    // HV Panic
    {0xFF, "HV PANIC", "Fatal error"},
    // Kernel
    {0x60, "Kernel", "Initialize kernel"},
    {0x61, "Kernel", "Initialize HAL phase 0"},
    {0x62, "Kernel", "Initialize process objects"},
    {0x63, "Kernel", "Initialize kernel debugger"},
    {0x64, "Kernel", "Initialize memory manager"},
    {0x65, "Kernel", "Initialize stacks"},
    {0x66, "Kernel", "Initialize object system"},
    {0x67, "Kernel", "Initialize phase 1 thread"},
    {0x68, "Kernel", "Initialize processors"},
    {0x69, "Kernel", "Initialize keyvault"},
    {0x6A, "Kernel", "Initialize HAL phase 1"},
    {0x6B, "Kernel", "Initialize SFC (flash controller)"},
    {0x6C, "Kernel", "Initialize security"},
    {0x6D, "Kernel", "Initialize keyvault (extended)"},
    {0x6E, "Kernel", "Initialize settings"},
    {0x6F, "Kernel", "Initialize power mode"},
    {0x70, "Kernel", "Initialize video driver"},
    {0x71, "Kernel", "Initialize audio driver"},
    {0x72, "Kernel", "Initialize boot animation + XMA/XAudio"},
    {0x73, "Kernel", "Initialize SATA driver"},
    {0x74, "Kernel", "Initialize shadowboot"},
    {0x75, "Kernel", "Initialize dump system"},
    {0x76, "Kernel", "Initialize system root"},
    {0x77, "Kernel", "Initialize other drivers"},
    {0x78, "Kernel", "Initialize STFS driver"},
    {0x79, "Kernel", "Load XAM"},
    {0x00, "", ""}
};

static const post_code_entry_t* lookup_post_code(uint8_t code) {
    for (int i = 0; post_codes[i].stage[0] != '\0'; i++) {
        if (post_codes[i].code == code) {
            return &post_codes[i];
        }
    }
    return NULL;
}

static void print_post_code(uint8_t code, int64_t timestamp) {
    const post_code_entry_t* entry = lookup_post_code(code);
    int64_t timestamp_ms = timestamp / 1000;
    if (entry) {
        printf("%10lld ms | 0x%02X | %-10s | %s\n", timestamp_ms, code, entry->stage, entry->description);
    } else {
        printf("%10lld ms | 0x%02X | %-10s | %s\n", timestamp_ms, code, "???", "Unknown POST code");
    }
}

static captured_code_t capture_buffer[MAX_CAPTURED_CODES];
static volatile uint32_t capture_count = 0;

// This is really handy when debugging but otherwise useless, either way i'm leaving it in
static volatile bool post_codes_enabled = true;     // POST code GPIO capture
static volatile bool kernel_uart_enabled = true;      // Kernel UART output
static volatile bool smc_uart_enabled = true;         // SMC UART output

// Turbo: on
static inline uint8_t IRAM_ATTR read_post_bits(void) {
    uint32_t in0 = REG_READ(GPIO_IN_REG);   // GPIO 0-31
    uint32_t in1 = REG_READ(GPIO_IN1_REG);  // GPIO 32-39
    
    return (uint8_t)(
        (((in1 >> 0) & 1) << 7) |  // GPIO32 -> bit7
        (((in1 >> 1) & 1) << 6) |  // GPIO33 -> bit6
        (((in0 >> 25) & 1) << 5) | // GPIO25 -> bit5
        (((in0 >> 26) & 1) << 4) | // GPIO26 -> bit4
        (((in0 >> 27) & 1) << 3) | // GPIO27 -> bit3
        (((in0 >> 14) & 1) << 2) | // GPIO14 -> bit2
        (((in0 >> 12) & 1) << 1) | // GPIO12 -> bit1
        ((in0 >> 13) & 1)        // GPIO13 -> bit0
    );
}

static void IRAM_ATTR gpio_isr_handler(void *arg) {
    if (!post_codes_enabled) return;

    // Ask me what this does and i'll say "i don't know"
    uint8_t r1 = read_post_bits();
    uint8_t r2 = read_post_bits();
    uint8_t r3 = read_post_bits();

    uint8_t final = (r1 == r2) ? r1 : ((r2 == r3) ? r2 : r3);

    static uint8_t last_stable = 0xFF;

    // Only accept when post code changes (again due to my noisy code yep)
    if (final != last_stable && final != 0x00) {
        uint32_t current_count = capture_count;
        if (current_count < MAX_CAPTURED_CODES) {
            capture_buffer[current_count].code = final;
            capture_buffer[current_count].timestamp = esp_timer_get_time();
            capture_count = current_count + 1;
        }
        last_stable = final;
    }
}

// Kernel UART task
static void kernel_uart_task(void *pvParameters) {
    uint8_t data[KERNEL_UART_BUF_SIZE];
    char line_buffer[512];
    int line_pos = 0;

    ESP_LOGI(TAG, "Kernel UART task started on GPIO%d (RX) @ %d baud", KERNEL_UART_ESP32_RX, KERNEL_UART_BAUD);
    printf("\n[KERNEL UART] Listening on GPIO%d @ %d baud (output %s)...\n\n",
           KERNEL_UART_ESP32_RX, KERNEL_UART_BAUD, kernel_uart_enabled ? "enabled" : "disabled");

    while (1) {
        int len = uart_read_bytes(KERNEL_UART_NUM, data, KERNEL_UART_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        if (len > 0) {
            data[len] = '\0';
            if (!kernel_uart_enabled) {
                continue;
            }

            for (int i = 0; i < len; i++) {
                char c = (char)data[i];
                if (c == '\n' || c == '\r') {
                    if (line_pos > 0) {
                        line_buffer[line_pos] = '\0';
                        printf("[KERNEL] %s\n", line_buffer);
                        line_pos = 0;
                    }
                } else if (line_pos < sizeof(line_buffer) - 1) {
                    line_buffer[line_pos++] = c;
                }

                if (line_pos >= sizeof(line_buffer) - 2) {
                    line_buffer[line_pos] = '\0';
                    printf("[KERNEL] %s\n", line_buffer);
                    line_pos = 0;
                }
            }
        }
    }
}

// SMC UART task
static void smc_uart_task(void *pvParameters) {
    uint8_t data[SMC_UART_BUF_SIZE];
    char line_buffer[256];
    int line_pos = 0;

    ESP_LOGI(TAG, "SMC UART task started on GPIO%d (RX) @ %d baud", SMC_UART_ESP32_RX, SMC_UART_BAUD);
    printf("\n[SMC UART] Listening on GPIO%d @ %d baud (output %s)...\n\n",
           SMC_UART_ESP32_RX, SMC_UART_BAUD, smc_uart_enabled ? "enabled" : "disabled");

    while (1) {
        int len = uart_read_bytes(SMC_UART_NUM, data, SMC_UART_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        if (len > 0) {
            ESP_LOGI(TAG, "SMC UART received %d bytes", len);
            data[len] = '\0';
            if (!smc_uart_enabled) {
                ESP_LOGI(TAG, "SMC UART data discarded (output disabled)");
                continue;
            }

            for (int i = 0; i < len; i++) {
                char c = (char)data[i];
                if (c == '\n' || c == '\r') {
                    if (line_pos > 0) {
                        line_buffer[line_pos] = '\0';
                        printf("[SMC] %s\n", line_buffer);
                        line_pos = 0;
                    }
                } else if (line_pos < sizeof(line_buffer) - 1) {
                    line_buffer[line_pos++] = c;
                }

                if (line_pos >= sizeof(line_buffer) - 2) {
                    line_buffer[line_pos] = '\0';
                    printf("[SMC] %s\n", line_buffer);
                    line_pos = 0;
                }
            }
        }
    }
}

// kernel UART
static void init_kernel_uart(void) {
    uart_config_t uart_config = {
        .baud_rate = KERNEL_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(KERNEL_UART_NUM, KERNEL_UART_BUF_SIZE * 2, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(KERNEL_UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(KERNEL_UART_NUM, KERNEL_UART_ESP32_TX, KERNEL_UART_ESP32_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(gpio_set_pull_mode(KERNEL_UART_ESP32_RX, GPIO_PULLUP_ONLY));
}

// SMC UART
static void init_smc_uart(void) {
    uart_config_t uart_config = {
        .baud_rate = SMC_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(SMC_UART_NUM, SMC_UART_BUF_SIZE * 2, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(SMC_UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(SMC_UART_NUM, SMC_UART_ESP32_TX, SMC_UART_ESP32_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(gpio_set_pull_mode(SMC_UART_ESP32_RX, GPIO_PULLUP_ONLY));
}

void app_main(void) {
    // Configure all POST pins as inputs with interrupts (does what it says on the tin)
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << POST_BIT7_PIN) | (1ULL << POST_BIT6_PIN) |
                       (1ULL << POST_BIT5_PIN) | (1ULL << POST_BIT4_PIN) |
                       (1ULL << POST_BIT3_PIN) | (1ULL << POST_BIT2_PIN) |
                       (1ULL << POST_BIT1_PIN) | (1ULL << POST_BIT0_PIN),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_ANYEDGE,
    };
    gpio_config(&io_conf);

    // Install GPIO interrupt service (for per-pin interrupt handling)
    gpio_install_isr_service(0);

    // Add ISR handler to all POST pins (it wont work otherwise)
    gpio_isr_handler_add(POST_BIT7_PIN, gpio_isr_handler, NULL);
    gpio_isr_handler_add(POST_BIT6_PIN, gpio_isr_handler, NULL);
    gpio_isr_handler_add(POST_BIT5_PIN, gpio_isr_handler, NULL);
    gpio_isr_handler_add(POST_BIT4_PIN, gpio_isr_handler, NULL);
    gpio_isr_handler_add(POST_BIT3_PIN, gpio_isr_handler, NULL);
    gpio_isr_handler_add(POST_BIT2_PIN, gpio_isr_handler, NULL);
    gpio_isr_handler_add(POST_BIT1_PIN, gpio_isr_handler, NULL);
    gpio_isr_handler_add(POST_BIT0_PIN, gpio_isr_handler, NULL);

    // UART
    init_kernel_uart();
    init_smc_uart();

    // UART tasks
    xTaskCreate(kernel_uart_task, "kernel_uart", 4096, NULL, 5, NULL);
    xTaskCreate(smc_uart_task, "smc_uart", 4096, NULL, 5, NULL);

    ESP_LOGI(TAG, "Xbox 360 POST Code Reader v5 - GPIO + Kernel UART + SMC UART");
    ESP_LOGI(TAG, "POST Pins: GPIO%d,%d,%d,%d,%d,%d,%d,%d",
             POST_BIT7_PIN, POST_BIT6_PIN, POST_BIT5_PIN, POST_BIT4_PIN,
             POST_BIT3_PIN, POST_BIT2_PIN, POST_BIT1_PIN, POST_BIT0_PIN);
    ESP_LOGI(TAG, "Kernel UART: GPIO%d (TX) / GPIO%d (RX) @ %d baud",
             KERNEL_UART_ESP32_TX, KERNEL_UART_ESP32_RX, KERNEL_UART_BAUD);
    ESP_LOGI(TAG, "SMC UART: GPIO%d (TX) / GPIO%d (RX) @ %d baud",
             SMC_UART_ESP32_TX, SMC_UART_ESP32_RX, SMC_UART_BAUD);
    printf("\nWaiting for POST codes and UART output...\n\n");
    
    // it worked before i added this
    uint32_t printed_idx = 0;
    int64_t base_time = 0;
    bool boot_started = false;
    uint32_t code_count = 0;
    int64_t last_code_time = 0;
    const int64_t BOOT_TIMEOUT_US = 5000000;  // 5 seconds inactivity = new boot

    while (1) {
        uint32_t count = capture_count;
        int64_t current_time = esp_timer_get_time();

        // Lazy check for new boot
        if (boot_started && count > 0 && (current_time - last_code_time > BOOT_TIMEOUT_US)) {
            if (post_codes_enabled) {
                printf("\n--- IDLE TIMEOUT/BOOT FINISHED ---\n\n");
            }
            capture_count = 0;
            printed_idx = 0;
            boot_started = false;
            code_count = 0;
            base_time = 0;
            last_code_time = 0;
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        while (printed_idx < count) {
            uint8_t code = capture_buffer[printed_idx].code;
            int64_t ts = capture_buffer[printed_idx].timestamp;
            last_code_time = ts;

            if (post_codes_enabled) {
                // Don't listen before 1BL is hit because my code introduces noise and a lot of it
                if (!boot_started) {
                    if (code == 0x10) {
                        boot_started = true;
                        base_time = ts;
                        code_count = 1;
                        printf("#%-3" PRIu32 " ", code_count);
                        print_post_code(code, 0);
                    }
                    printed_idx++;
                    continue;
                }

                code_count++;
                printf("#%-3" PRIu32 " ", code_count);
                print_post_code(code, ts - base_time);
            }
            printed_idx++;
        }

        if (count >= MAX_CAPTURED_CODES) {
            capture_count = 0;
            printed_idx = 0;
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
