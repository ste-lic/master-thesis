#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/elements.h>

#define MODBUS_SLAVE_ID 0x01
#define MODBUS_BAUD_RATE 9600
#define MODBUS_REG0_BASELINE 0x1000

typedef struct {
    FuriString* status_text;
    uint16_t register_value;
    uint8_t response_buffer[256];
    size_t response_len;
    FuriSemaphore* rx_semaphore;
    
    // Fuzzing state
    bool fuzzing_active;
    uint32_t test_cases_sent;
    uint32_t bugs_found;
    uint32_t fuzz_start_time;
    uint32_t discovery_time_ms;
    uint32_t triggering_mutation_value;  // The field value that caused the anomaly
    bool bug_discovered;
    char bug_description[64];  // Description of detected bug
} ModbusAppState;

// CRC-16 Modbus
static uint16_t modbus_crc16(const uint8_t* data, size_t length) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc = crc >> 1;
            }
        }
    }
    return crc;
}

// Mutation Engine
// Generic mutation generator: it currently targets Bug 1 (FC=0x10 byteCount).
// Returns the mutation parameter value (e.g., byteCount for Bug 1).
static uint16_t generate_mutation(
    uint8_t* buffer,
    size_t* out_len,
    uint32_t mutation_index) {
    
    // Bug 1: FC=0x10 (Write Multiple Registers) with varying byteCount
    // mutation_index maps directly to byteCount value (0-255)
    uint8_t byte_count = (uint8_t)(mutation_index % 256);
    
    buffer[0] = MODBUS_SLAVE_ID;
    buffer[1] = 0x10;           // FC: Write Multiple Registers
    buffer[2] = 0x00;           // start address high
    buffer[3] = 0x00;           // start address low (address 0)
    buffer[4] = 0x00;           // quantity high
    buffer[5] = 0x01;           // quantity low (1 register)
    buffer[6] = byte_count;     // byteCount field (mutation parameter)
    
    // Payload: fill with min(byteCount, 200) bytes to avoid buffer overflow on Flipper side
    uint8_t payload_bytes = (byte_count < 200) ? byte_count : 200;
    for (uint8_t i = 0; i < payload_bytes; i++) {
        buffer[7 + i] = 0xFF;
    }
    
    // CRC over the entire frame minus the CRC itself
    uint16_t crc = modbus_crc16(buffer, 7 + payload_bytes);
    buffer[7 + payload_bytes] = crc & 0xFF;
    buffer[7 + payload_bytes + 1] = (crc >> 8) & 0xFF;
    
    *out_len = 7 + payload_bytes + 2;
    
    return (uint16_t)byte_count;
}

// Serial Communication
static void modbus_serial_rx_callback(
    FuriHalSerialHandle* handle,
    FuriHalSerialRxEvent event,
    void* context) {
    
    ModbusAppState* state = context;
    
    if (event == FuriHalSerialRxEventData) {
        uint8_t data = furi_hal_serial_async_rx(handle);
        if (state->response_len < sizeof(state->response_buffer)) {
            state->response_buffer[state->response_len++] = data;
        }
        furi_semaphore_release(state->rx_semaphore);
    }
}

// Response Parsing
static bool modbus_parse_response(
    const uint8_t* buffer,
    size_t length,
    uint16_t* out_value) {
    
    if (length < 7) return false;
    
    // Verify CRC
    uint16_t received_crc = buffer[length - 2] | (buffer[length - 1] << 8);
    uint16_t calculated_crc = modbus_crc16(buffer, length - 2);
    if (received_crc != calculated_crc) return false;
    
    // Parse FC=0x03 response
    uint8_t byte_count = buffer[2];
    if (byte_count < 2) return false;
    
    *out_value = (buffer[3] << 8) | buffer[4];
    return true;
}

// Two-Step Oracle
// Returns true if a malfunctioning state (crash or corruption) is detected. On detection, stores the anomaly description.
static bool execute_oracle(
    FuriHalSerialHandle* serial_handle,
    ModbusAppState* state) {
    
    // Wait for any crash and reboot window
    furi_delay_ms(300);
    state->response_len = 0;
    
    // Drain semaphore of queued events
    while (furi_semaphore_acquire(state->rx_semaphore, 0) == FuriStatusOk) {}
    
    // Send liveness check (FC=0x03, read register 0)
    uint8_t liveness[8];
    liveness[0] = MODBUS_SLAVE_ID;
    liveness[1] = 0x03;           // FC: Read Holding Registers
    liveness[2] = 0x00;
    liveness[3] = 0x00;
    liveness[4] = 0x00;
    liveness[5] = 0x01;           // Read 1 register
    
    uint16_t crc = modbus_crc16(liveness, 6);
    liveness[6] = crc & 0xFF;
    liveness[7] = (crc >> 8) & 0xFF;
    
    furi_hal_serial_tx(serial_handle, liveness, 8);
    furi_hal_serial_tx_wait_complete(serial_handle);
    
    // Wait up to 500ms for response
    uint32_t lv_start = furi_get_tick();
    bool liveness_ok = false;
    
    while ((furi_get_tick() - lv_start) < 500) {
        if (furi_semaphore_acquire(state->rx_semaphore, 10) == FuriStatusOk) {
            lv_start = furi_get_tick();
        }
        if (state->response_len >= 7) {
            uint16_t val;
            if (modbus_parse_response(state->response_buffer, state->response_len, &val)) {
                liveness_ok = true;
                state->register_value = val;
            }
            break;
        }
    }
    
    // Evaluate results
    if (!liveness_ok) {
        furi_string_set(state->status_text, "CRASH DETECTED");
        snprintf(state->bug_description, sizeof(state->bug_description), "Liveness timeout");
        return true;
    }
    
    if (state->register_value != MODBUS_REG0_BASELINE) {
        furi_string_set(state->status_text, "CORRUPTION DETECTED");
        snprintf(state->bug_description, sizeof(state->bug_description), 
                 "Reg[0]=0x%04X (expected 0x%04X)", state->register_value, MODBUS_REG0_BASELINE);
        return true;
    }
    
    return false;
}

// Drawing
static void modbus_app_draw_callback(Canvas* canvas, void* context) {
    ModbusAppState* state = context;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 12, "Modbus Fuzzer");
    
    canvas_set_font(canvas, FontSecondary);
    
    if (state->fuzzing_active) {
        // Display active fuzzing metrics
        char metrics[64];
        uint32_t elapsed_ms = furi_get_tick() - state->fuzz_start_time;
        uint32_t elapsed_s = elapsed_ms / 1000;
        
        snprintf(metrics, sizeof(metrics), "Tests: %lu", state->test_cases_sent);
        canvas_draw_str(canvas, 2, 28, metrics);
        
        char time_str[32];
        snprintf(time_str, sizeof(time_str), "Time: %lu s", elapsed_s);
        canvas_draw_str(canvas, 2, 38, time_str);
        
        char rate_str[32];
        uint32_t rate = (elapsed_s > 0) ? (state->test_cases_sent / elapsed_s) : 0;
        snprintf(rate_str, sizeof(rate_str), "Rate: %lu tc/s", rate);
        canvas_draw_str(canvas, 2, 48, rate_str);
        
        canvas_draw_str(canvas, 2, 64, "Back to stop");
        
    } else if (state->bug_discovered) {
        // Display bug discovery results
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 28, "BUG FOUND!");
        canvas_set_font(canvas, FontSecondary);
        
        char discovery[64];
        snprintf(discovery, sizeof(discovery), "Value: %u", state->triggering_mutation_value);
        canvas_draw_str(canvas, 2, 38, discovery);
        
        char metrics[64];
        snprintf(metrics, sizeof(metrics), "Tests: %lu | Time: %lu ms",
                 state->test_cases_sent, state->discovery_time_ms);
        canvas_draw_str(canvas, 2, 48, metrics);
        
        canvas_draw_str(canvas, 2, 64, "OK to exit");
        
    } else {
        // Idle state
        canvas_draw_str(canvas, 2, 28, furi_string_get_cstr(state->status_text));
        canvas_draw_str(canvas, 2, 48, "Center: Start Fuzzing");
        canvas_draw_str(canvas, 2, 58, "Back: Exit");
    }
}

// Input Handling
static void modbus_app_input_callback(InputEvent* event, void* context) {
    furi_assert(context);
    FuriMessageQueue* queue = context;
    furi_message_queue_put(queue, event, FuriWaitForever);
}

// MAIN FLIPPER ZERO APP -> put this as the entry point of the .fam file generated by $ ufbt create appid=APP_NAME
int32_t mutation_engine_app(void* p) {
    UNUSED(p);
    
    ModbusAppState* state = malloc(sizeof(ModbusAppState));
    state->status_text = furi_string_alloc();
    state->register_value = 0;
    state->response_len = 0;
    state->rx_semaphore = furi_semaphore_alloc(1, 0);
    
    state->fuzzing_active = false;
    state->test_cases_sent = 0;
    state->bugs_found = 0;
    state->fuzz_start_time = 0;
    state->discovery_time_ms = 0;
    state->triggering_mutation_value = 0;
    state->bug_discovered = false;
    
    furi_string_set(state->status_text, "Ready");
    
    FuriMessageQueue* event_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    
    ViewPort* view_port = view_port_alloc();
    view_port_draw_callback_set(view_port, modbus_app_draw_callback, state);
    view_port_input_callback_set(view_port, modbus_app_input_callback, event_queue);
    
    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, view_port, GuiLayerFullscreen);
    
    // Initialize UART
    FuriHalSerialHandle* serial_handle = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if (!serial_handle) {
        furi_string_set(state->status_text, "UART init failed");
        view_port_update(view_port);
        furi_delay_ms(3000);
        goto cleanup;
    }
    
    furi_hal_serial_init(serial_handle, MODBUS_BAUD_RATE);
    furi_hal_serial_async_rx_start(serial_handle, modbus_serial_rx_callback, state, false);
    
    view_port_update(view_port);
    
    // Main event loop
    bool running = true;
    InputEvent event;
    uint32_t display_update_counter = 0;
    
    while (running) {
        if (state->fuzzing_active) {
            // Fuzzing loop: generate and send mutations
            state->response_len = 0;
            
            uint8_t request[256];
            size_t request_len;
            
            // Generate mutation and get the mutation parameter value
            uint16_t mutation_value = generate_mutation(request, &request_len, state->test_cases_sent);
            
            uint32_t test_start = furi_get_tick();
            furi_hal_serial_tx(serial_handle, request, request_len);
            furi_hal_serial_tx_wait_complete(serial_handle);
            
            // Execute oracle
            bool anomaly_detected = execute_oracle(serial_handle, state);
            
            if (anomaly_detected) {
                // Verify anomaly is in expected range for Bug 1 (byteCount > 20)
                if (mutation_value > 20) {
                    // Valid Bug 1 detection
                    state->bugs_found++;
                    state->bug_discovered = true;
                    state->triggering_mutation_value = mutation_value;
                    state->discovery_time_ms = furi_get_tick() - state->fuzz_start_time;
                    state->fuzzing_active = false;
                } else {
                    // Anomaly detected but not in expected Bug 1 range
                    // Continue fuzzing (this is a false positive or different bug)
                    furi_string_set(state->status_text, "Anomaly @ invalid value, continuing...");
                }
            }
            
            state->test_cases_sent++;
            
            // Update display periodically (every 10 test cases)
            display_update_counter++;
            if (display_update_counter >= 10) {
                view_port_update(view_port);
                display_update_counter = 0;
            }
            
            // Check for back button to stop early
            FuriStatus msg_status = furi_message_queue_get(event_queue, &event, 50);
            if (msg_status == FuriStatusOk && event.type == InputTypePress) {
                if (event.key == InputKeyBack) {
                    state->fuzzing_active = false;
                    furi_string_set(state->status_text, "Fuzzing stopped");
                    view_port_update(view_port);
                }
            }
            
        } else {
            // Idle loop: wait for user input
            if (furi_message_queue_get(event_queue, &event, 100) == FuriStatusOk) {
                if (event.type == InputTypePress) {
                    if (event.key == InputKeyBack) {
                        running = false;
                    } else if (event.key == InputKeyCenter) {
                        // Start fuzzing
                        state->fuzzing_active = true;
                        state->test_cases_sent = 0;
                        state->bugs_found = 0;
                        state->bug_discovered = false;
                        state->fuzz_start_time = furi_get_tick();
                        furi_string_set(state->status_text, "Fuzzing...");
                        view_port_update(view_port);
                    } else if (event.key == InputKeyOk && state->bug_discovered) {
                        // Exit after bug discovery
                        running = false;
                    }
                }
            }
        }
    }
    
    // Cleanup
    furi_hal_serial_async_rx_stop(serial_handle);
    furi_hal_serial_deinit(serial_handle);
    furi_hal_serial_control_release(serial_handle);
    
cleanup:
    gui_remove_view_port(gui, view_port);
    view_port_free(view_port);
    furi_record_close(RECORD_GUI);
    furi_message_queue_free(event_queue);
    furi_semaphore_free(state->rx_semaphore);
    furi_string_free(state->status_text);
    free(state);
    
    return 0;
}
