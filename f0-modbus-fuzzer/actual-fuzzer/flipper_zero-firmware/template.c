#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/elements.h>
#include <storage/storage.h>
#include <time.h>

#define MODBUS_SLAVE_ID 0x01
#define MODBUS_BAUD_RATE 9600
#define MODBUS_REG0_BASELINE 0x1000

// Bug discovery tracking
typedef struct {
    bool discovered;
    uint32_t mutation_index;
    uint16_t triggering_value;
    uint32_t discovery_time_ms;
} BugDiscovery;

typedef struct {
    FuriString* status_text;
    uint16_t register_value;
    uint8_t response_buffer[256];
    size_t response_len;
    FuriSemaphore* rx_semaphore;
    
    // Fuzzing state
    bool fuzzing_active;
    uint32_t test_cases_sent;
    uint32_t fuzz_start_time;
    uint32_t current_mutation_index;
    
    // Bug discovery tracking
    BugDiscovery bugs[3];  // Bug 1, Bug 2, Bug 3
    uint32_t bugs_found;
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

// Mutation Generation
// A Black-box mutation generates frames by systematically varying protocol fields
// Mutation index maps to:
//   0-255:     FC=0x03, start_addr (0-255)
//   256-510:   FC=0x03, quantity (0-255)
//   511-765:   FC=0x06, address (0-255)
//   766-1020:  FC=0x06, value (0-255)
//   1021-1275: FC=0x10, start_addr (0-255)
//   1276-1530: FC=0x10, quantity (0-255)
//   1531-1785: FC=0x10, byteCount (0-255)
//
// Returns the mutation parameter value and the function code being tested
static void generate_mutation(
    uint8_t* buffer,
    size_t* out_len,
    uint32_t mutation_index,
    uint8_t* out_fc,
    uint16_t* out_mutation_value) {
    
    uint32_t index_in_range = mutation_index % 1786;  // Cycle through all 1786 mutations
    uint8_t mutation_value = (uint8_t)(index_in_range % 256);
    uint8_t fc = 0x00;
    
    if (index_in_range < 256) {
        // FC=0x03, mutate start_addr
        fc = 0x03;
        buffer[0] = MODBUS_SLAVE_ID;
        buffer[1] = 0x03;
        buffer[2] = 0x00;
        buffer[3] = mutation_value;  // start_addr low
        buffer[4] = 0x00;
        buffer[5] = 0x01;            // quantity = 1
        *out_mutation_value = mutation_value;
        *out_len = 6;
        
    } else if (index_in_range < 512) {
        // FC=0x03, mutate quantity
        fc = 0x03;
        buffer[0] = MODBUS_SLAVE_ID;
        buffer[1] = 0x03;
        buffer[2] = 0x00;
        buffer[3] = 0x00;            // start_addr = 0
        buffer[4] = 0x00;
        buffer[5] = mutation_value;  // quantity
        *out_mutation_value = mutation_value;
        *out_len = 6;
        
    } else if (index_in_range < 768) {
        // FC=0x06, mutate address
        fc = 0x06;
        buffer[0] = MODBUS_SLAVE_ID;
        buffer[1] = 0x06;
        buffer[2] = 0x00;
        buffer[3] = mutation_value;  // address low
        buffer[4] = 0x11;
        buffer[5] = 0x11;            // value
        *out_mutation_value = mutation_value;
        *out_len = 6;
        
    } else if (index_in_range < 1024) {
        // FC=0x06, mutate value
        fc = 0x06;
        buffer[0] = MODBUS_SLAVE_ID;
        buffer[1] = 0x06;
        buffer[2] = 0x00;
        buffer[3] = 0x00;            // address = 0
        buffer[4] = 0x00;
        buffer[5] = mutation_value;  // value low
        *out_mutation_value = mutation_value;
        *out_len = 6;
        
    } else if (index_in_range < 1280) {
        // FC=0x10, mutate start_addr
        fc = 0x10;
        buffer[0] = MODBUS_SLAVE_ID;
        buffer[1] = 0x10;
        buffer[2] = 0x00;
        buffer[3] = mutation_value;  // start_addr low
        buffer[4] = 0x00;
        buffer[5] = 0x01;            // quantity = 1
        buffer[6] = 0x02;            // byteCount = 2
        buffer[7] = 0x11;
        buffer[8] = 0x11;
        *out_mutation_value = mutation_value;
        *out_len = 9;
        
    } else if (index_in_range < 1536) {
        // FC=0x10, mutate quantity
        fc = 0x10;
        buffer[0] = MODBUS_SLAVE_ID;
        buffer[1] = 0x10;
        buffer[2] = 0x00;
        buffer[3] = 0x00;            // start_addr = 0
        buffer[4] = 0x00;
        buffer[5] = mutation_value;  // quantity
        buffer[6] = 0x02;            // byteCount = 2
        buffer[7] = 0x11;
        buffer[8] = 0x11;
        *out_mutation_value = mutation_value;
        *out_len = 9;
        
    } else {
        // FC=0x10, mutate byteCount
        fc = 0x10;
        buffer[0] = MODBUS_SLAVE_ID;
        buffer[1] = 0x10;
        buffer[2] = 0x00;
        buffer[3] = 0x00;            // start_addr = 0
        buffer[4] = 0x00;
        buffer[5] = 0x01;            // quantity = 1
        buffer[6] = mutation_value;  // byteCount (mutation parameter)
        
        // Payload: fill with min(byteCount, 200) bytes
        uint8_t payload_bytes = (mutation_value < 200) ? mutation_value : 200;
        for (uint8_t i = 0; i < payload_bytes; i++) {
            buffer[7 + i] = 0xFF;
        }
        *out_mutation_value = mutation_value;
        *out_len = 7 + payload_bytes;
    }
    
    // Compute and append CRC
    uint16_t crc = modbus_crc16(buffer, *out_len);
    buffer[*out_len] = crc & 0xFF;
    buffer[*out_len + 1] = (crc >> 8) & 0xFF;
    *out_len += 2;
    
    *out_fc = fc;
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
    
    uint16_t received_crc = buffer[length - 2] | (buffer[length - 1] << 8);
    uint16_t calculated_crc = modbus_crc16(buffer, length - 2);
    if (received_crc != calculated_crc) return false;
    
    uint8_t byte_count = buffer[2];
    if (byte_count < 2) return false;
    
    *out_value = (buffer[3] << 8) | buffer[4];
    return true;
}

// Oracle: it returns true if an anomaly (crash or corruption) is detected, false otherwise. On detection, it stores the anomaly description
static bool execute_oracle(
    FuriHalSerialHandle* serial_handle,
    ModbusAppState* state) {
    
    // Waiting for crashes or reboot window
    furi_delay_ms(300);
    state->response_len = 0;
    
    // Drain semaphore of queued events
    while (furi_semaphore_acquire(state->rx_semaphore, 0) == FuriStatusOk) {}
    
    // The oracle sends a liveness check (FC=0x03, read register 0)
    uint8_t liveness[8];
    liveness[0] = MODBUS_SLAVE_ID;
    liveness[1] = 0x03;             // FC: Read Holding Registers
    liveness[2] = 0x00;
    liveness[3] = 0x00;
    liveness[4] = 0x00;
    liveness[5] = 0x01;             // Read 1 register
    
    uint16_t crc = modbus_crc16(liveness, 6);
    liveness[6] = crc & 0xFF;
    liveness[7] = (crc >> 8) & 0xFF;
    
    furi_hal_serial_tx(serial_handle, liveness, 8);
    furi_hal_serial_tx_wait_complete(serial_handle);
    
    // The oracle waits up to 500ms for response
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
    // The oracle evaluates the results
    if (!liveness_ok) {
        return true;
    }
    
    if (state->register_value != MODBUS_REG0_BASELINE) {
        return true;
    }
    
    return false;
}

// Bug Classification: every bug triggered is classified based on mutation index and value.
static int classify_bug(uint32_t mutation_index, uint16_t mutation_value) {
    uint32_t index_in_range = mutation_index % 1786;
    
    // Bug 1: FC=0x10, byteCount > 20 (indices 1531-1785, byteCount > 20)
    if (index_in_range >= 1531 && mutation_value > 20) {
        return 0;  // Bug 1
    }
    
    // Bug 2: FC=0x03, quantity > 125 (indices 256-511, quantity > 125)
    if (index_in_range >= 256 && index_in_range < 512 && mutation_value > 125) {
        return 1;  // Bug 2
    }
    
    // Bug 3: FC=0x06, address >= 10 (indices 511-765, address >= 10)
    if (index_in_range >= 511 && index_in_range < 768 && mutation_value >= 10) {
        return 2;  // Bug 3
    }
    
    return -1;  // No bug (false positive or unrelated anomaly)
}

// Storage and Logging
// Create the fuzz_logs directory if it doesn't exist
static bool create_fuzz_logs_directory(Storage* storage) {
    if (!storage) return false;
    
    bool success = storage_simply_mkdir(storage, "/ext/fuzz_logs");
    return success || storage_common_stat(storage, "/ext/fuzz_logs", NULL) == FSE_OK;
}

static bool write_fuzz_results_to_file(
    Storage* storage,
    ModbusAppState* state) {
    
    if (!storage) return false;
    
    char filename[128];
    static uint32_t file_counter = 0;
    snprintf(filename, sizeof(filename), "/ext/fuzz_logs/fuzz_blackbox_%08lu.txt", file_counter++);
    
    File* file = storage_file_alloc(storage);
    if (!storage_file_open(file, filename, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_free(file);
        return false;
    }
    
    // Write header
    storage_file_write(file, (const uint8_t*)"=== Modbus Black-Box Fuzzer Results ===\n\n", 42);
    
    char line[128];
    snprintf(line, sizeof(line), "Total Test Cases: %lu\n", state->test_cases_sent);
    storage_file_write(file, (const uint8_t*)line, strlen(line));
    
    snprintf(line, sizeof(line), "Total Bugs Found: %lu\n\n", state->bugs_found);
    storage_file_write(file, (const uint8_t*)line, strlen(line));
    
    // Write per-bug results
    const char* bug_names[] = {"Bug 1 (FC=0x10 byteCount overflow)", 
                               "Bug 2 (FC=0x03 quantity overflow)", 
                               "Bug 3 (FC=0x06 address off-by-one)"};
    
    for (int i = 0; i < 3; i++) {
        if (state->bugs[i].discovered) {
            snprintf(line, sizeof(line), "\n%s\n", bug_names[i]);
            storage_file_write(file, (const uint8_t*)line, strlen(line));
            
            snprintf(line, sizeof(line), "  Mutation Index: %lu\n", state->bugs[i].mutation_index);
            storage_file_write(file, (const uint8_t*)line, strlen(line));
            
            snprintf(line, sizeof(line), "  Triggering Value: %u\n", state->bugs[i].triggering_value);
            storage_file_write(file, (const uint8_t*)line, strlen(line));
            
            snprintf(line, sizeof(line), "  Discovery Time (ms): %lu\n", state->bugs[i].discovery_time_ms);
            storage_file_write(file, (const uint8_t*)line, strlen(line));
            
            uint32_t discovery_rate = (state->bugs[i].discovery_time_ms > 0) ?
                (state->bugs[i].mutation_index * 1000 / state->bugs[i].discovery_time_ms) : 0;
            snprintf(line, sizeof(line), "  Discovery Rate (mutations/sec): %lu\n", discovery_rate);
            storage_file_write(file, (const uint8_t*)line, strlen(line));
        } else {
            snprintf(line, sizeof(line), "\n%s: NOT DISCOVERED\n", bug_names[i]);
            storage_file_write(file, (const uint8_t*)line, strlen(line));
        }
    }
    
    storage_file_close(file);
    storage_file_free(file);
    
    return true;
}

// Drawing GUI
static void modbus_app_draw_callback(Canvas* canvas, void* context) {
    ModbusAppState* state = context;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 12, "Black-Box Fuzzer");
    
    canvas_set_font(canvas, FontSecondary);
    
    if (state->fuzzing_active) {
        // Display fuzzing metrics
        char metrics[64];
        uint32_t elapsed_s = (furi_get_tick() - state->fuzz_start_time) / 1000;
        
        snprintf(metrics, sizeof(metrics), "Mutations: %lu", state->test_cases_sent);
        canvas_draw_str(canvas, 2, 28, metrics);
        
        char time_str[32];
        snprintf(time_str, sizeof(time_str), "Time: %lu s", elapsed_s);
        canvas_draw_str(canvas, 2, 38, time_str);
        
        char bugs_str[32];
        snprintf(bugs_str, sizeof(bugs_str), "Bugs Found: %lu", state->bugs_found);
        canvas_draw_str(canvas, 2, 48, bugs_str);
        
        canvas_draw_str(canvas, 2, 64, "Back to stop");
        
    } else if (state->bugs_found > 0) {
        // Display results
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 28, "Complete!");
        canvas_set_font(canvas, FontSecondary);
        
        char summary[64];
        snprintf(summary, sizeof(summary), "Bugs Found: %lu", state->bugs_found);
        canvas_draw_str(canvas, 2, 44, summary);
        
        char total[64];
        snprintf(total, sizeof(total), "Mutations: %lu", state->test_cases_sent);
        canvas_draw_str(canvas, 2, 54, total);
        
        canvas_draw_str(canvas, 2, 64, "OK to exit");
        
    } else {
        canvas_draw_str(canvas, 2, 28, "Ready");
        canvas_draw_str(canvas, 2, 48, "OK: Start Fuzzing");
        canvas_draw_str(canvas, 2, 58, "Back: Exit");
    }
}

// Input Handling
static void modbus_app_input_callback(InputEvent* event, void* context) {
    furi_assert(context);
    FuriMessageQueue* queue = context;
    furi_message_queue_put(queue, event, FuriWaitForever);
}

// Main FAP body -> this signature also goes in the entry point section of the application.fam file
int32_t blackbox_input_generator_app(void* p) {
    UNUSED(p);
    
    ModbusAppState* state = malloc(sizeof(ModbusAppState));
    state->status_text = furi_string_alloc();
    state->register_value = 0;
    state->response_len = 0;
    state->rx_semaphore = furi_semaphore_alloc(1, 0);
    
    state->fuzzing_active = false;
    state->test_cases_sent = 0;
    state->fuzz_start_time = 0;
    state->current_mutation_index = 0;
    state->bugs_found = 0;
    
    for (int i = 0; i < 3; i++) {
        state->bugs[i].discovered = false;
        state->bugs[i].mutation_index = 0;
        state->bugs[i].triggering_value = 0;
        state->bugs[i].discovery_time_ms = 0;
    }
    
    furi_string_set(state->status_text, "Ready");
    
    // Open storage for logging
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if (!storage) {
        furi_string_set(state->status_text, "Storage error");
    } else {
        create_fuzz_logs_directory(storage);
    }
    
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
    uint32_t pause_until_ms = 0;
    
    while (running) {
        if (state->fuzzing_active && furi_get_tick() >= pause_until_ms) {
            // Fuzzing loop
            state->response_len = 0;
            
            uint8_t request[256];
            size_t request_len;
            uint8_t fc;
            uint16_t mutation_value;
            
            generate_mutation(request, &request_len, state->test_cases_sent, &fc, &mutation_value);
            
            furi_hal_serial_tx(serial_handle, request, request_len);
            furi_hal_serial_tx_wait_complete(serial_handle);
            
            // Execute oracle
            bool anomaly_detected = execute_oracle(serial_handle, state);
            
            if (anomaly_detected) {
                int bug_id = classify_bug(state->test_cases_sent, mutation_value);
                
                if (bug_id >= 0 && !state->bugs[bug_id].discovered) {
                    // Valid bug discovery
                    state->bugs[bug_id].discovered = true;
                    state->bugs[bug_id].mutation_index = state->test_cases_sent;
                    state->bugs[bug_id].triggering_value = mutation_value;
                    state->bugs[bug_id].discovery_time_ms = furi_get_tick() - state->fuzz_start_time;
                    state->bugs_found++;
                    
                    // Pause for 5 seconds to allow reboot -> the ESP32-C3 board automatically reboots so we tried to avoid losing some input
                    pause_until_ms = furi_get_tick() + 5000;
                    
                    // Stop fuzzing if all three bugs discovered -> this block shouldn't be here but it helps me optimizing the fuzzing runs for this thesis (:
                    // This block is reusable, just change the if condition
                    if (state->bugs_found >= 3) {
                        state->fuzzing_active = false;
                        // Automatically save results
                        if (write_fuzz_results_to_file(storage, state)) {
                            furi_string_set(state->status_text, "Results saved");
                        } else {
                            furi_string_set(state->status_text, "Save failed");
                        }
                        view_port_update(view_port);
                    }
                }
            }
            
            state->test_cases_sent++;
            
            // Update display periodically
            display_update_counter++;
            if (display_update_counter >= 10) {
                view_port_update(view_port);
                display_update_counter = 0;
            }
            
            // Check for back button
            FuriStatus msg_status = furi_message_queue_get(event_queue, &event, 50);
            if (msg_status == FuriStatusOk && event.type == InputTypePress) {
                if (event.key == InputKeyBack) {
                    state->fuzzing_active = false;
                    view_port_update(view_port);
                }
            }
            
        } else {
            // Idle loop
            if (furi_message_queue_get(event_queue, &event, 100) == FuriStatusOk) {
                if (event.type == InputTypePress) {
                    if (event.key == InputKeyBack) {
                        running = false;
                    } else if (event.key == InputKeyOk && !state->fuzzing_active) {
                        // Start fuzzing
                        state->fuzzing_active = true;
                        state->test_cases_sent = 0;
                        state->bugs_found = 0;
                        state->fuzz_start_time = furi_get_tick();
                        pause_until_ms = furi_get_tick();
                        
                        for (int i = 0; i < 3; i++) {
                            state->bugs[i].discovered = false;
                        }
                        
                        view_port_update(view_port);
                    } else if (event.key == InputKeyOk && state->bugs_found > 0 && !state->fuzzing_active) {
                        // Save results and exit
                        if (write_fuzz_results_to_file(storage, state)) {
                            furi_string_set(state->status_text, "Results saved");
                        }
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
    furi_record_close(RECORD_STORAGE);
    furi_message_queue_free(event_queue);
    furi_semaphore_free(state->rx_semaphore);
    furi_string_free(state->status_text);
    free(state);
    
    return 0;
}