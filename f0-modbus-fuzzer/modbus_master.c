#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/elements.h>

#define MODBUS_SLAVE_ID 0x01
#define MODBUS_BAUD_RATE 9600

typedef struct {
    FuriString* status_text;
    uint16_t register_value;
    bool request_sent;
    uint8_t response_buffer[256];
    size_t response_len;
    FuriSemaphore* rx_semaphore;
    const char* last_request_type;
    uint32_t last_rtt_ms;
} ModbusAppState;

// CRC-16 Modbus calculation
static uint16_t modbus_crc16(const uint8_t* data, size_t length) {
    uint16_t crc = 0xFFFF;
    for(size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for(uint8_t j = 0; j < 8; j++) {
            if(crc & 0x0001) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc = crc >> 1;
            }
        }
    }
    return crc;
}

// Construct a Modbus RTU Read Holding Registers request
static size_t modbus_build_read_holding_registers(
    uint8_t* buffer,
    uint8_t slave_id,
    uint16_t start_address,
    uint16_t count) {
    
    buffer[0] = slave_id;
    buffer[1] = 0x03;
    buffer[2] = (start_address >> 8) & 0xFF;
    buffer[3] = start_address & 0xFF;
    buffer[4] = (count >> 8) & 0xFF;
    buffer[5] = count & 0xFF;
    
    uint16_t crc = modbus_crc16(buffer, 6);
    buffer[6] = crc & 0xFF;
    buffer[7] = (crc >> 8) & 0xFF;
    
    return 8;
}

// Construct an invalid Modbus request (illegal function code)
static size_t modbus_build_invalid_request(
    uint8_t* buffer,
    uint8_t slave_id) {
    
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

// Parse a Modbus RTU response
static bool modbus_parse_response(
    const uint8_t* buffer,
    size_t length,
    uint16_t* out_value) {
    
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
static void modbus_serial_rx_callback(
    FuriHalSerialHandle* handle,
    FuriHalSerialRxEvent event,
    void* context) {
    
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
    
    if(state->request_sent) {
        char value_str[64];
        snprintf(value_str, sizeof(value_str), "%s: Reg[0]=0x%04X", 
                 state->last_request_type, state->register_value);
        canvas_draw_str(canvas, 2, 44, value_str);
        
        char rtt_str[32];
        snprintf(rtt_str, sizeof(rtt_str), "RTT: %lu ms", state->last_rtt_ms);
        canvas_draw_str(canvas, 2, 54, rtt_str);
    }
    
    canvas_draw_str(canvas, 2, 64, "OK=Valid  Left=Invalid");
}

// Input callback
static void modbus_app_input_callback(InputEvent* event, void* context) {
    furi_assert(context);
    FuriMessageQueue* queue = context;
    furi_message_queue_put(queue, event, FuriWaitForever);
}

int32_t modbus_master_app(void* p) {
    UNUSED(p);
    
    ModbusAppState* state = malloc(sizeof(ModbusAppState));
    state->status_text = furi_string_alloc();
    state->register_value = 0;
    state->request_sent = false;
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
    
    while(running) {
        if(furi_message_queue_get(event_queue, &event, 100) == FuriStatusOk) {
            if(event.type == InputTypePress) {
                if(event.key == InputKeyBack) {
                    running = false;
                } else if(event.key == InputKeyOk || event.key == InputKeyLeft) {
                    state->response_len = 0;
                    
                    uint8_t request[8];
                    size_t request_len;
                    
                    if(event.key == InputKeyOk) {
                        request_len = modbus_build_read_holding_registers(
                            request, MODBUS_SLAVE_ID, 0, 1);
                        state->last_request_type = "Valid";
                    } else {
                        request_len = modbus_build_invalid_request(
                            request, MODBUS_SLAVE_ID);
                        state->last_request_type = "Invalid";
                    }
                    
                    uint32_t rtt_start = furi_get_tick();
                    furi_hal_serial_tx(serial_handle, request, request_len);
                    furi_hal_serial_tx_wait_complete(serial_handle);
                    
                    furi_string_set(state->status_text, "Request sent...");
                    view_port_update(view_port);
                    
                    uint32_t timeout_ms = 1000;
                    uint32_t start_time = furi_get_tick();
                    
                    while((furi_get_tick() - start_time) < timeout_ms) {
                        if(furi_semaphore_acquire(state->rx_semaphore, 10) == FuriStatusOk) {
                            start_time = furi_get_tick();
                            timeout_ms = 100;
                        }
                        
                        if(state->response_len >= 7) {
                            break;
                        }
                    }
                    
                    if(state->response_len > 0) {
                        uint16_t value;
                        if(modbus_parse_response(state->response_buffer, state->response_len, &value)) {
                            state->register_value = value;
                            state->request_sent = true;
                            furi_string_set(state->status_text, "Success!");
                        } else {
                            char error_str[32];
                            snprintf(error_str, sizeof(error_str), "Parse err (len=%zu)", state->response_len);
                            furi_string_set(state->status_text, error_str);
                        }
                    } else {
                        furi_string_set(state->status_text, "Timeout");
                    }
                    
                    uint32_t rtt_end = furi_get_tick();
                    state->last_rtt_ms = rtt_end - rtt_start;
                    
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
