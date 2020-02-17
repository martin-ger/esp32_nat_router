/* Various global declarations for the esp32_nat_router

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define PARAM_NAMESPACE "esp32_nat"

extern uint16_t connect_count;
extern bool ap_connect;

esp_err_t get_config_param_int(char* name, int* param);
esp_err_t get_config_param_str(char* name, char** param);

#ifdef __cplusplus
}
#endif
