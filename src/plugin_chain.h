#ifndef PLUGIN_CHAIN_H
#define PLUGIN_CHAIN_H

#include "he.h"

he_plugin_chain_t *he_plugin_chain_create(void);
void he_plugin_destroy_chain(he_plugin_chain_t *chain);
he_return_code_t he_plugin_register_plugin(he_plugin_chain_t *chain, plugin_struct_t *plugin);
he_return_code_t he_plugin_ingress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length, size_t capacity);
he_return_code_t he_plugin_egress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length, size_t capacity);

#endif // PLUGIN_CHAIN_H
