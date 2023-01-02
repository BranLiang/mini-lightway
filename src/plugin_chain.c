#include "plugin_chain.h"

he_plugin_chain_t *he_plugin_chain_create(void)
{
    return calloc(1, sizeof(he_plugin_chain_t));
}

void he_plugin_destroy_chain(he_plugin_chain_t *chain)
{
    if (chain)
    {
        he_plugin_destroy_chain(chain->next);
        free(chain);
    }
}

he_return_code_t he_plugin_register_plugin(he_plugin_chain_t *chain, plugin_struct_t *plugin)
{
    if (chain == NULL || plugin == NULL)
    {
        return HE_ERR_NULL_POINTER;
    }

    if (chain->plugin == NULL)
    {
        chain->plugin = plugin;
        return HE_SUCCESS;
    }

    if (chain->next == NULL)
    {
        chain->next = he_plugin_chain_create();
        if (chain->next == NULL)
        {
            return HE_ERR_INIT_FAILED;
        }
    }

    return he_plugin_register_plugin(chain->next, plugin);
}

he_return_code_t he_plugin_ingress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length, size_t capacity)
{
    if (chain == NULL)
    {
        return HE_SUCCESS;
    }

    plugin_struct_t *plugin = chain->plugin;
    if (plugin && plugin->do_ingress)
    {
        he_plugin_return_code_t rc = plugin->do_ingress(packet, length, capacity, plugin->data);
        if (rc == HE_PLUGIN_FAIL)
        {
            return HE_ERR_FAILED;
        }

        if (rc == HE_PLUGIN_DROP)
        {
            return HE_ERR_PLUGIN_DROP;
        }
    }

    return he_plugin_ingress(chain->next, packet, length, capacity);
}

he_return_code_t he_plugin_egress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length, size_t capacity)
{
    if (chain == NULL)
    {
        return HE_SUCCESS;
    }

    he_return_code_t res = he_plugin_egress(chain->next, packet, length, capacity);
    if (res != HE_SUCCESS)
    {
        return res;
    }

    plugin_struct_t *plugin = chain->plugin;
    if (plugin && plugin->do_egress)
    {
        he_plugin_return_code_t rc = plugin->do_egress(packet, length, capacity, plugin->data);
        if (rc == HE_PLUGIN_FAIL)
        {
            return HE_ERR_FAILED;
        }

        if (rc == HE_PLUGIN_DROP)
        {
            return HE_ERR_PLUGIN_DROP;
        }
    }

    return HE_SUCCESS;
}

