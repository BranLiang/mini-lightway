#ifdef TEST

#include "unity.h"

#include "plugin_chain.h"

uint8_t *packet = NULL;
size_t packet_max_length = 1500;
size_t test_packet_size = 1100;

int ingress_count = 0;
int egress_count = 0;

he_plugin_return_code_t call_counting_plugin_ingress(uint8_t *packet, size_t *length, size_t capacity, void *data)
{
    ingress_count++;
    return HE_PLUGIN_SUCCESS;
}

he_plugin_return_code_t call_counting_plugin_egress(uint8_t *packet, size_t *length, size_t capacity, void *data)
{
    egress_count++;
    return HE_PLUGIN_SUCCESS;
}

plugin_struct_t call_counting_plugin = {
    .do_ingress = call_counting_plugin_ingress,
    .do_egress = call_counting_plugin_egress,
    .data = NULL,
};

he_plugin_return_code_t drop_if_zero(uint8_t *packet, size_t *length, size_t capacity, void *data)
{
    for (int i = 0; i < *length; i++)
    {
        if (packet[i] != 0)
        {
            return HE_PLUGIN_SUCCESS;
        }
    }

    return HE_PLUGIN_DROP;
}

plugin_struct_t zero_dropping_plugin = {
    .do_ingress = drop_if_zero,
    .do_egress = drop_if_zero,
    .data = NULL,
};

he_plugin_return_code_t always_fail(uint8_t *packet, size_t *length, size_t capacity, void *data)
{
    return HE_PLUGIN_FAIL;
}

plugin_struct_t failing_plugin = {
    .do_ingress = always_fail,
    .do_egress = always_fail,
    .data = NULL,
};

he_plugin_return_code_t zero_packet(uint8_t *packet, size_t *length, size_t capacity, void *data)
{
    for (int i = 0; i < *length; i++)
    {
        packet[i] = 0;
    }

    return HE_PLUGIN_SUCCESS;
}

plugin_struct_t wipeout_plugin = {
    .do_ingress = zero_packet,
    .do_egress = zero_packet,
    .data = NULL,
};

plugin_struct_t only_ingress_plugin = {
    .do_ingress = call_counting_plugin_ingress,
    .do_egress = NULL,
    .data = NULL,
};

plugin_struct_t only_egress_plugin = {
    .do_ingress = NULL,
    .do_egress = call_counting_plugin_egress,
    .data = NULL,
};

void setUp(void)
{
    packet = calloc(1, packet_max_length);
    test_packet_size = 1100;

    // Generate a random blob to represent the packet
    for (int i = 0; i < packet_max_length; i++)
    {
        packet[i] = rand() % 256;
    }

    ingress_count = 0;
    egress_count = 0;
}

void tearDown(void)
{
    free(packet);
}

void test_plugin_chain_register_fails_on_null(void)
{
    he_plugin_chain_t *chain = he_plugin_chain_create();
    he_return_code_t rc = he_plugin_register_plugin(NULL, &call_counting_plugin);
    TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, rc);

    rc = he_plugin_register_plugin(NULL, NULL);
    TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, rc);

    rc = he_plugin_register_plugin(chain, NULL);
    TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER, rc);
}

void test_ingress_egress_do_nothing_if_nothing_registered(void)
{
    he_return_code_t res = HE_ERR_FAILED;
    he_plugin_chain_t *chain = he_plugin_chain_create();

    res = he_plugin_ingress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_egress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
}

void test_ingress_egress_call_counts(void)
{
    he_return_code_t res = HE_ERR_FAILED;
    he_plugin_chain_t *chain = he_plugin_chain_create();

    res = he_plugin_register_plugin(chain, &call_counting_plugin);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_ingress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
    TEST_ASSERT_EQUAL(1, ingress_count);
    TEST_ASSERT_EQUAL(0, egress_count);

    res = he_plugin_egress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
    TEST_ASSERT_EQUAL(1, egress_count);
    TEST_ASSERT_EQUAL(1, ingress_count);
}

void test_multiple_plugins(void)
{
    he_return_code_t res = HE_ERR_FAILED;
    he_plugin_chain_t *chain = he_plugin_chain_create();

    res = he_plugin_register_plugin(chain, &call_counting_plugin);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_register_plugin(chain, &call_counting_plugin);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_register_plugin(chain, &call_counting_plugin);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_ingress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
    TEST_ASSERT_EQUAL(3, ingress_count);
    TEST_ASSERT_EQUAL(0, egress_count);

    res = he_plugin_egress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
    TEST_ASSERT_EQUAL(3, egress_count);
    TEST_ASSERT_EQUAL(3, ingress_count);
}

void test_ingress_egress_opposite_order(void)
{
    he_return_code_t res = HE_ERR_FAILED;
    he_plugin_chain_t *chain = he_plugin_chain_create();
    res = he_plugin_register_plugin(chain, &zero_dropping_plugin);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
    res = he_plugin_register_plugin(chain, &wipeout_plugin);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_ingress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_egress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_ERR_PLUGIN_DROP, res);
}

void test_plugin_failure(void)
{
    he_return_code_t res = HE_ERR_FAILED;
    he_plugin_chain_t *chain = he_plugin_chain_create();
    res = he_plugin_register_plugin(chain, &failing_plugin);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_ingress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_ERR_FAILED, res);

    res = he_plugin_egress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_ERR_FAILED, res);
}

void test_ingress_only_plugin(void)
{
    he_return_code_t res = HE_ERR_FAILED;
    he_plugin_chain_t *chain = he_plugin_chain_create();
    res = he_plugin_register_plugin(chain, &only_ingress_plugin);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_ingress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
    TEST_ASSERT_EQUAL(1, ingress_count);

    res = he_plugin_egress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
    TEST_ASSERT_EQUAL(0, egress_count);
}

void test_egress_only_plugin(void)
{
    he_return_code_t res = HE_ERR_FAILED;
    he_plugin_chain_t *chain = he_plugin_chain_create();
    res = he_plugin_register_plugin(chain, &only_egress_plugin);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);

    res = he_plugin_ingress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
    TEST_ASSERT_EQUAL(0, ingress_count);

    res = he_plugin_egress(chain, packet, &test_packet_size, packet_max_length);
    TEST_ASSERT_EQUAL(HE_PLUGIN_SUCCESS, res);
    TEST_ASSERT_EQUAL(1, egress_count);
}

void test_plugin_chain_destroy_fails_on_null(void)
{
    he_plugin_destroy_chain(NULL);
}

void test_plugin_chain_destroy_frees_single(void)
{
    he_plugin_chain_t *chain = he_plugin_chain_create();
    he_plugin_destroy_chain(chain);
}

void test_plugin_chain_destroy_frees_multiple(void)
{
    he_plugin_chain_t *chain = he_plugin_chain_create();
    he_plugin_register_plugin(chain, &call_counting_plugin);
    he_plugin_register_plugin(chain, &call_counting_plugin);
    he_plugin_register_plugin(chain, &call_counting_plugin);
    he_plugin_destroy_chain(chain);
}

#endif // TEST
