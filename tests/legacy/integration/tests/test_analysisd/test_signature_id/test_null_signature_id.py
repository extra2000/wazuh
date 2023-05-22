# # ----------------------------------------TEST_NULL_SIGNATURE_ID------------------------------------------
# # Configuration and cases data
# t3_configurations_path = os.path.join(CONFIGS_PATH, 'configuration_signature_id_values.yaml')
# t3_cases_path = os.path.join(TEST_CASES_PATH, 'cases_null_signature_id.yaml')

# # test_null_signature_id configurations
# t3_configuration_parameters, t3_configuration_metadata, t3_case_ids = get_test_cases_data(t3_cases_path)
# t3_configurations = load_configuration_template(t3_configurations_path, t3_configuration_parameters,
#                                                 t3_configuration_metadata)


# # Tests
# @pytest.mark.tier(level=1)
# @pytest.mark.parametrize('configuration, metadata', zip(t3_configurations, t3_configuration_metadata), ids=t3_case_ids)
# def test_null_signature_id(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
#                            prepare_custom_rules_file, restart_wazuh_function):
#     '''
#     description: Check that when a rule has an invalid signature ID value, that references a nonexisten rule,
#                  assigned to the if_sid option, the rule is ignored.

#     test_phases:
#         - setup:
#             - Set wazuh configuration.
#             - Copy custom rules file into manager
#             - Clean logs files and restart wazuh to apply the configuration.
#         - test:
#             - Check "if_sid not found" log is detected
#             - Check "empty if_sid" log is detected
#         - teardown:
#             - Delete custom rule file
#             - Restore configuration
#             - Stop wazuh

#     wazuh_min_version: 4.4.0

#     tier: 1

#     parameters:
#         - configuration:
#             type: dict
#             brief: Configuration loaded from `configuration_template`.
#         - metadata:
#             type: dict
#             brief: Test case metadata.
#         - set_wazuh_configuration:
#             type: fixture
#             brief: Set wazuh configuration.
#         - truncate_monitored_files:
#             type: fixture
#             brief: Truncate all the log files and json alerts files before and after the test execution.
#         - prepare_custom_rules_file:
#             type: fixture
#             brief: Copies custom rules_file before test, deletes after test.
#         - restart_wazuh_function:
#             type: fixture
#             brief: Restart wazuh at the start of the module to apply configuration.

#     assertions:
#         - Check that wazuh starts
#         - Check ".*Signature ID '(\\d*)' was not found and will be ignored in the 'if_sid'.* of rule '(\\d*)'" event
#         - Check ".*wazuh-testrule.*Empty 'if_sid' value. Rule '(\\d*)' will be ignored.*"

#     input_description:
#         - The `configuration_signature_id_values.yaml` file provides the module configuration for
#           this test.
#         - The `cases_signature_id_values.yaml` file provides the test cases.
#     '''

#     wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

#     # Check that expected log appears for rules if_sid field pointing to a non existent SID
#     ev.check_if_sid_not_found(wazuh_log_monitor)
#     # Check that expected log appears for rules if_sid field being empty (empty since non-existent SID is ignored)
#     ev.check_empty_if_sid(wazuh_log_monitor)