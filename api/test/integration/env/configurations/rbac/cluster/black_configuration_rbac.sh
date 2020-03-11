#!/usr/bin/env bash

sed -i 's,"mode": \("white"\|"black"\),"mode": "black",g' /var/ossec/framework/python/lib/python3.7/site-packages/api-4.0.0-py3.7.egg/api/configuration.py
sed -i "s:    # policies = RBAChecker.run_testing():    policies = RBAChecker.run_testing():g" /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.12.0-py3.7.egg/wazuh/rbac/preprocessor.py
permissions='[{"actions":["cluster:read_config"],"resources":["node:id:master-node","node:id:worker2"],"effect":"deny"},{"actions":["cluster:restart"],"resources":["node:id:worker1"],"effect":"deny"},{"actions":["cluster:status"],"resources":["*"],"effect":"deny"},{"actions":["cluster:read_file"],"resources":["node:id:master-node\\&file:path:etc/ossec.conf","node:id:worker2\\&file:path:etc/ossec.conf","node:id:master-node\\&file:path:etc/rules/local_rules.xml","node:id:worker2\\&file:path:etc/rules/local_rules.xml","node:id:master-node\\&file:path:ruleset/rules/0350-amazon_rules.xml","node:id:worker2\\&file:path:ruleset/rules/0350-amazon_rules.xml"],"effect":"deny"},{"actions":["cluster:upload_file"],"resources":["node:id:master-node","node:id:worker2"],"effect":"deny"},{"actions":["cluster:delete_file"],"resources":["node:id:master-node\&file:path:ruleset/decoders/0005-wazuh_decoders.xml","node:id:worker2\&file:path:etc/ossec.conf"],"effect":"deny"}]'
awk -v var="${permissions}" '{sub(/testing_policies = \[\]/, "testing_policies = " var)}1' /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.12.0-py3.7.egg/wazuh/rbac/auth_context.py >> /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.12.0-py3.7.egg/wazuh/rbac/auth_context1.py
cat /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.12.0-py3.7.egg/wazuh/rbac/auth_context1.py > /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.12.0-py3.7.egg/wazuh/rbac/auth_context.py
