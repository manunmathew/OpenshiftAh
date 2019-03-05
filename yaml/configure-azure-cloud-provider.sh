#!/bin/bash
# This script executes ansible playbooks that copies the appropriate azure.conf file to all nodes
# Then executes an ansible playbook to update the master-config.yaml on all masters
# Finally, it executes ansible playbooks to update the node-config.yaml on all nodes

echo $(date) " - Starting Script"

# Copy azure.conf to all nodes
echo $(date) " - Creating azure.conf on all nodes"

ansible-playbook create-azure-conf-infra.yaml
ansible-playbook create-azure-conf-cns.yaml
ansible-playbook create-azure-conf-tools.yaml
ansible-playbook create-azure-conf-prodtest.yaml
ansible-playbook create-azure-conf-accdev.yaml

# Update master-config.yaml file on all masters
echo $(date) " - Update master-config.yaml on all masters"

ansible-playbook setup-azure-master.yaml

# Update node-config.yaml file on all nodes
echo $(date) " - Update node-config.yaml on all nodes"

ansible-playbook setup-azure-node-master.yaml
ansible-playbook setup-azure-node.yaml

# Script complete
echo $(date) " - Script complete"