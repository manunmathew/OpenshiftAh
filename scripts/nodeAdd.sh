#!/bin/bash
# Script to scale the cluster by one compute node

echo $(date) " - Starting Script"

set -e

export SUDOUSER=$1
export NODE=$2
export NODEGROUP=$3

# Create playbook to update hosts file
# Filename: addnode-to-hosts.yaml
cat /home/$SUDOUSER/addnode-to-hosts.yaml << EOF
---
- hosts: localhost
  gather_facts: no
  tasks:
  - name: Add new node to inventory file
    lineinfile:
      dest: /etc/ansible/hosts
      insertafter: '[new_nodes]'
      line: "$NODE openshift_node_group_name='node-config-compute-$NODEGROUP"
      regexp: '^$NODE '
      state: present
EOF

# Filename: update-hosts.yaml
cat /home/$SUDOUSER/update-hosts.yaml << EOF
---
- hosts: localhost
  gather_facts: no
  tasks:
  - name: Remove new node from new_nodes section
    lineinfile:
      dest: /etc/ansible/hosts
      insertafter: '[new_nodes]'
      line: "$NODE openshift_node_group_name='node-config-compute-$NODEGROUP"
      regexp: '^$NODE '
      state: absent

  - name: Add new node to nodes section
    lineinfile:
      dest: /etc/ansible/hosts
      insertbefore: '# host group for adding new nodes'
      line: "$NODE openshift_node_group_name='node-config-compute-$NODEGROUP"
      regexp: '^$NODE '
      state: present
EOF

# Run Ansible Playbook to add new node to hosts file
echo $(date) " - Adding new node name to hosts file"

ansible-playbook /home/$SUDOUSER/addnode-to-hosts.yaml

# Run Ansible Playbook to add new Node to OpenShift Cluster
echo $(date) " - Adding new Node to OpenShift Cluster via Ansible Playbook"

runuser -l $SUDOUSER -c "ansible-playbook /usr/share/ansible/openshift-ansible/playbooks/openshift-node/scaleup.yml"

echo $(date) " - New Node added to OpenShift Cluster"

# Run Ansible Playbook to update hosts file
echo $(date) " - Moving new comput node from new_nodes section to nodes section in hosts file"

ansible-playbook /home/$SUDOUSER/update-hosts.yaml

# Remove unecessary playbook files
rm /home/$SUDOUSER/addnode-to-hosts.yaml
rm /home/$SUDOUSER/update-hosts.yaml

echo $(date) " - Script complete"
