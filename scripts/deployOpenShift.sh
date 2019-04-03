#!/bin/bash

echo $(date) " - Starting OpenShift Deployment Script"

set -e

export SUDOUSER=$1
export PASSWORD="$2"
export MASTER=$3
export MASTERPUBLICIPHOSTNAME=$4
export MASTERPUBLICIPADDRESS=$5
export INFRA=$6
export TOOLS=$7
export TOOLSCOUNT=$8
export INFRACOUNT=$9
export MASTERCOUNT=${10}
export ROUTING=${11}
export REGISTRYSA=${12}
export ACCOUNTKEY="${13}"
export METRICS=${14}
export LOGGING=${15}
export TENANTID=${16}
export SUBSCRIPTIONID=${17}
export AADCLIENTID=${18}
export AADCLIENTSECRET="${19}"
export RESOURCEGROUP=${20}
export LOCATION=${21}
export AZURE=${22}
export STORAGEKIND=${23}
export ENABLECNS=${24}
export CNS=${25}
export CNSCOUNT=${26}
export VNETNAME=${27}
export NODENSG=${28}
export NODEAVAILIBILITYSET=${29}
export MASTERCLUSTERTYPE=${30}
export PRIVATEIP=${31}
export PRIVATEDNS=${32}
export PRODTEST=${33}
export ACCDEV=${34}
export CUSTOMROUTINGCERTTYPE=${35}
export CUSTOMMASTERCERTTYPE=${36}
export PRODTESTCOUNT="${37}"
export ACCDEVCOUNT="${38}"
export DOMAIN="${39}"
export HOSTSUFFIX=${40}
export CLUSTERTYPE=${41}
export MINORVERSION=${42}
export PROJREQMSG="${43}"
export WSID=${44}
export WSKEY=${45}

export BASTION=$(hostname)

# Set CNS to default storage type.  Will be overridden later if Azure is true
export CNS_DEFAULT_STORAGE=true

# Determine if Commercial Azure or Azure Government
CLOUD=$( curl -H Metadata:true "http://169.254.169.254/metadata/instance/compute/location?api-version=2017-04-02&format=text" | cut -c 1-2 )
export CLOUD=${CLOUD^^}

export MASTERLOOP=$((MASTERCOUNT - 1))
export INFRALOOP=$((INFRACOUNT - 1))
export NODELOOP=$((NODECOUNT - 1))

echo $(date) " - Configuring SSH ControlPath to use shorter path name"

sed -i -e "s/^# control_path = %(directory)s\/%%h-%%r/control_path = %(directory)s\/%%h-%%r/" /etc/ansible/ansible.cfg
sed -i -e "s/^#host_key_checking = False/host_key_checking = False/" /etc/ansible/ansible.cfg
sed -i -e "s/^#pty=False/pty=False/" /etc/ansible/ansible.cfg
sed -i -e "s/^#stdout_callback = skippy/stdout_callback = skippy/" /etc/ansible/ansible.cfg
sed -i -e "s/^#pipelining = False/pipelining = True/" /etc/ansible/ansible.cfg

# echo $(date) " - Modifying sudoers"
sed -i -e "s/Defaults    requiretty/# Defaults    requiretty/" /etc/sudoers
sed -i -e '/Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"/aDefaults    env_keep += "PATH"' /etc/sudoers

# Create docker registry config based on Commercial Azure or Azure Government
if [[ $CLOUD == "US" ]]
then
    export DOCKERREGISTRYREALM="core.usgovcloudapi.net"
elif [[ $CLOUD == "CH" ]]
then
	export DOCKERREGISTRYREALM="core.chinacloudapi.cn"
else
    export DOCKERREGISTRYREALM="core.windows.net"
fi

# Setting the default openshift_cloudprovider_kind if Azure enabled
if [[ $AZURE == "true" ]]
then
    CLOUDKIND="openshift_cloudprovider_kind=azure
openshift_cloudprovider_azure_client_id=$AADCLIENTID
openshift_cloudprovider_azure_client_secret=$AADCLIENTSECRET
openshift_cloudprovider_azure_tenant_id=$TENANTID
openshift_cloudprovider_azure_subscription_id=$SUBSCRIPTIONID
openshift_cloudprovider_azure_cloud=$CLOUDNAME
openshift_cloudprovider_azure_vnet_name=$VNETNAME
openshift_cloudprovider_azure_security_group_name=$NODENSG
openshift_cloudprovider_azure_availability_set_name=$NODEAVAILIBILITYSET
openshift_cloudprovider_azure_resource_group=$RESOURCEGROUP
openshift_cloudprovider_azure_location=$LOCATION"
	# CNS_DEFAULT_STORAGE=false
	if [[ $STORAGEKIND == "managed" ]]
	then
		SCKIND="openshift_storageclass_parameters={'kind': 'managed', 'storageaccounttype': 'Premium_LRS'}"
	else
		SCKIND="openshift_storageclass_parameters={'kind': 'shared', 'storageaccounttype': 'Premium_LRS'}"
	fi
fi

# Create custom node group definitions
if [[ $CLUSTERTYPE == "prodacc" ]]
then
	prodtestnode=production
	accdevnode=acceptance
	NODEGROUP="openshift_node_groups=[{'name': 'node-config-master', 'labels': ['node-role.kubernetes.io/master=true']}, {'name': 'node-config-infra', 'labels': ['node-role.kubernetes.io/infra=true']}, {'name': 'node-config-compute-cns', 'labels': ['nodepool=cns']}, {'name': 'node-config-compute-tools', 'labels': ['node-role.kubernetes.io/compute=true', 'nodepool=ToolsProduction']}, {'name': 'node-config-compute-acceptance', 'labels': ['node-role.kubernetes.io/compute=true', 'nodepool=Acceptance']}, {'name': 'node-config-compute-production', 'labels': ['node-role.kubernetes.io/compute=true', 'nodepool=Production']}]"
else
	prodtestnode=test
	accdevnode=development
	NODEGROUP="openshift_node_groups=[{'name': 'node-config-master', 'labels': ['node-role.kubernetes.io/master=true']}, {'name': 'node-config-infra', 'labels': ['node-role.kubernetes.io/infra=true']}, {'name': 'node-config-compute-cns', 'labels': ['nodepool=cns']}, {'name': 'node-config-compute-tools', 'labels': ['node-role.kubernetes.io/compute=true', 'nodepool=ToolsAcceptance']}, {'name': 'node-config-compute-development', 'labels': ['node-role.kubernetes.io/compute=true', 'nodepool=Development']}, {'name': 'node-config-compute-test', 'labels': ['node-role.kubernetes.io/compute=true', 'nodepool=Test']}]"
fi

# Cloning Ansible playbook repository

echo $(date) " - Cloning Ansible playbook repository"

((cd /home/$SUDOUSER && git clone https://github.com/Microsoft/openshift-container-platform-playbooks.git) || (cd /home/$SUDOUSER/openshift-container-platform-playbooks && git pull))

if [ -d /home/${SUDOUSER}/openshift-container-platform-playbooks ]
then
    echo " - Retrieved playbooks successfully"
else
    echo " - Retrieval of playbooks failed"
    exit 99
fi

# Configure custom routing certificate
echo $(date) " - Create variable for routing certificate based on certificate type"
if [[ $CUSTOMROUTINGCERTTYPE == "custom" ]]
then
	ROUTINGCERTIFICATE="openshift_hosted_router_certificate={\"cafile\": \"/tmp/routingca.pem\", \"certfile\": \"/tmp/routingcert.pem\", \"keyfile\": \"/tmp/routingkey.pem\"}"
else
	ROUTINGCERTIFICATE=""
fi

# Configure custom master API certificate
echo $(date) " - Create variable for master api certificate based on certificate type"
if [[ $CUSTOMMASTERCERTTYPE == "custom" ]]
then
	MASTERCERTIFICATE="openshift_master_overwrite_named_certificates=true
openshift_master_named_certificates=[{\"names\": [\"$MASTERPUBLICIPHOSTNAME\"], \"cafile\": \"/tmp/masterca.pem\", \"certfile\": \"/tmp/mastercert.pem\", \"keyfile\": \"/tmp/masterkey.pem\"}]"
else
	MASTERCERTIFICATE=""
fi

# Configure master cluster address information based on Cluster type (private or public)
echo $(date) " - Create variable for master cluster address based on cluster type"
if [[ $MASTERCLUSTERTYPE == "private" ]]
then
	MASTERCLUSTERADDRESS="openshift_master_cluster_hostname=${MASTER}${HOSTSUFFIX}1
openshift_master_cluster_public_hostname=$PRIVATEDNS"
else
	MASTERCLUSTERADDRESS="openshift_master_cluster_hostname=$MASTERPUBLICIPHOSTNAME
openshift_master_cluster_public_hostname=$MASTERPUBLICIPHOSTNAME
openshift_master_cluster_public_vip=$MASTERPUBLICIPADDRESS"
fi

# Create Master nodes grouping
echo $(date) " - Creating Master nodes grouping"
MASTERLIST="${HOSTSUFFIX}$MASTERCOUNT"

for (( c=1; c<=$MASTERCOUNT; c++ ))
do
	mastergroup="$mastergroup
${MASTER}${HOSTSUFFIX}$c openshift_node_group_name='node-config-master'"
done

# Create Infra nodes grouping 
echo $(date) " - Creating Infra nodes grouping"
for (( c=1; c<=$INFRACOUNT; c++ ))
do
	infragroup="$infragroup
${INFRA}${HOSTSUFFIX}$c openshift_node_group_name='node-config-infra'"
done

# Create Tools node grouping
echo $(date) " - Creating Nodes grouping"
if [ $TOOLSCOUNT -gt 9 ]
then
	# If more than 10 tools nodes need to create groups 01 - 09 separately than 10 and higher
	for (( c=1; c<=9; c++ ))
	do
		toolsnodegroup="$toolsnodegroup
${TOOLS}0$c openshift_node_group_name='node-config-compute-tools'"
	done

	for (( c=10; c<=$TOOLSCOUNT; c++ ))
	do
		toolsnodegroup="$toolsnodegroup
$TOOLS$c openshift_node_group_name='node-config-compute-tools'"
	done
else
	# If less than 10 tools nodes
	for (( c=1; c<=$TOOLSCOUNT; c++ ))
	do
		toolsnodegroup="$toolsnodegroup
${TOOLS}0$c openshift_node_group_name='node-config-compute-tools'"
	done
fi

# Create Production / Test node grouping
echo $(date) " - Creating Nodes grouping"
if [ $PRODTESTCOUNT -gt 9 ]
then
	# If more than 10 production nodes need to create groups 01 - 09 separately than 10 and higher
	for (( c=1; c<=9; c++ ))
	do
    prodtestnodegroup="$prodtestnodegroup
${PRODTEST}0$c openshift_node_group_name='node-config-compute-$prodtestnode'"
	done

	for (( c=10; c<=$PRODTESTCOUNT; c++ ))
	do
    prodtestnodegroup="$prodtestnodegroup
$PRODTEST$c openshift_node_group_name='node-config-compute-$prodtestnode'"
	done
else
	# If less than 10 tools nodes
	for (( c=1; c<=$PRODTESTCOUNT; c++ ))
	do
    prodtestnodegroup="$prodtestnodegroup
${PRODTEST}0$c openshift_node_group_name='node-config-compute-$prodtestnode'"
	done
fi

# Create Acceptance / Development node grouping
echo $(date) " - Creating Nodes grouping"
if [ $ACCDEVCOUNT -gt 9 ]
then
	# If more than 10 acceptance nodes need to create groups 01 - 09 separately than 10 and higher
	for (( c=1; c<=9; c++ ))
	do
		accdevnodegroup="$accdevnodegroup
${ACCDEV}0$c openshift_node_group_name='node-config-compute-$accdevnode'"
	done
	
	for (( c=10; c<=$ACCDEVCOUNT; c++ ))
	do
		accdevnodegroup="$accdevnodegroup
$ACCDEV$c openshift_node_group_name='node-config-compute-$accdevnode'"
	done
else
	for (( c=1; c<=$ACCDEVCOUNT; c++ ))
	do
		accdevnodegroup="$accdevnodegroup
${ACCDEV}0$c openshift_node_group_name='node-config-compute-$accdevnode'"
	done
fi

# Create CNS nodes grouping if CNS is enabled
echo $(date) " - Creating CNS nodes grouping"
for (( c=1; c<=$CNSCOUNT; c++ ))
do
	cnsgroup="$cnsgroup
${CNS}${HOSTSUFFIX}$c openshift_node_group_name='node-config-compute-cns'"
done

# Setting the HA Mode if more than one master
if [ $MASTERCOUNT != 1 ]
then
	echo $(date) " - Enabling HA mode for masters"
    export HAMODE="openshift_master_cluster_method=native"
fi

# Create Temp Ansible Hosts File
echo $(date) " - Create Ansible Hosts file"

cat > /etc/ansible/hosts <<EOF
[tempnodes]
$mastergroup
$infragroup
$nodegroup
$cnsgroup
$toolsnodegroup
$prodtestnodegroup
$accdevnodegroup
EOF

# Run a loop playbook to ensure DNS Hostname resolution is working prior to continuing with script
echo $(date) " - Running DNS Hostname resolution check"
runuser -l $SUDOUSER -c "ansible-playbook ~/openshift-container-platform-playbooks/check-dns-host-name-resolution.yaml"

# Create glusterfs configuration if CNS is enabled
if [[ $ENABLECNS == "true" ]]
then
    echo $(date) " - Creating glusterfs configuration"
	
	# Ensuring selinux is configured properly
    echo $(date) " - Setting selinux to allow gluster-fuse access"
    runuser -l $SUDOUSER -c "ansible all -o -f 30 -b -a 'sudo setsebool -P virt_sandbox_use_fusefs on'" || true
	runuser -l $SUDOUSER -c "ansible all -o -f 30 -b -a 'sudo setsebool -P virt_use_fusefs on'" || true
	
    for (( c=1; c<=$CNSCOUNT; c++ ))
    do
        runuser $SUDOUSER -c "ssh-keyscan -H ${CNS}${HOSTSUFFIX}$c >> ~/.ssh/known_hosts"
        drive=$(runuser $SUDOUSER -c "ssh ${CNS}${HOSTSUFFIX}$c 'sudo /usr/sbin/fdisk -l'" | awk '$1 == "Disk" && $2 ~ /^\// && ! /mapper/ {if (drive) print drive; drive = $2; sub(":", "", drive);} drive && /^\// {drive = ""} END {if (drive) print drive;}')
        drive1=$(echo $drive | cut -d ' ' -f 1)
        drive2=$(echo $drive | cut -d ' ' -f 2)
        drive3=$(echo $drive | cut -d ' ' -f 3)
        cnsglusterinfo="$cnsglusterinfo
${CNS}${HOSTSUFFIX}$c glusterfs_devices='[ \"${drive1}\", \"${drive2}\", \"${drive3}\" ]'"
    done
fi

# Create Ansible Hosts File
echo $(date) " - Create Ansible Hosts file"

cat > /etc/ansible/hosts <<EOF
# Create an OSEv3 group that contains the masters and nodes groups
[OSEv3:children]
masters
nodes
etcd
master0
glusterfs
new_nodes

# Set variables common for all OSEv3 hosts
[OSEv3:vars]
ansible_ssh_user=$SUDOUSER
ansible_become=yes
openshift_install_examples=true
openshift_deployment_type=openshift-enterprise
deployment_type=openshift-enterprise
openshift_release=v3.11
openshift_image_tag=v${MINORVERSION}
openshift_pkg_version=-${MINORVERSION}
docker_udev_workaround=True
openshift_use_dnsmasq=true
openshift_master_default_subdomain=$ROUTING
openshift_override_hostname_check=true
osm_use_cockpit=true
os_sdn_network_plugin_name='redhat/openshift-ovs-multitenant'
openshift_master_api_port=443
openshift_master_console_port=443
osm_default_node_selector='node-role.kubernetes.io/compute=true'
openshift_disable_check=memory_availability,docker_image_availability
openshift_master_bootstrap_auto_approve=true
openshift_storage_glusterfs_storageclass_default=true
$CLOUDKIND
$SCKIND
$CUSTOMCSS
$ROUTINGCERTIFICATE
$MASTERCERTIFICATE

# Custom node group definitions
$NODEGROUP

# Workaround for docker image failure
# https://access.redhat.com/solutions/3480921
oreg_url=registry.access.redhat.com/openshift3/ose-\${component}:\${version}
openshift_examples_modify_imagestreams=true

# default selectors for router and registry services
openshift_router_selector='node-role.kubernetes.io/infra=true'
openshift_registry_selector='node-role.kubernetes.io/infra=true'

# Configure registry to use Azure blob storage
openshift_hosted_registry_replicas=1
openshift_hosted_registry_storage_kind=object
openshift_hosted_registry_storage_provider=azure_blob
openshift_hosted_registry_storage_azure_blob_accountname=$REGISTRYSA
openshift_hosted_registry_storage_azure_blob_accountkey=$ACCOUNTKEY
openshift_hosted_registry_storage_azure_blob_container=registry
openshift_hosted_registry_storage_azure_blob_realm=$DOCKERREGISTRYREALM
#openshift_hosted_registry_routetermination=reencrypt

# Specify CNS images
openshift_storage_glusterfs_image=registry.access.redhat.com/rhgs3/rhgs-server-rhel7:v3.11
openshift_storage_glusterfs_block_image=registry.access.redhat.com/rhgs3/rhgs-gluster-block-prov-rhel7:v3.11
openshift_storage_glusterfs_s3_image=registry.access.redhat.com/rhgs3/rhgs-s3-server-rhel7:v3.11
openshift_storage_glusterfs_heketi_image=registry.access.redhat.com/rhgs3/rhgs-volmanager-rhel7:v3.11

# Deploy Service Catalog
openshift_enable_service_catalog=false

# Type of clustering being used by OCP
$HAMODE

# Addresses for connecting to the OpenShift master nodes
$MASTERCLUSTERADDRESS

# Enable HTPasswdPasswordIdentityProvider
openshift_master_identity_providers=[{'name': 'htpasswd_auth', 'login': 'true', 'challenge': 'true', 'kind': 'HTPasswdPasswordIdentityProvider'}]

# Settings for Prometheus
openshift_cluster_monitoring_operator_prometheus_storage_enabled=true
openshift_cluster_monitoring_operator_alertmanager_storage_enabled=true
openshift_cluster_monitoring_operator_node_selector={"node-role.kubernetes.io/infra":"true"}

# Setup metrics
openshift_metrics_install_metrics=false
openshift_metrics_start_cluster=true
openshift_metrics_hawkular_nodeselector={"node-role.kubernetes.io/infra":"true"}
openshift_metrics_cassandra_nodeselector={"node-role.kubernetes.io/infra":"true"}
openshift_metrics_heapster_nodeselector={"node-role.kubernetes.io/infra":"true"}

# Setup logging
openshift_logging_install_logging=false
#openshift_logging_fluentd_nodeselector={"logging":"true"}
openshift_logging_es_nodeselector={"node-role.kubernetes.io/infra":"true"}
openshift_logging_kibana_nodeselector={"node-role.kubernetes.io/infra":"true"}
openshift_logging_curator_nodeselector={"node-role.kubernetes.io/infra":"true"}
#openshift_logging_master_public_url=https://$MASTERPUBLICIPHOSTNAME

# host group for masters
[masters]
$MASTER[${HOSTSUFFIX}1:${MASTERLIST}]

# host group for etcd
[etcd]
$MASTER[${HOSTSUFFIX}1:${MASTERLIST}]

[master0]
${MASTER}${HOSTSUFFIX}1

# Only populated when CNS is enabled
[glusterfs]
$cnsglusterinfo

# host group for nodes
[nodes]
$mastergroup
$infragroup
$toolsnodegroup
$prodtestnodegroup
$accdevnodegroup
$cnsgroup

# host group for adding new nodes
[new_nodes]
EOF

# Update WALinuxAgent
echo $(date) " - Updating WALinuxAgent on all cluster nodes"
runuser $SUDOUSER -c "ansible all -f 30 -b -m yum -a 'name=WALinuxAgent state=latest'"

# Setup NetworkManager to manage eth0
echo $(date) " - Running NetworkManager playbook"
runuser -l $SUDOUSER -c "ansible-playbook -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-node/network_manager.yml"

# Configure DNS so it always has the domain name
echo $(date) " - Adding $DOMAIN to search for resolv.conf"
runuser $SUDOUSER -c "ansible all -o -f 30 -b -m lineinfile -a 'dest=/etc/sysconfig/network-scripts/ifcfg-eth0 line=\"DOMAIN=$DOMAIN\"'"

# Configure resolv.conf on all hosts through NetworkManager
echo $(date) " - Restarting NetworkManager"
runuser -l $SUDOUSER -c "ansible all -o -f 30 -b -m service -a \"name=NetworkManager state=restarted\""
echo $(date) " - NetworkManager configuration complete"

# Restarting things so everything is clean before continuing with installation
echo $(date) " - Rebooting cluster to complete installation"
runuser -l $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/reboot-master.yaml"
runuser -l $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/reboot-nodes.yaml"
sleep 20

# Run OpenShift Container Platform prerequisites playbook
echo $(date) " - Running Prerequisites via Ansible Playbook"
runuser -l $SUDOUSER -c "ansible-playbook -f 30 /usr/share/ansible/openshift-ansible/playbooks/prerequisites.yml"
echo $(date) " - Prerequisites check complete"

# Initiating installation of OpenShift Container Platform using Ansible Playbook
echo $(date) " - Installing OpenShift Container Platform via Ansible Playbook"
runuser -l $SUDOUSER -c "ansible-playbook -f 30 /usr/share/ansible/openshift-ansible/playbooks/deploy_cluster.yml"
if [ $? -eq 0 ]
then
    echo $(date) " - OpenShift Cluster installed successfully"
else
    echo $(date) " - OpenShift Cluster failed to install"
    exit 6
fi

# Install OpenShift Atomic Client
cd /root
mkdir .kube
runuser ${SUDOUSER} -c "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${SUDOUSER}@${MASTER}${HOSTSUFFIX}1:~/.kube/config /tmp/kube-config"
cp /tmp/kube-config /root/.kube/config
mkdir /home/${SUDOUSER}/.kube
cp /tmp/kube-config /home/${SUDOUSER}/.kube/config
chown --recursive ${SUDOUSER} /home/${SUDOUSER}/.kube
rm -f /tmp/kube-config
yum -y install atomic-openshift-clients

# Adding user to OpenShift authentication file
echo $(date) " - Adding OpenShift user"
runuser $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/addocpuser.yaml"

# Assigning cluster admin rights to OpenShift user
echo $(date) " - Assigning cluster admin rights to user"
runuser $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/assignclusteradminrights.yaml"

# Adding some labels back because they go missing
# echo $(date) " - Adding api and logging labels"
# runuser -l $SUDOUSER -c  "oc label --overwrite nodes ${MASTER}${HOSTSUFFIX}1 openshift-infra=apiserver"
# runuser -l $SUDOUSER -c  "oc label --overwrite nodes --all logging-infra-fluentd=true logging=true"

# Installing Service Catalog, Ansible Service Broker and Template Service Broker
if [[ $AZURE == "true" || $ENABLECNS == "true" ]]
then
	echo $(date) " - Installing Service Catalog, Ansible service broker, and template service broker."
    runuser -l $SUDOUSER -c "ansible-playbook -e openshift_enable_service_catalog=true -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-service-catalog/config.yml"
fi

# Configure Metrics
if [[ $METRICS == "true" ]]
then
    sleep 30
    echo $(date) "- Deploying Metrics"
    if [[ $AZURE == "true" || $ENABLECNS == "true" ]]
    then
        runuser -l $SUDOUSER -c "ansible-playbook -e openshift_metrics_install_metrics=True -e openshift_metrics_cassandra_storage_type=dynamic -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-metrics/config.yml"
    else
        runuser -l $SUDOUSER -c "ansible-playbook -e openshift_metrics_install_metrics=True /usr/share/ansible/openshift-ansible/playbooks/openshift-metrics/config.yml"
    fi
    if [ $? -eq 0 ]
    then
        echo $(date) " - Metrics configuration completed successfully"
    else
        echo $(date) " - Metrics configuration failed"
        exit 11
    fi
fi

# Configure Logging

if [[ $LOGGING == "true" ]]
then
    sleep 60
    echo $(date) "- Deploying Logging"
    if [[ $AZURE == "true" || $ENABLECNS == "true" ]]
    then
        runuser -l $SUDOUSER -c "ansible-playbook -e openshift_logging_install_logging=True -e openshift_logging_es_pvc_dynamic=true -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-logging/config.yml"
    else
        runuser -l $SUDOUSER -c "ansible-playbook -e openshift_logging_install_logging=True -f 30 /usr/share/ansible/openshift-ansible/playbooks/openshift-logging/config.yml"
    fi
    if [ $? -eq 0 ]
    then
        echo $(date) " - Logging configuration completed successfully"
    else
        echo $(date) " - Logging configuration failed"
        exit 12
    fi
fi

# Creating variables file for private master and Azure AD configuration playbook
echo $(date) " - Creating variables file for future playbooks"
cat > /home/$SUDOUSER/openshift-container-platform-playbooks/vars.yaml <<EOF
admin_user: $SUDOUSER
master_lb_private_dns: $PRIVATEDNS
domain: $DOMAIN
EOF

# Creating file for Azure AD configuration playbook
echo $(date) " - Creating Azure AD configuration playbook"
cat > /home/$SUDOUSER/openshift-container-platform-playbooks/aad.yaml <<EOF
  - name: AzureAD
    challenge: false
    login: true
    mappingMethod: claim
    provider:
      apiVersion: v1
      kind: OpenIDIdentityProvider
      clientID: $AADCLIENTID
      clientSecret: $AADCLIENTSECRET
      claims:
        id:
        - sub
        preferredUsername:
        - unique_name
        name:
        - name
        email:
        - email
      urls:
        authorize: https://login.microsoftonline.com/$TENANTID/oauth2/authorize
        token: https://login.microsoftonline.com/$TENANTID/oauth2/token
EOF

# Configure for Azure AD Authentication
echo $(date) " - Configure cluster for Azure AD Authentication"
runuser -l $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/add-azuread-auth.yaml -e @~/openshift-container-platform-playbooks/vars.yaml"

if [ $? -eq 0 ]
then
	echo $(date) " - Azure AD authentication configuration added to master-config.yaml"
else
	echo $(date) " - Failed to add Azure AD authentication configuration to master-config.yaml"
fi

# Configure OMS Agent Daemonset
if [[ -n "$WSID" || $WSID != "" ]]
then

sleep 15
echo $(date) " - Configuring OMS Agent Daemonset"

export WSIDBASE64=$(echo $WSID | base64 | tr -d '\n')
export WSKEYBASE64=$(echo $WSKEY | base64 | tr -d '\n')

# Create oms secret yaml
cat > /home/$SUDOUSER/openshift-container-platform-playbooks/oms-secret.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: omsagent-secret
data:
  WSID: $WSIDBASE64
  KEY: $WSKEYBASE64
EOF

# Create daemonset yaml
cat > /home/$SUDOUSER/openshift-container-platform-playbooks/oms-agent.yaml <<EOF
apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: oms
spec:
  selector:
    matchLabels:
      name: omsagent
  template:
    metadata:
      labels:
        name: omsagent
        agentVersion: 1.8.1-256
        dockerProviderVersion: 1.0.0-35
    spec:
      serviceAccount: omsagent
      containers:
      - image: "microsoft/oms"
        imagePullPolicy: Always
        name: omsagent
        securityContext:
          privileged: true
        ports:
        - containerPort: 25225
          protocol: TCP
        - containerPort: 25224
          protocol: UDP
        volumeMounts:
        - mountPath: /var/run/docker.sock
          name: docker-sock
        - mountPath: /etc/omsagent-secret
          name: omsagent-secret
          readOnly: true
        - mountPath: /var/lib/docker/containers 
          name: containerlog-path
        livenessProbe:
          exec:
            command:
              - /bin/bash
              - -c
              - ps -ef | grep omsagent | grep -v "grep"
          initialDelaySeconds: 60
          periodSeconds: 60
      volumes:
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
      - name: omsagent-secret
        secret:
          secretName: omsagent-secret
      - name: containerlog-path
        hostPath:
          path: /var/lib/docker/containers
EOF

echo $(date) " - Creating omslogging project, service account and setting proper policies.  Create secret and daemonset."
oc adm new-project omslogging --node-selector=''
oc project omslogging
oc create serviceaccount omsagent
oc adm policy add-cluster-role-to-user cluster-reader system:serviceaccount:omslogging:omsagent
oc adm policy add-scc-to-user privileged system:serviceaccount:omslogging:omsagent

oc create -f /home/$SUDOUSER/openshift-container-platform-playbooks/oms-secret.yaml
oc create -f /home/$SUDOUSER/openshift-container-platform-playbooks/oms-agent.yaml

# Finished creating OMS Agent daemonset
echo $(date) " - OMS Agent daemonset created"

fi

# Disable self-provisioning of projects
sleep 15
echo $(date) " - Disable self-provisioning of projects."
oc patch clusterrolebinding.rbac self-provisioners -p '{"subjects": null}'
oc patch clusterrolebinding.rbac self-provisioners -p '{ "metadata": { "annotations": { "rbac.authorization.kubernetes.io/autoupdate": "false" } } }'
oc  describe clusterrolebinding.rbac self-provisioners

# Create custom project request message
echo $(date) " - Create custom project request message"
cat > /home/$SUDOUSER/openshift-container-platform-playbooks/projectreqmsg.yaml <<EOF
projectRequestMessage: '${PROJREQMSG}
EOF

runuser -l $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/add-project-request-message.yaml -e @~/openshift-container-platform-playbooks/vars.yaml"
echo $(date) " - Custom project request message created"

# Configure cluster for private masters
if [[ $MASTERCLUSTERTYPE == "private" ]]
then
	echo $(date) " - Configure cluster for private masters"
	runuser -l $SUDOUSER -c "ansible-playbook -f 30 ~/openshift-container-platform-playbooks/activate-private-lb-fqdn.31x.yaml"
fi

# Delete yaml files
echo $(date) " - Deleting unecessary files"
rm -rf /home/${SUDOUSER}/openshift-container-platform-playbooks

# Delete pem files
echo $(date) " - Delete pem files"
rm -rf /tmp/*.pem

echo $(date) " - Sleep for 15 seconds"
sleep 15

echo $(date) " - Script complete"
