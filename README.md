## Overview

The AWS IID attestor is a plugin for the SPIRE Agent and SPIRE Server that allows SPIRE to automatically attest instances using the AWS Instance Metadata API and the AWS Instance Identity document. It also allows an operator to use AWS Instance IDs when defining SPIFFE ID attestation policies. This plugin is also a pre-requisite for the AWS node resolver plugin.

## Pre-requisites
The instructions assume you have a running SPIRE Server and Agent configured and running on AWS EC2 instances.
Follow instructions [ here ](https://github.com/spiffe/spiffe-example/blob/master/ec2/README.md) for a basic VPC and EC2 setup.
Instructions to install and configure SPIRE Server and SPIRE Agent are [ here ](https://github.com/spiffe/spire/README.md#installing-spire-server-and-agent)


## Compiling and Installing the server IID attestor plugin
Use go install to compile and install the plugin binaries. (Follow instructions [ here ](https://golang.org/doc/install) to install Go)
This installs the server binary in your $GOPATH/bin directory by default or in the path set by $GOBIN environment variable. 

            go install github.com/spiffe/aws-iid-attestor/server

Alternatively build the plugin outside of the SPIRE Server and copy the binary to an appropriate path on the SPIRE Server.

### Configuring the IID attestation server plugin:
Create `aws-iid-attestor.conf` - plugin configuration file in <SPIRE Installation Directory>/conf/server/plugin/.
The sever configuration template is as below:

```
pluginName = "aws_iid_attestor"
pluginCmd = "<path to plugin binary>"
pluginChecksum = ""
enabled = true
pluginType = "NodeAttestor"
pluginData {
    access_id = "<aws_access_key_id>"
    secret = "<aws_access_secret_key>"
    trust_domain = "example.org"
}
```

The `pluginName` should be `"aws_iid_attestor"` and matches the name used in plugin ServeConfig.
The  `pluginCmd` should specify the path to the server IID attestor binary.
The `pluginType` should be `"NodeAttestor"` and matches the HandshakeConfig.

Configuration under `pluginData` are specific to the server IID attestor plugin and are passed to the plugin binary:
    `access_id` specifies the AWS access secret key id of IAM user with action policy to allow "ec2:DescribeInstances", the plugin creates an ec2 client to introspect the instance being attested. 
     `secret` specifies the AWS access secret key corresponding to the `access_id`.
     `trust_domain` should corresponds to the configured [ trust_domain ](https://github.com/spiffe/spire/blob/master/doc/spire_server.md#server-configuration-file) of the SPIRE deployment.

### Start SPIRE Server

Verify `BindAddress` in <SPIRE Installation Directory>/conf/server/server.conf is set to the private IP of the ec2 instance and start the SPIRE Server.

     cd <SPIRE Installation Directory>
      ./spire-server run


## Compiling and Installing the agent IID attestor plugin
Use go install to compile and install the plugin binaries. (Follow instructions [ here ](https://golang.org/doc/install) to setup go environment)
This installs the server binary in your $GOPATH/bin directory by default or in the path set by $GOBIN environment variable.

            go install github.com/spiffe/aws-iid-attestor/agent

Alternatively build the plugin outside of the SPIRE Agent and copy the binary to an appropriate path on the SPIRE Agent.

### Configuring the IID attestation agent plugin:
Create `aws-iid-attestor.conf` - plugin configuration file in <SPIRE Installation Directory>/conf/agent/plugin/.
The agent configuration template is as below:

```
pluginName = "aws_iid_attestor"
pluginCmd = "<path to plugin binary>"
pluginChecksum = ""
enabled = true
pluginType = "NodeAttestor"
pluginData {
	trust_domain = "example.org"
}
```

The `pluginName` should be `"aws_iid_attestor"` and matches the name used in plugin ServeConfig.
The  `pluginCmd` should specify the path to the agent IID attestor binary.
The `pluginType` should be `"NodeAttestor"` and matches the HandshakeConfig.

Configuration under `pluginData` are specific to the agent IID attestor plugin and are passed to the plugin binary
     `trust_domain` should corresponds to the configured [ trust_domain ](https://github.com/spiffe/spire/blob/master/doc/spire_agent.md#agent-configuration-file) of the SPIRE deployment.

Remove join-token attestor config, only one type of node attestation is supported on the SPIRE Agent.

rm ~/opt/spire-<version>/conf/agent/plugin/join-token.conf

### Start SPIRE Agent

Verify `ServerAddress` in <SPIRE Installation Directory>/conf/agent/agent.conf is set to the SPIRE Server's private IP start the SPIRE Agent.

     cd <SPIRE Installation Directory>
      ./spire-agent run

The agent base SVID SPIFFE ID will be of the format:

     spiffe://<trust_domain>/spire/agent/aws_iid_attestor/<aws_account_number>/<instance_id> 

SVIDs registered with the above base SPIFFE ID as their `-parentID` will be managed by the SPIRE Agent and available to respective attested workloads running on the ec2 instance.

     cd <SPIRE Installation Directory>	
     ./spire-server register     -serverAddr <spire_server_address:port> \
     -parentID spiffe://<trust_domain>/spire/agent/aws_iid_attestor/<aws_account_number>/<instance_id> \
     -spiffeID <workload_spiffe_id>    -selector <workload_selector>
