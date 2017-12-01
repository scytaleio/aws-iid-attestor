
## Overview

This walkthrough will guide you through steps to configure SPIRE Server and SPIRE Agent for AWS IID based attestation.

## Pre-requisites
The instructions assume you have a running SPIRE Server and Agent Configured and running on AWS EC2 instances.
Follow instructions [ here ](https://github.com/spiffe/spiffe-example/blob/master/ec2/README.md) for a basic VPC and EC2 setup.
Instructions to install and configure SPIRE Server and SPIRE Agent are [ here ](https://github.com/spiffe/spire/README.md#installing-spire-server-and-agent)


## Compiling and Installing the server IID attestor plugin
Use go install to compile and install the plugin binaries.(Follow instructions [ here ](https://golang.org/doc/install) to setup go environment)
This installs the server binary in the path specified by GOBIN environment variable.

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
    `access_id` specifies the AWS access secret key id and should have permission "ec2:DescribeInstances"
     `secret` specifies the AWS access secret key corresponding to the `access_id`
     `trust_domain` should corresponds to the configured [ trust_domain ](https://github.com/spiffe/spire/blob/master/doc/spire_server.md#server-configuration-file) of the SPIRE deployment.

### Start SPIRE server

Verify `BindAddress` in <SPIRE Installation Directory>/conf/server/server.conf is set to the private IP of the ec2 instance and start the server.

     cd <SPIRE Installation Directory>
      ./spire-server run


## Compiling and Installing the agent IID attestor plugin
Use go install to compile and install the plugin binaries.(Follow instructions [ here ](https://golang.org/doc/install) to setup go environment)
This installs the server binary in the path specified by GOBIN environment variable.

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
}```

The `pluginName` should be `"aws_iid_attestor"` and matches the name used in plugin ServeConfig.
The  `pluginCmd` should specify the path to the agent IID attestor binary.
The `pluginType` should be `"NodeAttestor"` and matches the HandshakeConfig.

Configuration under `pluginData` are specific to the agent IID attestor plugin and are passed to the plugin binary
     `trust_domain` should corresponds to the configured [ trust_domain ](https://github.com/spiffe/spire/blob/master/doc/spire_agent.md#agent-configuration-file) of the SPIRE deployment.

Remove join-token attestor config, only one type of node attestation is supported on the SPIRE Agent.

rm ~/opt/spire-<version>/conf/agent/plugin/join-token.conf

### Start SPIRE agent

Verify `ServerAddress` in <SPIRE Installation Directory>/conf/agent/agent.conf is set to the SPIRE Server's private IP start the SPIRE Agent.

     cd <SPIRE Installation Directory>
      ./spire-agent run
