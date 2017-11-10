package main

import (
	"crypto"
	"math"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"sync"
	"time"

	ec2 "github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"

	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"
	aia "github.com/spiffe/aws-iid-attestor/common"

)



const (
	pluginName = "iid_attestor"

	maxSecondsBetweenDeviceAttachments = 60
)

const awsCaCertPEM = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----`

type IIDAttestorConfig struct {
	TrustDomain string `hcl:"trust_domain"`
}

type IIDAttestorPlugin struct {
	ConfigTime time.Time

	trustDomain string

	awsCaCertPublicKey *rsa.PublicKey

	mtx *sync.Mutex
}

func (p *IIDAttestorPlugin) spiffeID(awsAccountId, awsInstanceId string) *url.URL {
	spiffePath := path.Join("spire", "agent", pluginName, awsAccountId, awsInstanceId)	
	id := &url.URL{
		Scheme: "spiffe",
		Host:   p.trustDomain,
		Path:   spiffePath,
	}
	return id
}

func (p *IIDAttestorPlugin) Attest(req *nodeattestor.AttestRequest) (*nodeattestor.AttestResponse, error) {

	var attestedData aia.IidAttestedData
	err := json.Unmarshal(req.AttestedData.Data, &attestedData)
	if err != nil {
		err = fmt.Errorf("IID attestation attempted but an error occured while unmarshaling the attestation data: %v", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	var doc aia.InstanceIdentityDocument
	err = json.Unmarshal([]byte(attestedData.Document), &doc)
	if err != nil {
		err = fmt.Errorf("IID attestation attempted but an error occured while unmarshaling the IID: %v", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	// Is it alright to dump the IID here?
	if req.AttestedBefore {
		err := fmt.Errorf("IID attestation attempted but the IID has been used and is no longer valid: %s", attestedData.Document)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	docHash := sha256.Sum256([]byte(attestedData.Document))
	if err != nil {
		err = fmt.Errorf("IID attestation attempted but an error occured hashing the IID: %v", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	sigBytes, err := base64.StdEncoding.DecodeString(attestedData.Signature)
	if err != nil {
		err = fmt.Errorf("IID attestation attempted but an error occured while base64 decoding the IID signature, %s: %v", attestedData.Signature, err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	err = rsa.VerifyPKCS1v15(p.awsCaCertPublicKey, crypto.SHA256, docHash[:], sigBytes)
	if err != nil {
		err = fmt.Errorf("IID attestation attempted but an error occurred while verifying the cryptographic signature: %v", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	// Perform validations with the AWS EC2 API

	sess := session.Must(session.NewSession())

	ec2Client := ec2.New(sess, &aws.Config {
		Region: &doc.Region,
	})

	query := &ec2.DescribeInstancesInput {
		InstanceIds: []*string{&doc.InstanceId},
	}

	result, err := ec2Client.DescribeInstances(query)
	if err != nil {	
		err = fmt.Errorf("IID attestation attempted but an error occurred while performing validations via describe-instance: %s", err)
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	instance := result.Reservations[0].Instances[0]

	if *instance.NetworkInterfaces[0].Attachment.DeviceIndex != 0 {
		err = fmt.Errorf("IID attestation attempted but a validation step failed: instance.NetworkInterfaces[0].Attachment.DeviceIndex != 0")
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	netIfaceAttachTime := instance.NetworkInterfaces[0].Attachment.AttachTime

	rootDeviceName := instance.RootDeviceName

	rootDeviceIndex := -1
	for i, bdm := range instance.BlockDeviceMappings {
		if *bdm.DeviceName == *rootDeviceName {
			rootDeviceIndex = i
			break
		}
	}

	if rootDeviceIndex == -1 {
		err = fmt.Errorf("IID attestation attempted but a validation step failed: unable to locate the root device block mapping")
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	rootDeviceAttachTime := instance.BlockDeviceMappings[rootDeviceIndex].Ebs.AttachTime

	if int(math.Abs(float64(netIfaceAttachTime.Unix() - rootDeviceAttachTime.Unix()))) > maxSecondsBetweenDeviceAttachments {
		err = fmt.Errorf("IID attestation attempted but a validation step failed: disparity between device attachments exceeds threshold")
		return &nodeattestor.AttestResponse{Valid: false}, err
	}

	resp := &nodeattestor.AttestResponse{
		Valid:        true,
		BaseSPIFFEID: p.spiffeID(doc.AccountId, doc.InstanceId).String(),
	}

	return resp, nil
}

func (p *IIDAttestorPlugin) Configure(req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	resp := &spi.ConfigureResponse{}

	// Parse HCL config payload into config struct
	config := &IIDAttestorConfig{}
	hclTree, err := hcl.Parse(req.Configuration)
	if err != nil {
		err := fmt.Errorf("Error parsing AWS IID Attestor configuration: %s", err)
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		err := fmt.Errorf("Error decoding AWS IID Attestor configuration: %v", err)
		return resp, err
	}

	block, _ := pem.Decode([]byte(awsCaCertPEM))

	awsCaCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err := fmt.Errorf("Error reading the AWS CA Certificate in the AWS IID Attestor: %v", err)
		return resp, err
	}

	awsCaCertPublicKey, ok := awsCaCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err := fmt.Errorf("Error extracting the AWS CA Certificate's public key in the AWS IID Attestor: %v", err)
		return resp, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.trustDomain = config.TrustDomain
	p.awsCaCertPublicKey = awsCaCertPublicKey

	return &spi.ConfigureResponse{}, nil
}

func (*IIDAttestorPlugin) GetPluginInfo(*spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func New() nodeattestor.NodeAttestor {
	return &IIDAttestorPlugin{
		mtx: &sync.Mutex{},
	}
}

func main() {
	p := &IIDAttestorPlugin{
		mtx: &sync.Mutex{},
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: nodeattestor.Handshake,
		Plugins: map[string]plugin.Plugin{
			"join_token": nodeattestor.NodeAttestorPlugin{NodeAttestorImpl: p},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
