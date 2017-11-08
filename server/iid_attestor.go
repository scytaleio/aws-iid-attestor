package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/hcl"

	spi "github.com/spiffe/spire/proto/common/plugin"
	"github.com/spiffe/spire/proto/server/nodeattestor"

	aia "github.com/spiffe/aws-iid-attestor/common"
)

const awsCaCertPEM = `-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----
`

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
	spiffePath := path.Join("spiffe", "node-id", awsAccountId, awsInstanceId)
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

	err = rsa.VerifyPKCS1v15(p.awsCaCertPublicKey, crypto.SHA256, docHash[:], []byte(attestedData.Signature))
	if err != nil {
		err = fmt.Errorf("IID attestation attempted but an error occured hashing the IID: %v", err)
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
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}
	err = hcl.DecodeObject(&config, hclTree)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	// Set local vars from config struct
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.trustDomain = config.TrustDomain

	block, _ := pem.Decode([]byte(awsCaCertPEM))

	awsCaCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

	var ok bool
	p.awsCaCertPublicKey, ok = awsCaCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		resp.ErrorList = []string{err.Error()}
		return resp, err
	}

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
