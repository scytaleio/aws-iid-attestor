package common

// 
type InstanceIdentityDocument struct {
	InstanceId string `json:"instanceId" `
	AccountId  string `json:"accountId"`
}


type IidAttestedData struct {
	Document  string `json:"document"`
	Signature string `json:"signature"`
}
