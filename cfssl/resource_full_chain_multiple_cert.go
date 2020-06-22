package cfssl

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"time"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

func resourceFullChainMultipleCert() *schema.Resource {
	return &schema.Resource{
		Create: resourceFullChainMultipleCertCreate,
		Read:   resourceFullChainMultipleCertRead,
		Delete: resourceFullChainMultipleCertDelete,

		Schema: map[string]*schema.Schema{
			"cert_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"ca_csr_json": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateFunc:     validation.ValidateJsonString,
				DiffSuppressFunc: jsonDiffSuppress,
			},
			"csr_list": {
				Type:             schema.TypeList,
				Required:         true,
				ForceNew:         true,
				DiffSuppressFunc: jsonDiffSuppress,
				Elem:             &schema.Schema{
			    Type:         schema.TypeString,
					ValidateFunc: validation.ValidateJsonString,
			  },
			},
			"ca_cert": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"certs_details": {
				Type:     schema.TypeList,
				Computed: true,
				Elem:     &schema.Schema{
					Type: schema.TypeMap,
					Elem: &schema.Schema{
						Type: schema.TypeString,
						ValidateFunc: validation.ValidateJsonString,
					},
				},
			},
		},
	}
}

func resourceFullChainMultipleCertCreate(d *schema.ResourceData, meta interface{}) error {
	caCsrJson := []byte(d.Get("ca_csr_json").(string))
	ca_req := csr.CertificateRequest{
		KeyRequest: csr.NewKeyRequest(),
	}
	ca_err := json.Unmarshal(caCsrJson, &ca_req)
	if ca_err != nil {
		return ca_err
	}

	ca_cert, _, ca_key, err := initca.New(&ca_req)
	if err != nil {
		return err
	}

	d.Set("ca_cert", string(ca_cert))

	ca_cert_filename := "/tmp/" + d.Get("cert_id").(string) + "_ca.crt"
	ca_cert_w_err := ioutil.WriteFile(ca_cert_filename, []byte(d.Get("ca_cert").(string)), 0600)
	if ca_cert_w_err != nil {
		return ca_cert_w_err
	}
	defer os.Remove(ca_cert_filename)

	ca_key_filename := "/tmp/" + d.Get("cert_id").(string) + "_ca.key"
	ca_key_w_err := ioutil.WriteFile(ca_key_filename, ca_key, 0600)
	if ca_key_w_err != nil {
		return ca_key_w_err
	}

	certs_details := make([]interface{}, 0)

	for _, csr_json := range d.Get("csr_list").([]interface{}) {
		csrJson := []byte(csr_json.(string))
		req := csr.CertificateRequest{
			KeyRequest: csr.NewKeyRequest(),
		}
		csr_err := json.Unmarshal(csrJson, &req)
		if csr_err != nil {
			return csr_err
		}

		csr_endpoint := req.CN

		g := &csr.Generator{Validator: genkey.Validator}
		csrBytes, key, err := g.ProcessRequest(&req)
		if err != nil {
			return err
		}

		c := cli.Config{
			CAFile:    ca_cert_filename,
			CAKeyFile: ca_key_filename,
		}
		s, err := sign.SignerFromConfig(c)
		if err != nil {
			return err
		}
		signReq := signer.SignRequest{
			Request: string(csrBytes),
		}
		cert, err := s.Sign(signReq)
		if err != nil {
			return err
		}

		cert_info_map := map[string]string{
																"endpoint": csr_endpoint,
																"cert": string(cert),
																"key": string(key),
															}

		certs_details = append(certs_details, cert_info_map)
	}

	d.SetId(d.Get("cert_id").(string) + " - " + time.Now().UTC().String())

	d.Set("certs_details", certs_details)

	return nil
}

func resourceFullChainMultipleCertRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourceFullChainMultipleCertDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}
