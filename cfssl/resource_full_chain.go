package cfssl

import (
	"encoding/json"
	"io/ioutil"
	//"os"
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

func resourceFullChain() *schema.Resource {
	return &schema.Resource{
		Create: resourceFullChainCreate,
		Read:   resourceFullChainRead,
		Delete: resourceFullChainDelete,

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
			"csr_json": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateFunc:     validation.ValidateJsonString,
				DiffSuppressFunc: jsonDiffSuppress,
			},
			"ca_cert": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ca_csr": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"ca_key": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cert": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"csr": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"key": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceFullChainCreate(d *schema.ResourceData, meta interface{}) error {
	caCsrJson := []byte(d.Get("ca_csr_json").(string))
	ca_req := csr.CertificateRequest{
		KeyRequest: csr.NewKeyRequest(),
	}
	ca_err := json.Unmarshal(caCsrJson, &ca_req)
	if ca_err != nil {
		return ca_err
	}

	ca_cert, ca_csrBytes, ca_key, err := initca.New(&ca_req)
	if err != nil {
		return err
	}

	d.Set("ca_cert", string(ca_cert))
	d.Set("ca_csr", string(ca_csrBytes))
	d.Set("ca_key", string(ca_key))

	csrJson := []byte(d.Get("csr_json").(string))
	req := csr.CertificateRequest{
		KeyRequest: csr.NewKeyRequest(),
	}
	csr_err := json.Unmarshal(csrJson, &req)
	if csr_err != nil {
		return csr_err
	}

	ca_cert_filename := "/tmp/" + d.Get("cert_id").(string) + "_ca.crt"
	ca_cert_w_err := ioutil.WriteFile(ca_cert_filename, []byte(d.Get("ca_cert").(string)), 0600)
	if ca_cert_w_err != nil {
		return ca_cert_w_err
	}

	ca_key_filename := "/tmp/" + d.Get("cert_id").(string) + "_ca.key"
	ca_key_w_err := ioutil.WriteFile(ca_key_filename, []byte(d.Get("ca_key").(string)), 0600)
	if ca_key_w_err != nil {
		return ca_key_w_err
	}

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

	d.SetId(d.Get("cert_id").(string) + " - " + time.Now().UTC().String())
	d.Set("cert", string(cert))
	d.Set("csr", string(csrBytes))
	d.Set("key", string(key))
	d.Set("ca_cert", "")
	d.Set("ca_key", "")
	d.Set("ca_csr", "")

	return nil
}

func resourceFullChainRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourceFullChainDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}
