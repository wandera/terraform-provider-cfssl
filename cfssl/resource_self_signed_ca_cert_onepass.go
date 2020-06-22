package cfssl

import (
	"encoding/json"
	"time"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

func resourceSelfSignedCACertOnePass() *schema.Resource {
	return &schema.Resource{
		Create: resourceSelfSignedCACertOnePassCreate,
		Read:   resourceSelfSignedCACertOnePassRead,
		Delete: resourceSelfSignedCACertOnePassDelete,

		Schema: map[string]*schema.Schema{
			"environment": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "",
			},
			"cert_id": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "",
			},
			"csr_json": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateFunc:     validation.ValidateJsonString,
				DiffSuppressFunc: jsonDiffSuppress,
			},
			"cert": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"onepass_vault": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "",
			},
			"onepass_item_title": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceSelfSignedCACertOnePassCreate(d *schema.ResourceData, meta interface{}) error {
	csrJson := []byte(d.Get("csr_json").(string))
	req := csr.CertificateRequest{
		KeyRequest: csr.NewKeyRequest(),
	}
	err := json.Unmarshal(csrJson, &req)
	if err != nil {
		return err
	}

	cert, _, key, err := initca.New(&req)
	if err != nil {
		return err
	}

	timestamp := time.Now().UTC().String()
	onepass_item_title := d.Get("environment").(string) + " " + d.Get("cert_id").(string) + " " + " CA" + " - " + timestamp

	if meta != nil && d.Get("onepass_vault").(string) != ""{
		item := &Item{
			Vault:    d.Get("onepass_vault").(string),
			Template: Category2Template(SecureNoteCategory),
			Details: Details{
				Notes: "CA_cert:\n" + string(cert) + "\n\nCA_key:\n" + string(key),
			},
			Overview: Overview{
				Title: onepass_item_title,
			},
		}
		m := meta.(*Meta)
		err = m.onePassClient.CreateItem(item)
		if err != nil {
			return err
		}
	}

	d.SetId(timestamp)
	d.Set("cert", string(cert))
	d.Set("onepass_item_title", onepass_item_title)

	return nil
}

func resourceSelfSignedCACertOnePassRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourceSelfSignedCACertOnePassDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}
