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
	"github.com/cloudflare/cfssl/signer"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"

	"github.com/matryer/try"
)

func resourceCertFromKey() *schema.Resource {
	return &schema.Resource{
		Create: resourceCertFromKeyCreate,
		Read:   resourceCertFromKeyRead,
		Delete: resourceCertFromKeyDelete,

		Schema: map[string]*schema.Schema{
			"environment": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"cert_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
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
				Required: true,
				ForceNew: true,
			},
			"ca_key": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
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
				Optional: true,
				Default:  "",
				ForceNew: true,
			},
			"created_key": {
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

func resourceCertFromKeyCreate(d *schema.ResourceData, meta interface{}) error {
	csrJson := []byte(d.Get("csr_json").(string))
	req := csr.CertificateRequest{
		KeyRequest: csr.NewKeyRequest(),
	}
	err := json.Unmarshal(csrJson, &req)
	if err != nil {
		return err
	}

	tmpCAFile, err := ioutil.TempFile("", "ca")
	if err != nil {
		return err
	}
	defer os.Remove(tmpCAFile.Name())
	if _, err := tmpCAFile.Write([]byte(d.Get("ca_cert").(string))); err != nil {
		return err
	}

	ca_key_filename := d.Get("ca_key").(string)

	if _, err := os.Stat(ca_key_filename); os.IsNotExist(err) {
	  // path/to/whatever does *not* exist
		tmpCAKeyFile, err := ioutil.TempFile("", "ca-key")
		if err != nil {
			return err
		}
		defer os.Remove(tmpCAKeyFile.Name())
		if _, err := tmpCAKeyFile.Write([]byte(d.Get("ca_key").(string))); err != nil {
			return err
		}
		ca_key_filename = tmpCAKeyFile.Name()

		d.Set("ca_key", "")
	}

	csrBytes := make([]byte, 0)
	key := make([]byte, 0)

	if d.Get("key").(string) != "" {
		tmpKeyFile, err := ioutil.TempFile("", "key")
		if err != nil {
			return err
		}
		defer os.Remove(tmpKeyFile.Name())
		if _, err := tmpKeyFile.Write([]byte(d.Get("key").(string))); err != nil {
			return err
		}

		g := &csr.Generator{Validator: genkey.Validator}
		csrBytes, key, err = g.ProcessRequestFromKey(&req, tmpKeyFile.Name())
		if err != nil {
			return err
		}
		d.Set("created_key", "")
	} else {
		g := &csr.Generator{Validator: genkey.Validator}
		csrBytes, key, err = g.ProcessRequest(&req)
		if err != nil {
			return err
		}
		d.Set("key", string(key))
		d.Set("created_key", string(key))
	}

	c := cli.Config{
		CAFile:    tmpCAFile.Name(),
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

	timestamp := time.Now().UTC().String()
	d.SetId(timestamp)

	d.Set("cert", string(cert))
	d.Set("csr", string(csrBytes))

	onepass_item_title := d.Get("cert_id").(string) + " " + " certificates" + " - " + timestamp
	d.Set("onepass_item_title", onepass_item_title)

	ca_key, err := ioutil.ReadFile(ca_key_filename)
  if err != nil {
      return err
  }

	if meta != nil && d.Get("onepass_vault").(string) != ""{
		item := &Item{
			Vault:    d.Get("onepass_vault").(string),
			Template: Category2Template(SecureNoteCategory),
			Details: Details{
				Notes: "CA_cert:\n" + d.Get("ca_cert").(string) + "\n\nCA_key:\n" + string(ca_key) + "\n\ncert:\n" + string(cert) + "\n\nkey:\n" + d.Get("key").(string),
			},
			Overview: Overview{
				Title: onepass_item_title,
			},
		}
		m := meta.(*Meta)
		//err = m.onePassClient.CreateItem(item)

		err = try.Do(func(attempt int) (bool, error) {
		  var err error
		  err = m.onePassClient.CreateItem(item)
		  return attempt < 5, err // try 5 times
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func resourceCertFromKeyRead(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourceCertFromKeyDelete(d *schema.ResourceData, meta interface{}) error {
	return nil
}
