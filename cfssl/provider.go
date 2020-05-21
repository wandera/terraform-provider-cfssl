package cfssl

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/Masterminds/semver"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

var version string = "0.7.1"

// Provider returns a terraform.ResourceProvider.
func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"onepassword_email": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OP_EMAIL", nil),
				Description: "Set account email address",
			},
			"onepassword_password": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OP_PASSWORD", nil),
				Description: "Set account password",
			},
			"onepassword_secret_key": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("OP_SECRET_KEY", nil),
				Description: "Set account secret key",
			},
			"onepassword_subdomain": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "my",
				DefaultFunc: schema.EnvDefaultFunc("OP_SUBDOMAIN", nil),
				Description: "Set alternative subdomain for 1password. From [subdomain].1password.com",
			},
		},

		ResourcesMap: map[string]*schema.Resource{
			"cfssl_cert":                             resourceCert(),
			"cfssl_self_signed_ca_cert":              resourceSelfSignedCACert(),
			"cfssl_full_chain_cert":                  resourceFullChain(),
			"cfssl_full_chain_multiple_cert":         resourceFullChainMultipleCert(),
			"cfssl_full_chain_multiple_cert_onepass": resourceFullChainMultipleCertOnePassCaKey(),
		},

		DataSourcesMap: map[string]*schema.Resource{},

		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	return NewMeta(d)
}

const opPasswordCreate = "create"
const opPasswordDelete = "delete"
const opPasswordGet = "get"

type OnePassClient struct {
	Password  string
	Email     string
	SecretKey string
	Subdomain string
	PathToOp  string
	Session   string
	mutex     *sync.Mutex
}

type Meta struct {
	data          *schema.ResourceData
	onePassClient *OnePassClient
}

func NewMeta(d *schema.ResourceData) (*Meta, error) {
	m := &Meta{data: d}
	client, err := m.NewOnePassClient()
	m.onePassClient = client
	return m, err
}

func unzip(src string, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		traversableCheck := strings.Split(f.Name, "..")
		fpath := filepath.Join(dest, traversableCheck[len(traversableCheck)-1])
		if err != nil {
			return err
		}
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", fpath)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

func findExistingOPClient() (string, error) {
	o, err := exec.Command("op", "--version", "--raw").Output()

	if err != nil {
		return "", fmt.Errorf("Trouble calling: op\nOutput: %s", o)
	}

	c, err := semver.NewConstraint(">= " + version)
	if err != nil {
		return "", err
	}

	v, err := semver.NewVersion(strings.TrimSuffix(string(o), "\n"))
	if err != nil {
		return "", fmt.Errorf("[%s]", string(o))
	}

	if c.Check(v) {
		return "op", nil
	}

	return "", fmt.Errorf("op version needs to be equal or greater than: %s", version)
}

func installOPClient() (string, error) {
	if os.Getenv("OP_VERSION") != "" {
		semVer, err := semver.NewVersion(os.Getenv("OP_VERSION"))
		if err != nil {
			return "", err
		}
		version = semVer.String()
	}
	binZip := fmt.Sprintf("/tmp/op_%s.zip", version)
	if _, err := os.Stat(binZip); os.IsNotExist(err) {
		resp, err := http.Get(fmt.Sprintf(
			"https://cache.agilebits.com/dist/1P/op/pkg/v%s/op_%s_%s_v%s.zip",
			version,
			runtime.GOOS,
			runtime.GOARCH,
			version,
		))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		out, err := os.Create(binZip)
		if err != nil {
			return "", err
		}
		defer out.Close()
		if _, err = io.Copy(out, resp.Body); err != nil {
			return "", err
		}
		if err := unzip(binZip, "/tmp/terraform-provider-onepassword/"+version); err != nil {
			return "", err
		}
	}
	return "/tmp/terraform-provider-onepassword/" + version + "/op", nil
}

func (m *Meta) NewOnePassClient() (*OnePassClient, error) {
	bin, err := findExistingOPClient()
	if err != nil {
		bin, err = installOPClient()
		if err != nil {
			return nil, err
		}
	}

	subdomain := m.data.Get("onepassword_subdomain").(string)
	email := m.data.Get("onepassword_email").(string)
	password := m.data.Get("onepassword_password").(string)
	secretKey := m.data.Get("onepassword_secret_key").(string)
	session := ""

	if email == "" || password == "" || secretKey == "" {
		email = ""
		password = ""
		secretKey = ""

		var sessionKeyName string
		if strings.Contains(subdomain, "-") {
			sessionKeyName = "OP_SESSION_" + strings.ReplaceAll(subdomain, "-", "_")
		} else {
			sessionKeyName = "OP_SESSION_" + subdomain
		}
		session = os.Getenv(sessionKeyName)

		if session == "" {
			return nil, fmt.Errorf("email, password or secret_key is empty and environment variable %s is not set",
				sessionKeyName)
		}
	}

	op := &OnePassClient{
		Email:     email,
		Password:  password,
		SecretKey: secretKey,
		Subdomain: subdomain,
		PathToOp:  bin,
		Session:   session,
		mutex:     &sync.Mutex{},
	}

	if session != "" {
		return op, nil
	}
	if err := op.SignIn(); err != nil {
		return nil, err
	}
	return op, nil
}

func (o *OnePassClient) SignIn() error {
	cmd := exec.Command(o.PathToOp, "signin", o.Subdomain, o.Email, o.SecretKey, "--output=raw")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		defer stdin.Close()
		if _, err := io.WriteString(stdin, fmt.Sprintf("%s\n", o.Password)); err != nil {
			log.Println("[ERROR] ", err)
		}
	}()

	session, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(fmt.Sprintf("Cannot signin: %s\nExit code: %s", string(session), err))
	}

	o.Session = string(session)
	return nil
}

func (o *OnePassClient) runCmd(args ...string) ([]byte, error) {
	args = append(args, fmt.Sprintf("--session=%s", strings.Trim(o.Session, "\n")))
	o.mutex.Lock()
	cmd := exec.Command(o.PathToOp, args...)
	defer o.mutex.Unlock()
	res, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("some error in command %v\nError: %s\nOutput: %s", args[:len(args)-1], err, res)
	}
	return res, err
}

func getResultID(r []byte) (string, error) {
	result := &Resource{}
	if err := json.Unmarshal(r, result); err != nil {
		return "", err
	}
	return result.UUID, nil
}

type Resource struct {
	UUID string `json:"uuid"`
}

func getID(d *schema.ResourceData) string {
	if d.Id() != "" {
		return d.Id()
	}
	return d.Get("name").(string)
}

func (o *OnePassClient) Delete(resource string, id string) error {
	_, err := o.runCmd(opPasswordDelete, resource, id)
	return err
}
