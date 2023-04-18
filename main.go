package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/keys-pub/go-libfido2"
)

var (
	debug *log.Logger

	domain          = flag.String("vpn-endpoint", "", "The VPN to connect to.")
	username        = flag.String("username", "", "The username to authenticate against.")
	passwordCmd     = flag.String("password-command", "", "The command to fetch the password to authenticate with.")
	devicePin       = flag.String("device-pin", "", "The PIN to your device (optional).")
	verbose         = flag.Bool("verbose", false, "Print verbose log messages.")
	openConnectArgs = flag.String("openconnect-args", "", "A list of arguments to pass the openconnect command, separated by spaces. They will be passed in verbatim.")
)

func init() {
	flag.Parse()

	debugSink := io.Discard
	if *verbose {
		debugSink = os.Stderr
	}
	debug = log.New(debugSink, "[DEBUG]", log.Ltime|log.Lshortfile|log.Lmsgprefix)
}

func main() {
	if *domain == "" {
		fmt.Println("Please provide a domain.")
		os.Exit(1)
	}
	if *username == "" {
		fmt.Println("Please provide a username.")
		os.Exit(1)
	}
	if *passwordCmd == "" {
		fmt.Println("Please provide a command to fetch your password.")
		os.Exit(1)
	}

	device, info, err := getFirstDevice()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Using %#v for 2FA.", info)

	password := must(runGetOneLine(*passwordCmd))

	var client http.Client
	client.Jar = must(cookiejar.New(nil))

	samlURL := must(preLogin(&client, *domain))
	samlDomain := samlURL.Hostname()
	debug.Printf("samlURL: %v", samlURL)

	debug.Printf("GET %s: fetching cookie(s)", samlURL)
	must(client.Get(samlURL.String()))

	serverAuthReq := must(oktaAuth(
		&client,
		samlDomain,
		*username,
		password,
		*devicePin,
	))

	serverVeriResp := must(oktaVerify(
		device,
		&client,
		samlDomain,
		*username,
		*devicePin,
		serverAuthReq,
	))

	fmt.Fprintln(os.Stderr, "Please touch your device to continue.")
	assertionBag := must(makeDeviceAssertion(
		samlDomain,
		device,
		serverVeriResp,
		serverAuthReq.Embedded.Factors,
		*devicePin,
	))

	sessionTok := must(func() (string, error) {
		var sessionTokContainer struct{ SessionToken string }
		err := postJSON(
			&client,
			serverVeriResp.Links.Next.Href,
			assertionBag,
			&sessionTokContainer,
		)
		if err != nil {
			return "", err
		}
		return sessionTokContainer.SessionToken, nil
	}())
	debug.Printf("obtained session token %q", sessionTok)

	loginHTML := must(fetchOktaLoginPage(&client, samlURL, sessionTok))
	loginForm := must(parseLoginForm(loginHTML))
	samlUsername, cookie, err := submitLoginForm(&client, loginForm)
	if err != nil {
		log.Fatal(err)
	}

	openConnectArgs := strings.Split(*openConnectArgs, " ")
	if len(openConnectArgs) == 1 && openConnectArgs[0] == "" {
		openConnectArgs = nil
	}
	cmd := append(
		[]string{
			"sudo", "-E",
			"openconnect",
			*domain,
			"--protocol=gp",
			"--user=" + samlUsername,
			"--usergroup=gateway:prelogin-cookie",
			"--passwd-on-stdin",
		},
		openConnectArgs...,
	)

	// Write the cookie to the buffer in anticipation of the process reading
	// it.
	var stdin bytes.Buffer
	fmt.Fprintf(&stdin, cookie)

	process := exec.Command(cmd[0], cmd[1:]...)
	process.Stderr = os.Stderr
	process.Stdout = os.Stdout
	process.Stdin = &stdin

	debug.Println("Starting openconnect...")
	fmt.Fprintf(os.Stderr, "%s %s\n", cmd[0], cmd[1:])
	err = process.Run()
	if err != nil {
		log.Fatal(err)
	}
}

func preLogin(client *http.Client, domain string) (*url.URL, error) {
	url := fmt.Sprintf("https://%s/ssl-vpn/prelogin.esp", domain)
	debug.Printf("POST %s", url)
	httpResp, err := client.Post(url, "", nil)
	if err != nil {
		return nil, err
	}
	respRaw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}
	debug.Printf("POST %s: %.100s", url, respRaw)

	var resp struct {
		SAMLRequest []byte `xml:"saml-request"`
	}
	err = xml.Unmarshal(respRaw, &resp)
	if err != nil {
		return nil, err
	}
	debug.Printf("POST %s: %#.20v", url, resp)

	dst := make([]byte, base64.StdEncoding.DecodedLen(len(resp.SAMLRequest)))
	_, err = base64.StdEncoding.Decode(dst, resp.SAMLRequest)
	if err != nil {
		return nil, err
	}
	debug.Printf("POST %s: form: %s", url, dst)

	loginForm, err := parseLoginForm(dst)
	if err != nil {
		return nil, err
	}

	return loginForm.newRequest()
}

func fetchOktaLoginPage(
	client *http.Client,
	samlURL *url.URL,
	sessionToken string,
) ([]byte, error) {
	url := must(url.Parse(fmt.Sprintf(
		"https://%s/login/sessionCookieRedirect",
		samlURL.Hostname(),
	)))
	q := url.Query()
	q.Add("token", sessionToken)
	q.Add("redirectUrl", samlURL.String())
	url.RawQuery = q.Encode()

	debug.Printf("GET %s", url)
	httpResp, err := client.Get(url.String())
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(httpResp.Body)
}

func parseLoginForm(htmlRaw []byte) (*loginForm, error) {
	findForm := func(html string) (string, error) {
		start := strings.Index(html, "<form")
		if start == -1 {
			return "", fmt.Errorf("cannot find form in HTML")
		}
		const endTag = "</form>"
		end := start + strings.Index(html[start:], endTag)
		return html[start : end+len(endTag)], nil
	}
	formHTML, err := findForm(string(htmlRaw))
	if err != nil {
		return nil, err
	}

	var html loginForm
	err = xml.Unmarshal([]byte(formHTML), &html)
	if err != nil {
		return nil, err
	}
	return &html, nil
}

type loginForm struct {
	XMLName xml.Name `xml:"form"`
	Action  string   `xml:"action,attr"`
	Inputs  []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:"value,attr"`
	} `xml:"input"`
}

func (l *loginForm) newRequest() (*url.URL, error) {
	url, err := url.Parse(l.Action)
	if err != nil {
		return nil, err
	}

	q := url.Query()
	for _, input := range l.Inputs {
		q.Add(input.Name, input.Value)
	}
	url.RawQuery = q.Encode()

	return url, nil
}

func (l *loginForm) submit(c *http.Client) (*http.Response, error) {
	url, err := l.newRequest()
	if err != nil {
		return nil, err
	}
	formVals := url.Query()

	url.RawQuery = ""
	debug.Printf("POST %s form with values: %#.100v", url, formVals)
	return c.PostForm(url.String(), formVals)
}

func getFirstDevice() (*libfido2.Device, *libfido2.DeviceLocation, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, nil, err
	}
	if len(locs) == 0 {
		return nil, nil, fmt.Errorf("cannot find device")
	}
	deviceLoc := locs[0]

	dev, err := libfido2.NewDevice(deviceLoc.Path)
	if err != nil {
		return nil, deviceLoc, err
	}
	return dev, deviceLoc, nil
}

func oktaVerify(
	device *libfido2.Device,
	client *http.Client,
	domain string,
	username string,
	pin string,
	oktaAuthResp *oktaAuthResp,
) (*oktaVerifResp, error) {
	url, err := url.Parse("https://" + domain + "/api/v1/authn/factors/webauthn/verify")
	if err != nil {
		return nil, err
	}

	var resp oktaVerifResp
	err = postJSON(
		client,
		url.String(),
		map[string]string{"stateToken": oktaAuthResp.StateToken},
		&resp,
	)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

type oktaVerifResp struct {
	Links struct {
		Next struct{ Href string } `json:"next"`
	} `json:"_links"`
	StateToken string
	Embedded   struct {
		Challenge struct{ Challenge string }
		User      struct{ Id string }
	} `json:"_embedded"`
}

func makeDeviceAssertion(
	samlDomain string,
	device *libfido2.Device,
	resp *oktaVerifResp,
	factors []webauthnFactor,
	devicePin string,
) (map[string]any, error) {
	challenge := []byte(resp.Embedded.Challenge.Challenge)
	credentialIDs := make([][]byte, 0, len(factors))
	for _, f := range factors {
		if f.Type != "webauthn" {
			continue
		}
		credID, err := websafeDecode(f.Profile.CredentialID)
		if err != nil {
			return nil, err
		}
		credentialIDs = append(credentialIDs, credID)
	}

	clientDataHashJSON, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   string(challenge),
		"origin":      fmt.Sprintf("https://%s", samlDomain),
		"crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}
	cdhSum := sha256.Sum256(clientDataHashJSON)

	debug.Printf("making device assertion for %q", samlDomain)
	// The user needs to touch their device for this call to continue.
	assertion, err := device.Assertion(
		samlDomain,
		cdhSum[:],
		credentialIDs,
		devicePin,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var authData []byte
	err = cbor.Unmarshal(assertion.AuthDataCBOR, &authData)
	if err != nil {
		return nil, err
	}

	b64 := func(b []byte) string {
		return base64.StdEncoding.EncodeToString(must(websafeDecode(websafeEncode(b))))
	}
	return map[string]any{
		"authenticatorData": b64(authData),
		"clientData":        b64(clientDataHashJSON),
		"signatureData":     b64(assertion.Sig),
		"stateToken":        resp.StateToken,
	}, nil
}

type webauthnFactor struct {
	Type    string `json:"factorType"`
	Profile struct {
		CredentialID string
	}
}

type oktaAuthResp struct {
	Status     string
	StateToken string
	Embedded   struct {
		Factors []webauthnFactor
	} `json:"_embedded"`
}

func oktaAuth(
	client *http.Client,
	domain, username, password, pin string,
) (*oktaAuthResp, error) {
	url := must(url.Parse(fmt.Sprintf("https://%s/api/v1/authn", domain)))

	var resp oktaAuthResp
	err := postJSON(
		client,
		url.String(),
		map[string]string{
			"username": username,
			"password": password,
		},
		&resp,
	)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func submitLoginForm(
	client *http.Client,
	loginForm *loginForm,
) (username, cookie string, _ error) {
	httpResp, err := loginForm.submit(client)
	if err != nil {
		return "", "", err
	}

	return httpResp.Header.Get("saml-username"),
		httpResp.Header.Get("prelogin-cookie"),
		nil
}

/// Utility functions

func must[T any](val T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return val
}

func runGetOneLine(cmd string) (string, error) {
	cmdParts := strings.Split(cmd, " ")
	proc := exec.CommandContext(context.Background(), cmdParts[0], cmdParts[1:]...)
	out, err := proc.Output()
	if err != nil {
		return "", err
	}
	maybeLine, _, err := bufio.NewReader(bytes.NewReader(out)).ReadLine()
	if err != nil {
		return "", err
	}
	return string(maybeLine), nil
}

func websafeDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.Trim(strconv.QuoteToASCII(s), `"`))
}

func websafeEncode(b []byte) string {
	return strings.Trim(strconv.QuoteToASCII(base64.RawURLEncoding.EncodeToString(b)), `"`)
}

// postJSON marshals body of type T to JSON, posts it to endpoint using c, and
// then unmarshals the response from JSON into type S.
func postJSON[T, S any](
	c *http.Client,
	endpoint string,
	body T,
	resp *S,
) error {
	jsonBody, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}

	debug.Printf("POST %s: body: %s", endpoint, jsonBody)
	jsonBuff := bytes.NewBuffer(jsonBody)
	httpResp, err := c.Post(endpoint, "application/json", jsonBuff)
	if err != nil {
		return err
	}
	respBody, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return err
	}

	jsonBuff.Reset()
	err = json.Indent(jsonBuff, respBody, "", "  ")
	if err != nil {
		return err
	}
	debug.Printf("POST %s: %s", endpoint, jsonBuff.String())

	if httpResp.StatusCode != 200 {
		return fmt.Errorf("%s", respBody)
	}

	err = json.Unmarshal(respBody, resp)
	debug.Printf("POST %s: response: %#v", endpoint, resp)
	return err
}
