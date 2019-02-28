package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-ini/ini"
	"github.com/pkg/errors"
)

type configEntry struct {
	Name            string
	Region          string
	MFASerial       string
	RoleARN         string
	AccessKeyID     string
	SecretAccessKey string
	SourceProfile   string
}

// merge  c1 into empty c values.
func (c configEntry) merge(c1 configEntry) configEntry {
	if c.Name == "" {
		c.Name = c1.Name
	}
	if c.Region == "" {
		c.Region = c1.Region
	}
	if c.MFASerial == "" {
		c.MFASerial = c1.MFASerial
	}
	if c.RoleARN == "" {
		c.RoleARN = c1.RoleARN
	}
	if c.AccessKeyID == "" {
		c.AccessKeyID = c1.AccessKeyID
	}
	if c.SecretAccessKey == "" {
		c.SecretAccessKey = c1.SecretAccessKey
	}
	if c.SourceProfile == "" {
		c.SourceProfile = c1.SourceProfile
	}
	return c
}

func loadAWSConfigFile(configPath, credentialsPath string) (config, credentials *ini.File, err error) {
	// If path is empty, use the default ~/.aws/config and ~/.aws/credentials.
	var homeDir string
	if configPath == "" || credentialsPath == "" {
		u, err := user.Current() // Lookup current user to get HomeDir.
		if err != nil {
			return nil, nil, errors.Wrap(err, "user.Current")
		}
		homeDir = u.HomeDir
	}
	if configPath == "" {
		configPath = homeDir + "/.aws/config"
	}
	if credentialsPath == "" {
		credentialsPath = homeDir + "/.aws/credentials"
	}
	// Load the ini files.
	config, err = ini.Load(configPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "ini.Load config")
	}
	credentials, err = ini.Load(credentialsPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "ini.Load credentials")
	}

	return config, credentials, nil
}

func newIniConfigEntry(section *ini.Section) configEntry {
	return configEntry{
		Name:            section.Name(),
		Region:          section.Key("region").String(),
		MFASerial:       section.Key("mfa_serial").String(),
		RoleARN:         section.Key("role_arn").String(),
		AccessKeyID:     section.Key("aws_access_key_id").String(),
		SecretAccessKey: section.Key("aws_secret_access_key").String(),
		SourceProfile:   section.Key("source_profile").String(),
	}
}

type configRegistry map[string]configEntry

func processAWSConfig(configFile, credentialsFile *ini.File) configRegistry {
	reg := configRegistry{}

	// Load the default config section.
	defaultEntry := newIniConfigEntry(configFile.Section("default"))

	// Load all the other entries.
	for _, secName := range configFile.SectionStrings() {
		// Skip default.
		if secName == "DEFAULT" || secName == "default" {
			continue
		}
		// Create a config entry from the section.
		entry := newIniConfigEntry(configFile.Section(secName))

		// If we have a "source profile", look it up.
		if entry.SourceProfile != "" {
			// First check the credentials file.
			sourceSection := credentialsFile.Section(entry.SourceProfile)
			if len(sourceSection.Keys()) == 0 {
				// If missing, check the config file.
				sourceSection = configFile.Section(entry.SourceProfile)
			}
			sourceEntry := newIniConfigEntry(sourceSection)

			// Complete the entry with the source one.
			entry = entry.merge(sourceEntry)
		}

		// Complete the entry with the detault ones.
		entry = entry.merge(defaultEntry)

		secName = strings.TrimPrefix(secName, "profile ") // Remove the "profile " prefixes.
		entry.Name = secName
		// Add the entry to the reg.
		reg[secName] = entry
	}

	return reg
}

// HandlerFunc .
type HandlerFunc func(w http.ResponseWriter, req *http.Request) error

func (h HandlerFunc) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if err := h(w, req); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "%s", err)
	}
}

type controller struct {
	configRegistry

	sync.RWMutex
	roleTokens map[string]tokens
	stopChan   chan struct{}
}

func dumpTokens(w io.Writer, tokens tokens) {
	_, _ = fmt.Fprintf(w, "export AWS_DEFAULT_REGION=%q\n", tokens.Region)
	_, _ = fmt.Fprintf(w, "export AWS_ACCESS_KEY_ID=%q\n", tokens.AccessKeyID)
	_, _ = fmt.Fprintf(w, "export AWS_SECRET_ACCESS_KEY=%q\n", tokens.SecretAccessKey)
	_, _ = fmt.Fprintf(w, "export AWS_SESSION_TOKEN=%q\n", tokens.SessionToken)
	_, _ = fmt.Fprintf(w, "export AWS_SESSION_EXPIRATION=%q\n", tokens.Expiration.In(time.Local))
}

// Common errors.
var (
	ErrMissingMFA = errors.New("missing mfa")
)

func (c *controller) handler(w http.ResponseWriter, req *http.Request) error {
	if err := req.ParseForm(); err != nil {
		return errors.Wrap(err, "ParseForm")
	}
	env := req.Form.Get("env")
	if env == "" {
		return errors.New("missing 'env' query string")
	}

	// Check if we have already valid tokens for the requested env.
	c.RLock()
	tokens, ok := c.roleTokens[env]
	c.RUnlock()
	if ok && tokens.Expiration.After(time.Now()) { // Also make sure that the tokens are not expired.
		dumpTokens(w, tokens)
		return nil
	}

	// If not, get new ones.

	entry, ok := c.configRegistry[env]
	if !ok {
		return errors.New("no configuration found for requested env")
	}

	mfa := req.Form.Get("mfa")
	if entry.MFASerial != "" && mfa == "" {
		return ErrMissingMFA
	}

	if err := c.refreshRoleTokens(req.Context(), entry, mfa); err != nil {
		return errors.Wrap(err, "refreshRoleToken")
	}

	c.RLock()
	tokens = c.roleTokens[env]
	c.RUnlock()

	dumpTokens(w, tokens)
	return nil
}

func (c *controller) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	HandlerFunc(c.handler).ServeHTTP(w, req)
}

func (c *controller) refreshRoleTokens(ctx context.Context, entry configEntry, mfa string) error {
	if entry.RoleARN == "" {
		return errors.New("missing role_arn from config")
	}

	sessionName := entry.SourceProfile
	if sessionName != "" {
		sessionName += "-"
	}
	sessionName += "assume-" + entry.Name

	in := sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(3600),
		RoleArn:         &entry.RoleARN,
		RoleSessionName: &sessionName,
	}

	if entry.MFASerial != "" && mfa != "" {
		in.SerialNumber = &entry.MFASerial
		in.TokenCode = &mfa
	}

	awsCfg := aws.NewConfig()

	if entry.Region != "" {
		awsCfg = awsCfg.WithRegion(entry.Region)
	}

	// If we have a non-expired token, use it, otherwise, try the access key id.
	c.RLock()
	tokens, ok := c.roleTokens[entry.Name]
	c.RUnlock()
	if ok && tokens.Expiration.After(time.Now()) {
		creds := credentials.NewStaticCredentials(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
		awsCfg = awsCfg.WithCredentials(creds)
	} else if entry.AccessKeyID != "" && entry.SecretAccessKey != "" {
		creds := credentials.NewStaticCredentials(entry.AccessKeyID, entry.SecretAccessKey, "")
		awsCfg = awsCfg.WithCredentials(creds)
	}

	awsSession, err := session.NewSession(awsCfg)
	if err != nil {
		return errors.Wrap(err, "aws NewSession")
	}

	stsService := sts.New(awsSession)

	log.Printf("Calling sts.AssumeRole.")
	out, err := stsService.AssumeRoleWithContext(ctx, &in)
	if err != nil {
		return errors.Wrap(err, "sts.AssumeRole")
	}

	c.Lock()
	c.roleTokens[entry.Name] = newTokens(entry.Region, out.Credentials)
	c.Unlock()

	if debugMode {
		c.RLock()
		buf, err := json.Marshal(c.roleTokens)
		c.RUnlock()
		if err != nil {
			return errors.Wrap(err, "marshal roletokens")
		}
		if err := ioutil.WriteFile("/tmp/tt", buf, 0600); err != nil {
			return errors.Wrap(err, "writefile")
		}
	}

	return nil
}

func (c *controller) step() {
	// Copy the roleTokens map so we don't hold the lock.
	c.RLock()
	roleTokens := make(map[string]tokens, len(c.roleTokens))
	for role, tokens := range c.roleTokens {
		roleTokens[role] = tokens
	}
	c.RUnlock()

	for role, tokens := range roleTokens {
		// If the token expires within 10 minutes, refresh it.
		if !tokens.Expiration.Add(-10 * time.Minute).Before(time.Now()) {
			continue
		}
		go func(entry configEntry) {
			log.Printf("Refresh %q", entry.Name)
			if err := c.refreshRoleTokens(context.Background(), entry, ""); err != nil {
				// In case of error, remove the tokens from the role. Next request for it will require mfa.
				log.Printf("Error refreshing token for %q: %s", entry.Name, err)
				c.Lock()
				delete(c.roleTokens, entry.Name)
				c.Unlock()
			}
		}(c.configRegistry[role])
	}
}

func (c *controller) run() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

loop:
	select {
	case <-c.stopChan:
		return
	case <-ticker.C:
		go c.step()
	}
	goto loop
}

func (c *controller) Close() error {
	close(c.stopChan)
	return nil
}

type tokens struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

func newTokens(region string, creds *sts.Credentials) tokens {
	var out tokens
	if creds == nil {
		return out
	}
	out.Region = region
	if creds.AccessKeyId != nil {
		out.AccessKeyID = *creds.AccessKeyId
	}
	if creds.SecretAccessKey != nil {
		out.SecretAccessKey = *creds.SecretAccessKey
	}
	if creds.SessionToken != nil {
		out.SessionToken = *creds.SessionToken
	}
	if creds.Expiration != nil {
		out.Expiration = *creds.Expiration
	}
	return out
}

func server() {
	config, credentials, err := loadAWSConfigFile("", "")
	if err != nil {
		log.Fatalf("Load aws conifg file: %s", err)
	}

	c := &controller{
		configRegistry: processAWSConfig(config, credentials),
		roleTokens:     map[string]tokens{},
		stopChan:       make(chan struct{}),
	}

	if debugMode {
		buf, _ := ioutil.ReadFile("/tmp/tt")
		_ = json.Unmarshal(buf, &c.roleTokens)
	}

	go c.run()
	if err := http.ListenAndServe(":9099", c); err != nil && err != http.ErrServerClosed {
		log.Fatalf("ListenAndServe: %s", err)
	}
}

func client() {
	client := &http.Client{}
	var mfa string
	if len(os.Args) < 2 || os.Args[1] == "" {
		log.Fatalf("Usage: %s <env>", os.Args[0])
	}
	env := os.Args[1]
begin:
	req, err := http.NewRequest(http.MethodGet, "http://localhost:9099?env="+env+"&mfa="+mfa, nil)
	if err != nil {
		log.Fatalf("NewRequest: %s", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Do: %s", err)
	}
	buf, err := ioutil.ReadAll(resp.Body)
	e1 := resp.Body.Close()
	_ = e1 // Best effort.
	if resp.StatusCode == http.StatusInternalServerError && string(buf) == ErrMissingMFA.Error() {
		fmt.Fprintf(os.Stderr, "Enter MFA code: ")
		if _, err := fmt.Scanf("%s", &mfa); err != nil {
			log.Fatalf("Read mfa: %s", err)
		}
		goto begin
	}
	fmt.Printf("%s", buf)
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}

var debugMode bool

func main() {
	var serverMode bool
	flag.BoolVar(&serverMode, "d", false, "Serve mode.")
	flag.BoolVar(&debugMode, "D", false, "Debug mode.")
	flag.Parse()
	if serverMode {
		server()
		return
	}
	client()
}
