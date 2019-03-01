package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/fsnotify/fsnotify"
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

func defaultConfigPaths() (configFilePath, credsFilePath string, err error) {
	u, err := user.Current() // Lookup current user to get HomeDir.
	if err != nil {
		return "", "", errors.Wrap(err, "user.Current")
	}
	return u.HomeDir + "/.aws/config", u.HomeDir + "/.aws/credentials", nil
}

func loadAWSConfigFile(configPath, credentialsPath string) (config, credentials *ini.File, err error) {
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
	roleARN := section.Key("role_arn").String()
	if roleARN == "" {
		roleARN = section.Key("_role_arn").String()
	}
	return configEntry{
		Name:            section.Name(),
		Region:          section.Key("region").String(),
		MFASerial:       section.Key("mfa_serial").String(),
		RoleARN:         roleARN,
		AccessKeyID:     section.Key("aws_access_key_id").String(),
		SecretAccessKey: section.Key("aws_secret_access_key").String(),
		SourceProfile:   section.Key("source_profile").String(),
	}
}

type configRegistry map[string]configEntry

func processAWSConfig(configFile, credentialsFile *ini.File) configRegistry {
	reg := configRegistry{}

	// Load all the other entries.
	for _, secName := range configFile.SectionStrings() {
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
		entry = entry.merge(reg["DEFAULT"])

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

func dumpTokens(w io.Writer, fmtMode string, tokens tokens) {
	if fmtMode == "env" {
		_, _ = fmt.Fprintf(w, "export AWS_DEFAULT_REGION=%q\n", tokens.Region)
		_, _ = fmt.Fprintf(w, "export AWS_ACCESS_KEY_ID=%q\n", tokens.AccessKeyID)
		_, _ = fmt.Fprintf(w, "export AWS_SECRET_ACCESS_KEY=%q\n", tokens.SecretAccessKey)
		_, _ = fmt.Fprintf(w, "export AWS_SESSION_TOKEN=%q\n", tokens.SessionToken)
		_, _ = fmt.Fprintf(w, "export AWS_SESSION_EXPIRATION=%q\n", tokens.Expiration.In(time.Local))
		return
	}
	buf, _ := json.MarshalIndent(tokens, "", "  ")
	_, _ = fmt.Fprintf(w, "%s\n", buf)
}

// Common errors.
var (
	ErrMissingMFA = errors.New("missing mfa")
)

func (c *controller) handler(w http.ResponseWriter, req *http.Request) error {
	if err := req.ParseForm(); err != nil {
		return errors.Wrap(err, "ParseForm")
	}
	profile := req.Form.Get("profile")
	if profile == "" {
		return errors.New("missing 'profile' query string")
	}
	fmtMode := req.Form.Get("fmt")
	if fmtMode == "" {
		fmtMode = "env"
	}

	// Check if we have already valid tokens for the requested env.
	c.Lock()
	tokens, ok := c.roleTokens[profile]
	if ok {
		tokens.LastUse = time.Now()
		c.roleTokens[profile] = tokens
	}
	c.Unlock()
	if ok && tokens.Expiration.After(time.Now()) { // Also make sure that the tokens are not expired.
		dumpTokens(w, fmtMode, tokens)
		return nil
	}

	// If not, get new ones.
	c.RLock()
	entry, ok := c.configRegistry[profile]
	c.RUnlock()
	if !ok {
		return errors.New("no configuration found for requested env")
	}
	if entry.RoleARN == "" {
		return errors.New("no role_arn found for requested env")
	}

	mfa := req.Form.Get("mfa")
	if entry.MFASerial != "" && mfa == "" {
		w.Header().Set("X-Role-Arn", entry.RoleARN)
		w.Header().Set("X-Mfa-Arn", entry.MFASerial)
		return ErrMissingMFA
	}

	if err := c.refreshRoleTokens(req.Context(), entry, mfa); err != nil {
		return errors.Wrap(err, "refreshRoleToken")
	}

	c.Lock()
	tokens = c.roleTokens[profile]
	tokens.LastUse = time.Now()
	c.roleTokens[profile] = tokens
	c.Unlock()

	dumpTokens(w, fmtMode, tokens)
	return nil
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

	newTokens := newTokens(entry.Region, out.Credentials)
	newTokens.LastUse = tokens.LastUse
	c.Lock()
	c.roleTokens[entry.Name] = newTokens
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
		// If the token was not used for more than 24h, drop it.
		if time.Since(tokens.LastUse) >= 24*time.Hour {
			log.Printf("%s not used for 24h, dropping it.", role)
			log.Printf("Last use was %s.", tokens.LastUse.In(time.Local))
			c.Lock()
			delete(c.roleTokens, role)
			c.Unlock()
			continue
		}
		// If the token expires within 10 minutes, refresh it.
		if !tokens.Expiration.Add(-10 * time.Minute).Before(time.Now()) {
			continue
		}
		c.RLock()
		entry := c.configRegistry[role]
		c.RUnlock()
		go func(entry configEntry) {
			log.Printf("Refresh %q - %s.", entry.Name, entry.RoleARN)
			if err := c.refreshRoleTokens(context.Background(), entry, ""); err != nil {
				// In case of error, remove the tokens from the role. Next request for it will require mfa.
				log.Printf("Error refreshing token for %q: %s.", entry.Name, err)
				c.Lock()
				delete(c.roleTokens, entry.Name)
				c.Unlock()
			}
		}(entry)
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
	Version         int       `json:"Version"` // Always "1".
	Region          string    `json:"Region"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiraiton"`
	LastUse         time.Time `json:"LastUse"`
}

func newTokens(region string, creds *sts.Credentials) tokens {
	var out tokens
	if creds == nil {
		return out
	}
	out.Region = region
	out.Version = 1
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

func (c *controller) healthcheck(w http.ResponseWriter, req *http.Request) {
	_ = req.ParseForm()

	type roleToken struct {
		Name       string
		Region     string
		Expiraiton time.Time
		LastUse    time.Time
	}
	roleTokens := make([]roleToken, 0, len(c.roleTokens))
	c.RLock()
	for name, tokens := range c.roleTokens {
		roleTokens = append(roleTokens, roleToken{
			Name:       name,
			Region:     tokens.Region,
			Expiraiton: tokens.Expiration,
			LastUse:    tokens.LastUse,
		})
	}
	reg := make(configRegistry, len(c.configRegistry))
	for k, v := range c.configRegistry {
		reg[k] = v
	}
	c.RUnlock()

	out := map[string]interface{}{
		"role_tokens": roleTokens,
	}
	if req.Form.Get("config") != "" {
		out["config_registry"] = reg
	}

	buf, _ := json.MarshalIndent(out, "", "  ")
	_, _ = fmt.Fprintf(w, "%s\n", buf)
}

func server() {
	configPath, credsPath, err := defaultConfigPaths()
	if err != nil {
		log.Fatalf("Lookup default aws files: %s.", err)
	}
	config, credentials, err := loadAWSConfigFile(configPath, credsPath)
	if err != nil {
		log.Fatalf("Load aws config files: %s.", err)
	}

	c := &controller{
		configRegistry: processAWSConfig(config, credentials),
		roleTokens:     map[string]tokens{},
		stopChan:       make(chan struct{}),
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Error starting fsnotify watcher: %s.", err)
	}
	if err := watcher.Add(configPath); err != nil {
		log.Fatalf("Error adding the config file to the fsnotify watcher: %s.", err)
	}
	if err := watcher.Add(credsPath); err != nil {
		log.Fatalf("Error adding the creds file to the fsnotify watcher: %s.", err)
	}
	go func() {
	loop:
		select {
		case <-watcher.Events:
			config, credentials, err := loadAWSConfigFile(configPath, credsPath)
			if err != nil {
				log.Fatalf("Load aws config files: %s.", err)
			}
			c.Lock()
			c.configRegistry = processAWSConfig(config, credentials)
			c.Unlock()
		case <-c.stopChan:
			return
		}
		goto loop
	}()

	if debugMode {
		buf, _ := ioutil.ReadFile("/tmp/tt")
		_ = json.Unmarshal(buf, &c.roleTokens)
	}

	go c.run()
	http.Handle("/", HandlerFunc(c.handler))
	http.HandleFunc("/healthcheck", c.healthcheck)
	if err := http.ListenAndServe(":9099", nil); err != nil && err != http.ErrServerClosed {
		log.Fatalf("ListenAndServe: %s", err)
	}
}

func lookupParentProcessProfileDarwin() string {
	// TODO: FInd the proper way to use the sysctl syscall to get the parent's commandline.
	cmd := exec.Command("ps", "-p", fmt.Sprintf("%d", os.Getppid()), "-o", "command")
	buf, _ := cmd.Output() // Best effort.
	parts := strings.Split(string(buf), " ")
	var profile string
	for i, elem := range parts {
		if string(elem) != "--profile" || i >= len(parts)-1 {
			continue
		}
		profile = string(parts[i+1])
		break
	}
	log.Printf(">>> %s", profile)
	return profile
}

func lookupParentProcessProfile() string {
	// TODO: Add support for osx.
	if runtime.GOOS != "linux" {
		return lookupParentProcessProfileDarwin()
	}
	parentCmdLine, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", os.Getppid()))
	if err != nil {
		panic(err)
	}
	parts := bytes.Split(parentCmdLine, []byte{0})
	var profile string
	for i, elem := range parts {
		if string(elem) != "--profile" || i >= len(parts)-1 {
			continue
		}
		profile = string(parts[i+1])
		break
	}
	return profile
}

func lookupProfile() string {
	profile := flag.Arg(0)
	if profile == "" {
		profile = lookupParentProcessProfile()
	}
	if profile == "" {
		profile = os.Getenv("AWS_PROFILE")
	}
	if profile == "" {
		profile = os.Getenv("AWS_DEFAULT_PROFILE")
	}
	return profile
}

func client() {
	client := &http.Client{}
	var mfa string
	profile := lookupProfile()
	if profile == "" {
		log.Fatalf("Usage: %s <env>", os.Args[0])
	}
begin:
	req, err := http.NewRequest(http.MethodGet, "http://localhost:9099?fmt="+fmtMode+"&profile="+profile+"&mfa="+mfa, nil)
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
		_, _ = fmt.Fprintf(os.Stderr, "[%s] %s.\n", profile, resp.Header.Get("X-Role-Arn"))
		_, _ = fmt.Fprintf(os.Stderr, "Enter MFA code for %s: ", resp.Header.Get("X-Mfa-Arn"))
		if _, err := fmt.Scanf("%s", &mfa); err != nil {
			log.Fatalf("Read mfa: %s", err)
		}
		goto begin
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Error getting credentials for %q: %s\n", profile, buf)
	}
	fmt.Printf("%s", buf)
}

var debugMode bool
var fmtMode string

func main() {
	var serverMode bool
	flag.BoolVar(&serverMode, "d", false, "Serve mode.")
	flag.BoolVar(&debugMode, "D", false, "Debug mode.")
	flag.StringVar(&fmtMode, "f", "json", "Output format in client mode. 'json' or 'env'.")
	flag.Parse()
	if serverMode {
		server()
		return
	}
	client()
}
