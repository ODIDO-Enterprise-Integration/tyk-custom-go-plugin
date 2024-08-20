/*
Upstream (back-end) OAuth2 authentication plugin.

Usage from an OAS API:
1) Add the following parameters to Plugin Configuration/Config Data (example is for Salesforce)
{
  "BACKEND_ID": "SalesforceCRM",
  "BACKEND_OAUTH_CLIENT_ID": "SFCRM_OAUTH_CLIENT_ID",
  "BACKEND_OAUTH_CLIENT_SECRET": "SFCRM_OAUTH_CLIENT_SECRET",
  "BACKEND_OAUTH_GRANT_TYPE": "SFCRM_OAUTH_GRANT_TYPE",
  "BACKEND_OAUTH_PASSWORD": "SFCRM_OAUTH_PASSWORD",
  "BACKEND_OAUTH_TOKEN_ENDPOINT": "SFCRM_OAUTH_TOKEN_ENDPOINT",
  "BACKEND_OAUTH_USERNAME": "SFCRM_OAUTH_USERNAME"
}
2) Set Plugin Configuration/Plugin Driver to "Go Plugin"
3) Add the following Post-plugin:
 - Function Name = UpstreamOauthLogin
 - Path = /opt/tyk-gateway/middleware/CustomGoPlugin.so
4) Add the following Response-plugin:
 - Function Name = CheckForExpiredAuth
 - Path = /opt/tyk-gateway/middleware/CustomGoPlugin.so
5) Make sure that the following Environment Variables are set for the Tyk Gateway (var names from step 1)
 - SFCRM_OAUTH_GRANT_TYPE=password
 - SFCRM_OAUTH_TOKEN_ENDPOINT=https://login.salesforce.com/services/oauth2/token
 - SFCRM_OAUTH_USERNAME=****
 - SFCRM_OAUTH_PASSWORD=****
 - SFCRM_OAUTH_CLIENT_ID=****
 - SFCRM_OAUTH_CLIENT_SECRET=****

 You may have 0 or 1 OAuth2 back-end set up for an API
 Each API may have its own back-end each of them would use a separate set of environment variables,
*/

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/ctx"
	"github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/storage"
)

var logger = log.Get()
var store storage.RedisCluster

const BackendId = "BACKEND_ID"
const BackendOauthGrantType = "BACKEND_OAUTH_GRANT_TYPE"
const BackendOauthClientId = "BACKEND_OAUTH_CLIENT_ID"
const BackendOauthClientSecret = "BACKEND_OAUTH_CLIENT_SECRET"
const BackendOauthTokenEndpoint = "BACKEND_OAUTH_TOKEN_ENDPOINT"
const BackendOauthUsername = "BACKEND_OAUTH_USERNAME"
const BackendOauthPassword = "BACKEND_OAUTH_PASSWORD"

const TokenCacheKeyHeader = "X-Odido-Backend-Id"

const RedisKeyPrefix = "odido.oauth.token."

func getStore(appCtx context.Context) storage.RedisCluster {

	// Get Tyk Config
	conf := config.Global()

	logger.Infof("Global config: %v+", conf)

	// Create Redis Controller
	rc := storage.NewRedisController(appCtx)
	logger.Debug("Created Redis Controller. Connected?", rc.Connected())

	store := storage.RedisCluster{KeyPrefix: "", HashKeys: conf.HashKeys, RedisController: rc}
	go rc.ConnectToRedis(appCtx, nil, &conf)
	for i := 0; i < 5; i++ { // max 5 attempts - should only take 2
		if rc.Connected() {
			logger.Debug("Redis Controller connected")
			break
		}
		logger.Debug("Redis Controller not connected, will retry")

		time.Sleep(10 * time.Millisecond)
	}

	if !rc.Connected() {
		logger.Error("Could not connect to storage")
	}

	return store
}

func getEnvVar(name interface{}) string {
	value := os.Getenv(name.(string))
	if value == "" {
		logger.Errorf("Environment variable is not set: %v", name)
	}
	return value
}

func login(pluginConfig map[string]interface{}) (string, string, int64) {

	clientId := getEnvVar(pluginConfig[BackendOauthClientId].(string))
	clientSecret := getEnvVar(pluginConfig[BackendOauthClientSecret].(string))
	username := getEnvVar(pluginConfig[BackendOauthUsername].(string))
	password := getEnvVar(pluginConfig[BackendOauthPassword].(string))
	tokenEndpoint := getEnvVar(pluginConfig[BackendOauthTokenEndpoint].(string))
	grantType := getEnvVar(pluginConfig[BackendOauthGrantType].(string))

	if clientId != "" && clientSecret != "" && username != "" && password != "" && tokenEndpoint != "" {
		loginBody := url.Values{}
		loginBody.Set("grant_type", grantType)
		loginBody.Add("client_id", clientId)
		loginBody.Add("client_secret", clientSecret)
		if grantType == "password" {
			loginBody.Add("format", "json")
			loginBody.Add("username", username)
			loginBody.Add("password", password)
		}

		logger.Debugf("sending login request to %s: %v", tokenEndpoint, loginBody)

		loginResponse, err := http.PostForm(tokenEndpoint, loginBody)

		if err != nil {
			logger.Errorf("error logging in to %s : %v", tokenEndpoint, err)
			return "", "", 0
		}

		if loginResponse.StatusCode >= 400 {
			logger.Errorf("error logging in to %s : %+v", tokenEndpoint, loginResponse)
			body, _ := io.ReadAll(loginResponse.Body)
			logger.Errorf("%+v", string(body))
			return "", "", 0
		}

		defer loginResponse.Body.Close()
		loginResponseBody, err2 := io.ReadAll(loginResponse.Body)
		if err2 != nil {
			logger.Infof("error reading response from %s : %v", tokenEndpoint, err2)
			return "", "", 0
		}
		var responseMap map[string]interface{}
		err3 := json.Unmarshal(loginResponseBody, &responseMap)

		if err3 != nil {
			logger.Infof("error decoding response %v: %v", string(loginResponseBody[:]), err3)
			return "", "", 0
		}

		logger.Infof("logged in to %s : %v", tokenEndpoint, responseMap)
		accessToken := responseMap["access_token"].(string)
		instanceUrl := ""
		if responseMap["instance_url"] != nil {
			instanceUrl = responseMap["instance_url"].(string)
		}
		expiresIn := int64(3600)
		if responseMap["expires_in"] != nil {
			expiresIn = responseMap["expires_in"].(int64)
		}
		return accessToken, instanceUrl, expiresIn

	}
	return "", "", 0
}

func UpstreamOauthLogin(rw http.ResponseWriter, r *http.Request) {

	apiDef := ctx.GetOASDefinition(r)
	apiExtensions := apiDef.GetTykExtension()

	logger.Infof("API Extensions: %+v", apiExtensions)
	pluginConfig := apiExtensions.Middleware.Global.PluginConfig.Data.Value
	backendId := pluginConfig[BackendId].(string)
	cacheKey := RedisKeyPrefix + backendId
	accessToken := ""
	instanceUrl := ""

	ttlSeconds, err := store.GetKeyTTL(cacheKey)
	if err == nil {
		if ttlSeconds > 1 {
			accessTokenAndUrl, err2 := store.GetKey(cacheKey)
			if err2 == nil && strings.Contains(accessTokenAndUrl, "|") {
				parts := strings.Split(accessTokenAndUrl, "|")
				accessToken = parts[0]
				instanceUrl = parts[1]
			} else {
				logger.Warnf("Error retrieving access token value from cache: %v", err2)
			}
		} else {
			logger.Info("Access token expired, acquiring a new one")
		}
	} else {
		logger.Warnf("Error retrieving access token TTL from cache: %v", err)
	}

	if accessToken == "" {
		accessToken2, instanceUrl2, ttlSeconds2 := login(pluginConfig)
		if accessToken2 != "" && ttlSeconds2 > 0 {
			store.SetKey(cacheKey, accessToken2+"|"+instanceUrl2, ttlSeconds2)
			accessToken = accessToken2
			instanceUrl = instanceUrl2
			logger.Info("Acquired access token for " + backendId)
		} else {
			logger.Error("Cannot acquire access token for " + backendId)
			accessToken = ""
		}
	}

	if instanceUrl != "" {
		logger.Debugf("instance URL: %s", instanceUrl)
		apiExtensions.Upstream.URL = instanceUrl
		logger.Infof("NEW API Extensions: %+v", apiExtensions)
		apiDef.SetTykExtension(apiExtensions)

		// *** Try setting the OAS, instead of the deep copy of the OAS
		// v := r.Context().Value(ctx.OASDefinition)
		// myOas, ok := v.(*oas.OAS)

		// if ok {
		// 	myOas.SetTykExtension(apiExtensions)
		// 	logger.Infof("NEW API Extensions were set: %+v", ctx.GetOASDefinition(r).GetTykExtension())
		// } else {
		// 	logger.Warn("NEW API Extensions were not set!")
		// }

		newUrl := instanceUrl + r.URL.Path + "?" + r.URL.RawQuery
		r.Header.Add("X-Odido-Request-URL", newUrl)
		// *** Try updating the pointer to the request - I don't know Go, but this would not make sense in C, I try it anyway
		// ctx2 := context.WithValue(r.Context(), ctx.UrlRewriteTarget, newUrl)
		// r2 := r.WithContext(ctx2)
		// *r = *r2
	}

	if accessToken != "" {
		r.Header.Add(TokenCacheKeyHeader, backendId)
		r.Header.Add("Authorization", "Bearer "+accessToken)
	}
}

func CheckForExpiredAuth(rw http.ResponseWriter, res *http.Response, req *http.Request) {

	serverName := res.TLS.ServerName
	certs := res.TLS.PeerCertificates
	certSubject := "unknown"
	if len(certs) > 0 {
		certSubject = certs[0].Subject.CommonName
	}
	requestHostHeader := res.Request.Host
	requestUrl := req.Header.Get("X-Odido-Request-URL")

	logger.Info("####### X-TLS-SNI " + serverName)
	logger.Info("####### X-TLS-Cert-Subject " + certSubject)
	logger.Info("####### X-Request-Host-Header " + requestHostHeader)

	res.Header.Add("X-Odido-TLS-SNI", serverName)
	res.Header.Add("X-Odido-TLS-Cert-Subject", certSubject)
	res.Header.Add("X-Odido-Request-Host-Header", requestHostHeader)
	res.Header.Add("X-Odido-Request-URL", requestUrl)

	if res.StatusCode == 401 {
		backendId := req.Header.Get(TokenCacheKeyHeader)
		if backendId != "" {
			cacheKey := RedisKeyPrefix + backendId
			logger.Infof("Service returned 401 response, deleting key from token cache: %s", cacheKey)
			store.DeleteKey(cacheKey)
		}
	}
}

func main() {}

// This will be run during Gateway startup
func init() {

	store = getStore(context.Background())

	logger.Info("--- Go custom plugin init success! ---- ")
}
