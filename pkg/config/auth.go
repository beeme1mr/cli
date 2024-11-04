package config

import (
	"strings"
	"time"

	v1API "github.com/supabase/cli/pkg/api"
	"github.com/supabase/cli/pkg/cast"
	"github.com/supabase/cli/pkg/diff"
)

type (
	auth struct {
		Enabled                bool     `toml:"enabled"`
		Image                  string   `toml:"-"`
		SiteUrl                string   `toml:"site_url"`
		AdditionalRedirectUrls []string `toml:"additional_redirect_urls"`

		JwtExpiry                  uint `toml:"jwt_expiry"`
		EnableRefreshTokenRotation bool `toml:"enable_refresh_token_rotation"`
		RefreshTokenReuseInterval  uint `toml:"refresh_token_reuse_interval"`
		EnableManualLinking        bool `toml:"enable_manual_linking"`

		Hook     hook     `toml:"hook"`
		MFA      mfa      `toml:"mfa"`
		Sessions sessions `toml:"sessions"`

		EnableSignup           bool        `toml:"enable_signup"`
		EnableAnonymousSignIns bool        `toml:"enable_anonymous_sign_ins"`
		Email                  email       `toml:"email"`
		Sms                    sms         `toml:"sms"`
		External               extProvider `toml:"external"`

		// Custom secrets can be injected from .env file
		JwtSecret      string `toml:"-" mapstructure:"jwt_secret"`
		AnonKey        string `toml:"-" mapstructure:"anon_key"`
		ServiceRoleKey string `toml:"-" mapstructure:"service_role_key"`

		ThirdParty thirdParty `toml:"third_party"`
	}

	extProvider map[string]provider

	thirdParty struct {
		Firebase tpaFirebase `toml:"firebase"`
		Auth0    tpaAuth0    `toml:"auth0"`
		Cognito  tpaCognito  `toml:"aws_cognito"`
	}

	tpaFirebase struct {
		Enabled bool `toml:"enabled"`

		ProjectID string `toml:"project_id"`
	}

	tpaAuth0 struct {
		Enabled bool `toml:"enabled"`

		Tenant       string `toml:"tenant"`
		TenantRegion string `toml:"tenant_region"`
	}

	tpaCognito struct {
		Enabled bool `toml:"enabled"`

		UserPoolID     string `toml:"user_pool_id"`
		UserPoolRegion string `toml:"user_pool_region"`
	}

	email struct {
		EnableSignup         bool                     `toml:"enable_signup"`
		DoubleConfirmChanges bool                     `toml:"double_confirm_changes"`
		EnableConfirmations  bool                     `toml:"enable_confirmations"`
		SecurePasswordChange bool                     `toml:"secure_password_change"`
		Template             map[string]emailTemplate `toml:"template"`
		Smtp                 smtp                     `toml:"smtp"`
		MaxFrequency         time.Duration            `toml:"max_frequency"`
		OtpLength            uint                     `toml:"otp_length"`
		OtpExpiry            uint                     `toml:"otp_expiry"`
	}

	smtp struct {
		Host       string `toml:"host"`
		Port       uint16 `toml:"port"`
		User       string `toml:"user"`
		Pass       string `toml:"pass"`
		AdminEmail string `toml:"admin_email"`
		SenderName string `toml:"sender_name"`
	}

	emailTemplate struct {
		Subject     string `toml:"subject"`
		ContentPath string `toml:"content_path"`
	}

	sms struct {
		EnableSignup        bool              `toml:"enable_signup"`
		EnableConfirmations bool              `toml:"enable_confirmations"`
		Template            string            `toml:"template"`
		Twilio              twilioConfig      `toml:"twilio" mapstructure:"twilio"`
		TwilioVerify        twilioConfig      `toml:"twilio_verify" mapstructure:"twilio_verify"`
		Messagebird         messagebirdConfig `toml:"messagebird" mapstructure:"messagebird"`
		Textlocal           textlocalConfig   `toml:"textlocal" mapstructure:"textlocal"`
		Vonage              vonageConfig      `toml:"vonage" mapstructure:"vonage"`
		TestOTP             map[string]string `toml:"test_otp"`
		MaxFrequency        time.Duration     `toml:"max_frequency"`
	}

	hook struct {
		MFAVerificationAttempt      hookConfig `toml:"mfa_verification_attempt"`
		PasswordVerificationAttempt hookConfig `toml:"password_verification_attempt"`
		CustomAccessToken           hookConfig `toml:"custom_access_token"`
		SendSMS                     hookConfig `toml:"send_sms"`
		SendEmail                   hookConfig `toml:"send_email"`
	}

	factorTypeConfiguration struct {
		EnrollEnabled bool `toml:"enroll_enabled"`
		VerifyEnabled bool `toml:"verify_enabled"`
	}

	phoneFactorTypeConfiguration struct {
		factorTypeConfiguration
		OtpLength    uint          `toml:"otp_length"`
		Template     string        `toml:"template"`
		MaxFrequency time.Duration `toml:"max_frequency"`
	}

	mfa struct {
		TOTP               factorTypeConfiguration      `toml:"totp"`
		Phone              phoneFactorTypeConfiguration `toml:"phone"`
		WebAuthn           factorTypeConfiguration      `toml:"web_authn"`
		MaxEnrolledFactors uint                         `toml:"max_enrolled_factors"`
	}

	hookConfig struct {
		Enabled bool   `toml:"enabled"`
		URI     string `toml:"uri"`
		Secrets string `toml:"secrets"`
	}

	sessions struct {
		Timebox           time.Duration `toml:"timebox"`
		InactivityTimeout time.Duration `toml:"inactivity_timeout"`
	}

	twilioConfig struct {
		Enabled           bool   `toml:"enabled"`
		AccountSid        string `toml:"account_sid"`
		MessageServiceSid string `toml:"message_service_sid"`
		AuthToken         string `toml:"auth_token" mapstructure:"auth_token"`
	}

	messagebirdConfig struct {
		Enabled    bool   `toml:"enabled"`
		Originator string `toml:"originator"`
		AccessKey  string `toml:"access_key" mapstructure:"access_key"`
	}

	textlocalConfig struct {
		Enabled bool   `toml:"enabled"`
		Sender  string `toml:"sender"`
		ApiKey  string `toml:"api_key" mapstructure:"api_key"`
	}

	vonageConfig struct {
		Enabled   bool   `toml:"enabled"`
		From      string `toml:"from"`
		ApiKey    string `toml:"api_key" mapstructure:"api_key"`
		ApiSecret string `toml:"api_secret" mapstructure:"api_secret"`
	}

	provider struct {
		Enabled        bool   `toml:"enabled"`
		ClientId       string `toml:"client_id"`
		Secret         string `toml:"secret"`
		Url            string `toml:"url"`
		RedirectUri    string `toml:"redirect_uri"`
		SkipNonceCheck bool   `toml:"skip_nonce_check"`
	}
)

func (a *auth) ToUpdateAuthConfigBody() v1API.UpdateAuthConfigBody {
	body := v1API.UpdateAuthConfigBody{
		SiteUrl:                           &a.SiteUrl,
		UriAllowList:                      cast.Ptr(strings.Join(a.AdditionalRedirectUrls, ",")),
		JwtExp:                            cast.UintToIntPtr(&a.JwtExpiry),
		RefreshTokenRotationEnabled:       &a.EnableRefreshTokenRotation,
		SecurityRefreshTokenReuseInterval: cast.UintToIntPtr(&a.RefreshTokenReuseInterval),
		SecurityManualLinkingEnabled:      &a.EnableManualLinking,
		DisableSignup:                     cast.Ptr(!a.EnableSignup),
		ExternalAnonymousUsersEnabled:     &a.EnableAnonymousSignIns,
	}
	a.Sms.updateAuthConfigBody(&body)
	a.Hook.updateAuthConfigBody(&body)
	a.External.updateAuthConfigBody(&body)
	return body
}

func (s sms) updateAuthConfigBody(body *v1API.UpdateAuthConfigBody) {
	body.ExternalPhoneEnabled = &s.EnableSignup
	body.SmsMaxFrequency = cast.Ptr(int(s.MaxFrequency.Seconds()))
	body.SmsAutoconfirm = &s.EnableConfirmations
	body.SmsTemplate = &s.Template
	if otpString := mapToEnv(s.TestOTP); len(otpString) > 0 {
		body.SmsTestOtp = &otpString
	}
	switch {
	case s.Twilio.Enabled:
		body.SmsProvider = cast.Ptr("twilio")
	case s.TwilioVerify.Enabled:
		body.SmsProvider = cast.Ptr("twilio_verify")
	case s.Messagebird.Enabled:
		body.SmsProvider = cast.Ptr("messagebird")
	case s.Textlocal.Enabled:
		body.SmsProvider = cast.Ptr("textlocal")
	case s.Vonage.Enabled:
		body.SmsProvider = cast.Ptr("vonage")
	}
	// TODO: simplify this logic by making local config pointers?
	if len(s.Twilio.AccountSid) > 0 {
		body.SmsTwilioAccountSid = &s.Twilio.AccountSid
	}
	if len(s.Twilio.AuthToken) > 0 {
		body.SmsTwilioAuthToken = &s.Twilio.AuthToken
	}
	if len(s.Twilio.MessageServiceSid) > 0 {
		body.SmsTwilioMessageServiceSid = &s.Twilio.MessageServiceSid
	}
	if len(s.TwilioVerify.AccountSid) > 0 {
		body.SmsTwilioVerifyAccountSid = &s.TwilioVerify.AccountSid
	}
	if len(s.TwilioVerify.AuthToken) > 0 {
		body.SmsTwilioVerifyAuthToken = &s.TwilioVerify.AuthToken
	}
	if len(s.TwilioVerify.MessageServiceSid) > 0 {
		body.SmsTwilioVerifyMessageServiceSid = &s.TwilioVerify.MessageServiceSid
	}
	if len(s.Messagebird.AccessKey) > 0 {
		body.SmsMessagebirdAccessKey = &s.Messagebird.AccessKey
	}
	if len(s.Messagebird.Originator) > 0 {
		body.SmsMessagebirdOriginator = &s.Messagebird.Originator
	}
	if len(s.Textlocal.ApiKey) > 0 {
		body.SmsTextlocalApiKey = &s.Textlocal.ApiKey
	}
	if len(s.Textlocal.Sender) > 0 {
		body.SmsTextlocalSender = &s.Textlocal.Sender
	}
	if len(s.Vonage.ApiKey) > 0 {
		body.SmsVonageApiKey = &s.Vonage.ApiKey
	}
	if len(s.Vonage.ApiSecret) > 0 {
		body.SmsVonageApiSecret = &s.Vonage.ApiSecret
	}
	if len(s.Vonage.From) > 0 {
		body.SmsVonageFrom = &s.Vonage.From
	}
}

func (h hook) updateAuthConfigBody(body *v1API.UpdateAuthConfigBody) {
	body.HookCustomAccessTokenEnabled = &h.CustomAccessToken.Enabled
	if len(h.CustomAccessToken.URI) > 0 {
		body.HookCustomAccessTokenUri = &h.CustomAccessToken.URI
	}
	if len(h.CustomAccessToken.Secrets) > 0 {
		body.HookCustomAccessTokenSecrets = &h.CustomAccessToken.Secrets
	}
	body.HookMfaVerificationAttemptEnabled = &h.MFAVerificationAttempt.Enabled
	if len(h.MFAVerificationAttempt.URI) > 0 {
		body.HookMfaVerificationAttemptUri = &h.MFAVerificationAttempt.URI
	}
	if len(h.MFAVerificationAttempt.Secrets) > 0 {
		body.HookMfaVerificationAttemptSecrets = &h.MFAVerificationAttempt.Secrets
	}
	body.HookPasswordVerificationAttemptEnabled = &h.PasswordVerificationAttempt.Enabled
	if len(h.PasswordVerificationAttempt.URI) > 0 {
		body.HookPasswordVerificationAttemptUri = &h.PasswordVerificationAttempt.URI
	}
	if len(h.PasswordVerificationAttempt.Secrets) > 0 {
		body.HookPasswordVerificationAttemptSecrets = &h.PasswordVerificationAttempt.Secrets
	}
	body.HookSendEmailEnabled = &h.SendEmail.Enabled
	if len(h.SendEmail.URI) > 0 {
		body.HookSendEmailUri = &h.SendEmail.URI
	}
	if len(h.SendEmail.Secrets) > 0 {
		body.HookSendEmailSecrets = &h.SendEmail.Secrets
	}
	body.HookSendSmsEnabled = &h.SendSMS.Enabled
	if len(h.SendSMS.URI) > 0 {
		body.HookSendSmsUri = &h.SendSMS.URI
	}
	if len(h.SendSMS.Secrets) > 0 {
		body.HookSendSmsSecrets = &h.SendSMS.Secrets
	}
}

func (p extProvider) updateAuthConfigBody(body *v1API.UpdateAuthConfigBody) {
	var prov provider
	// Ignore deprecated fields: "linkedin", "slack"
	prov = p["apple"]
	body.ExternalAppleEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalAppleClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalAppleSecret = &prov.Secret
	}
	prov = p["azure"]
	body.ExternalAzureEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalAzureClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalAzureSecret = &prov.Secret
	}
	if len(prov.Url) > 0 {
		body.ExternalAzureUrl = &prov.Url
	}
	prov = p["bitbucket"]
	body.ExternalBitbucketEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalBitbucketClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalBitbucketSecret = &prov.Secret
	}
	prov = p["discord"]
	body.ExternalDiscordEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalDiscordClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalDiscordSecret = &prov.Secret
	}
	prov = p["facebook"]
	body.ExternalFacebookEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalFacebookClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalFacebookSecret = &prov.Secret
	}
	prov = p["github"]
	body.ExternalGithubEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalGithubClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalGithubSecret = &prov.Secret
	}
	prov = p["gitlab"]
	body.ExternalGitlabEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalGitlabClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalGitlabSecret = &prov.Secret
	}
	if len(prov.Url) > 0 {
		body.ExternalGitlabUrl = &prov.Url
	}
	prov = p["google"]
	body.ExternalGoogleEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalGoogleClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalGoogleSecret = &prov.Secret
	}
	body.ExternalGoogleSkipNonceCheck = &prov.SkipNonceCheck
	prov = p["keycloak"]
	body.ExternalKeycloakEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalKeycloakClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalKeycloakSecret = &prov.Secret
	}
	if len(prov.Url) > 0 {
		body.ExternalKeycloakUrl = &prov.Url
	}
	prov = p["linkedin_oidc"]
	body.ExternalLinkedinOidcEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalLinkedinOidcClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalLinkedinOidcSecret = &prov.Secret
	}
	prov = p["notion"]
	body.ExternalNotionEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalNotionClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalNotionSecret = &prov.Secret
	}
	prov = p["slack_oidc"]
	body.ExternalSlackOidcEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalSlackOidcClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalSlackOidcSecret = &prov.Secret
	}
	prov = p["spotify"]
	body.ExternalSpotifyEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalSpotifyClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalSpotifySecret = &prov.Secret
	}
	prov = p["twitch"]
	body.ExternalTwitchEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalTwitchClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalTwitchSecret = &prov.Secret
	}
	prov = p["twitter"]
	body.ExternalTwitterEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalTwitterClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalTwitterSecret = &prov.Secret
	}
	prov = p["workos"]
	body.ExternalWorkosEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalWorkosClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalWorkosSecret = &prov.Secret
	}
	if len(prov.Url) > 0 {
		body.ExternalWorkosUrl = &prov.Url
	}
	prov = p["zoom"]
	body.ExternalZoomEnabled = &prov.Enabled
	if len(prov.ClientId) > 0 {
		body.ExternalZoomClientId = &prov.ClientId
	}
	if len(prov.Secret) > 0 {
		body.ExternalZoomSecret = &prov.Secret
	}
}

func (a *auth) fromRemoteAuthConfig(remoteConfig v1API.AuthConfigResponse) auth {
	result := *a
	result.SiteUrl = cast.Val(remoteConfig.SiteUrl, "")
	result.AdditionalRedirectUrls = strToArr(cast.Val(remoteConfig.UriAllowList, ""))
	result.JwtExpiry = cast.IntToUint(cast.Val(remoteConfig.JwtExp, 0))
	result.EnableRefreshTokenRotation = cast.Val(remoteConfig.RefreshTokenRotationEnabled, false)
	result.RefreshTokenReuseInterval = cast.IntToUint(cast.Val(remoteConfig.SecurityRefreshTokenReuseInterval, 0))
	result.EnableManualLinking = cast.Val(remoteConfig.SecurityManualLinkingEnabled, false)
	result.EnableSignup = !cast.Val(remoteConfig.DisableSignup, false)
	result.EnableAnonymousSignIns = cast.Val(remoteConfig.ExternalAnonymousUsersEnabled, false)
	// SMS config
	result.Sms.EnableSignup = cast.Val(remoteConfig.ExternalPhoneEnabled, false)
	result.Sms.MaxFrequency = time.Duration(cast.Val(remoteConfig.SmsMaxFrequency, 0)) * time.Second
	result.Sms.EnableConfirmations = cast.Val(remoteConfig.SmsAutoconfirm, false)
	result.Sms.Template = cast.Val(remoteConfig.SmsTemplate, "")
	result.Sms.TestOTP = envToMap(cast.Val(remoteConfig.SmsTestOtp, ""))
	if provider := cast.Val(remoteConfig.SmsProvider, ""); len(provider) > 0 {
		result.Sms.Twilio.Enabled = provider == "twilio"
		result.Sms.TwilioVerify.Enabled = provider == "twilio_verify"
		result.Sms.Messagebird.Enabled = provider == "messagebird"
		result.Sms.Textlocal.Enabled = provider == "textlocal"
		result.Sms.Vonage.Enabled = provider == "vonage"
	}
	result.Sms.Twilio.AccountSid = cast.Val(remoteConfig.SmsTwilioAccountSid, "")
	result.Sms.Twilio.AuthToken = cast.Val(remoteConfig.SmsTwilioAuthToken, "")
	result.Sms.Twilio.MessageServiceSid = cast.Val(remoteConfig.SmsTwilioMessageServiceSid, "")
	result.Sms.TwilioVerify.AccountSid = cast.Val(remoteConfig.SmsTwilioVerifyAccountSid, "")
	result.Sms.TwilioVerify.AuthToken = cast.Val(remoteConfig.SmsTwilioVerifyAuthToken, "")
	result.Sms.TwilioVerify.MessageServiceSid = cast.Val(remoteConfig.SmsTwilioVerifyMessageServiceSid, "")
	result.Sms.Messagebird.AccessKey = cast.Val(remoteConfig.SmsMessagebirdAccessKey, "")
	result.Sms.Messagebird.Originator = cast.Val(remoteConfig.SmsMessagebirdOriginator, "")
	result.Sms.Textlocal.ApiKey = cast.Val(remoteConfig.SmsTextlocalApiKey, "")
	result.Sms.Textlocal.Sender = cast.Val(remoteConfig.SmsTextlocalSender, "")
	result.Sms.Vonage.ApiKey = cast.Val(remoteConfig.SmsVonageApiKey, "")
	result.Sms.Vonage.ApiSecret = cast.Val(remoteConfig.SmsVonageApiSecret, "")
	result.Sms.Vonage.From = cast.Val(remoteConfig.SmsVonageFrom, "")
	// Hooks config
	result.Hook.CustomAccessToken.Enabled = cast.Val(remoteConfig.HookCustomAccessTokenEnabled, false)
	result.Hook.CustomAccessToken.URI = cast.Val(remoteConfig.HookCustomAccessTokenUri, "")
	result.Hook.CustomAccessToken.Secrets = cast.Val(remoteConfig.HookCustomAccessTokenSecrets, "")
	result.Hook.MFAVerificationAttempt.Enabled = cast.Val(remoteConfig.HookMfaVerificationAttemptEnabled, false)
	result.Hook.MFAVerificationAttempt.URI = cast.Val(remoteConfig.HookMfaVerificationAttemptUri, "")
	result.Hook.MFAVerificationAttempt.Secrets = cast.Val(remoteConfig.HookMfaVerificationAttemptSecrets, "")
	result.Hook.PasswordVerificationAttempt.Enabled = cast.Val(remoteConfig.HookPasswordVerificationAttemptEnabled, false)
	result.Hook.PasswordVerificationAttempt.URI = cast.Val(remoteConfig.HookPasswordVerificationAttemptUri, "")
	result.Hook.PasswordVerificationAttempt.Secrets = cast.Val(remoteConfig.HookPasswordVerificationAttemptSecrets, "")
	result.Hook.SendEmail.Enabled = cast.Val(remoteConfig.HookSendEmailEnabled, false)
	result.Hook.SendEmail.URI = cast.Val(remoteConfig.HookSendEmailUri, "")
	result.Hook.SendEmail.Secrets = cast.Val(remoteConfig.HookSendEmailSecrets, "")
	result.Hook.SendSMS.Enabled = cast.Val(remoteConfig.HookSendSmsEnabled, false)
	result.Hook.SendSMS.URI = cast.Val(remoteConfig.HookSendSmsUri, "")
	result.Hook.SendSMS.Secrets = cast.Val(remoteConfig.HookSendSmsSecrets, "")
	// Provider config
	result.External["apple"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalAppleEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalAppleClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalAppleSecret, ""),
	}
	result.External["azure"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalAzureEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalAzureClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalAzureSecret, ""),
		Url:      cast.Val(remoteConfig.ExternalAzureUrl, ""),
	}
	result.External["bitbucket"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalBitbucketEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalBitbucketClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalBitbucketSecret, ""),
	}
	result.External["discord"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalDiscordEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalDiscordClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalDiscordSecret, ""),
	}
	result.External["facebook"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalFacebookEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalFacebookClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalFacebookSecret, ""),
	}
	result.External["github"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalGithubEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalGithubClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalGithubSecret, ""),
	}
	result.External["gitlab"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalGitlabEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalGitlabClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalGitlabSecret, ""),
		Url:      cast.Val(remoteConfig.ExternalGitlabUrl, ""),
	}
	result.External["google"] = provider{
		Enabled:        cast.Val(remoteConfig.ExternalGoogleEnabled, false),
		ClientId:       cast.Val(remoteConfig.ExternalGoogleClientId, ""),
		Secret:         cast.Val(remoteConfig.ExternalGoogleSecret, ""),
		SkipNonceCheck: cast.Val(remoteConfig.ExternalGoogleSkipNonceCheck, false),
	}
	result.External["keycloak"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalKeycloakEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalKeycloakClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalKeycloakSecret, ""),
		Url:      cast.Val(remoteConfig.ExternalKeycloakUrl, ""),
	}
	result.External["linkedin_oidc"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalLinkedinOidcEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalLinkedinOidcClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalLinkedinOidcSecret, ""),
	}
	result.External["notion"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalNotionEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalNotionClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalNotionSecret, ""),
	}
	result.External["slack_oidc"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalSlackOidcEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalSlackOidcClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalSlackOidcSecret, ""),
	}
	result.External["spotify"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalSpotifyEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalSpotifyClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalSpotifySecret, ""),
	}
	result.External["twitch"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalTwitchEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalTwitchClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalTwitchSecret, ""),
	}
	result.External["twitter"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalTwitterEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalTwitterClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalTwitterSecret, ""),
	}
	result.External["workos"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalWorkosEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalWorkosClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalWorkosSecret, ""),
		Url:      cast.Val(remoteConfig.ExternalWorkosUrl, ""),
	}
	result.External["zoom"] = provider{
		Enabled:  cast.Val(remoteConfig.ExternalZoomEnabled, false),
		ClientId: cast.Val(remoteConfig.ExternalZoomClientId, ""),
		Secret:   cast.Val(remoteConfig.ExternalZoomSecret, ""),
	}
	return result
}

func (a *auth) DiffWithRemote(projectRef string, remoteConfig v1API.AuthConfigResponse) ([]byte, error) {
	// Convert the config values into easily comparable remoteConfig values
	currentValue, err := ToTomlBytes(a.hashSecrets(projectRef))
	if err != nil {
		return nil, err
	}
	remoteCompare, err := ToTomlBytes(a.fromRemoteAuthConfig(remoteConfig))
	if err != nil {
		return nil, err
	}
	return diff.Diff("remote[auth]", remoteCompare, "local[auth]", currentValue), nil
}

func (a *auth) hashSecrets(key string) auth {
	result := *a
	if len(result.Email.Smtp.Pass) > 0 {
		result.Email.Smtp.Pass = sha256Hmac(key, result.Email.Smtp.Pass)
	}
	if len(result.Sms.Twilio.AuthToken) > 0 {
		result.Sms.Twilio.AuthToken = sha256Hmac(key, result.Sms.Twilio.AuthToken)
	}
	if len(result.Sms.TwilioVerify.AuthToken) > 0 {
		result.Sms.TwilioVerify.AuthToken = sha256Hmac(key, result.Sms.TwilioVerify.AuthToken)
	}
	if len(result.Sms.Messagebird.AccessKey) > 0 {
		result.Sms.Messagebird.AccessKey = sha256Hmac(key, result.Sms.Messagebird.AccessKey)
	}
	if len(result.Sms.Textlocal.ApiKey) > 0 {
		result.Sms.Textlocal.ApiKey = sha256Hmac(key, result.Sms.Textlocal.ApiKey)
	}
	if len(result.Sms.Vonage.ApiSecret) > 0 {
		result.Sms.Vonage.ApiSecret = sha256Hmac(key, result.Sms.Vonage.ApiSecret)
	}
	if len(result.Hook.MFAVerificationAttempt.Secrets) > 0 {
		result.Hook.MFAVerificationAttempt.Secrets = sha256Hmac(key, result.Hook.MFAVerificationAttempt.Secrets)
	}
	if len(result.Hook.PasswordVerificationAttempt.Secrets) > 0 {
		result.Hook.PasswordVerificationAttempt.Secrets = sha256Hmac(key, result.Hook.PasswordVerificationAttempt.Secrets)
	}
	if len(result.Hook.CustomAccessToken.Secrets) > 0 {
		result.Hook.CustomAccessToken.Secrets = sha256Hmac(key, result.Hook.CustomAccessToken.Secrets)
	}
	if len(result.Hook.SendSMS.Secrets) > 0 {
		result.Hook.SendSMS.Secrets = sha256Hmac(key, result.Hook.SendSMS.Secrets)
	}
	if len(result.Hook.SendEmail.Secrets) > 0 {
		result.Hook.SendEmail.Secrets = sha256Hmac(key, result.Hook.SendEmail.Secrets)
	}
	for name, provider := range result.External {
		if len(provider.Secret) > 0 {
			provider.Secret = sha256Hmac(key, result.Hook.SendEmail.Secrets)
			result.External[name] = provider
		}
	}
	// Hide deprecated fields
	delete(a.External, "slack")
	delete(a.External, "linkedin")
	// TODO: support SecurityCaptchaSecret in local config
	return result
}
