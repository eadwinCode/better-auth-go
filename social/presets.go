package social

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// SupportedProviders is the Better Auth v1.6 built-in provider catalog.
var SupportedProviders = []string{
	"apple", "atlassian", "cognito", "discord", "dropbox", "facebook", "figma",
	"github", "gitlab", "google", "huggingface", "kakao", "kick", "line",
	"linear", "linkedin", "microsoft", "naver", "notion", "paybin", "paypal",
	"polar", "railway", "reddit", "roblox", "salesforce", "slack", "spotify",
	"tiktok", "twitch", "twitter", "vercel", "vk", "wechat", "zoom",
}

func providerPreset(id string, options Options) (preset, error) {
	value := preset{id: id, tokenAuth: TokenAuthBody, pkce: true, mapper: providerMapper(id)}
	switch id {
	case "apple":
		value.authorizationURL = "https://appleid.apple.com/auth/authorize"
		value.tokenURL = "https://appleid.apple.com/auth/token"
		value.jwksURL = "https://appleid.apple.com/auth/keys"
		value.issuers = []string{"https://appleid.apple.com"}
		value.defaultScopes = []string{"email", "name"}
		value.oidc = true
		value.authorizationExtra = map[string]string{"response_mode": "form_post"}
	case "atlassian":
		value.authorizationURL = "https://auth.atlassian.com/authorize"
		value.tokenURL = "https://auth.atlassian.com/oauth/token"
		value.userInfoURL = "https://api.atlassian.com/me"
		value.defaultScopes = []string{"read:jira-user", "offline_access"}
		value.authorizationExtra = map[string]string{"audience": "api.atlassian.com"}
	case "cognito":
		issuer := strings.TrimSuffix(options.Issuer, "/")
		if issuer == "" {
			return preset{}, errors.New("social: cognito issuer/domain is required")
		}
		value.authorizationURL = issuer + "/oauth2/authorize"
		value.tokenURL = issuer + "/oauth2/token"
		value.userInfoURL = issuer + "/oauth2/userinfo"
		value.jwksURL = issuer + "/.well-known/jwks.json"
		value.issuers = []string{issuer}
		value.defaultScopes = []string{"openid", "profile", "email"}
		value.oidc = true
	case "discord":
		value.authorizationURL = "https://discord.com/api/oauth2/authorize"
		value.tokenURL = "https://discord.com/api/oauth2/token"
		value.userInfoURL = "https://discord.com/api/users/@me"
		value.defaultScopes = []string{"identify", "email"}
		value.pkce = false
	case "dropbox":
		value.authorizationURL = "https://www.dropbox.com/oauth2/authorize"
		value.tokenURL = "https://api.dropboxapi.com/oauth2/token"
		value.userInfoURL = "https://api.dropboxapi.com/2/users/get_current_account"
		value.userInfoMethod = http.MethodPost
		value.defaultScopes = []string{"account_info.read"}
	case "facebook":
		value.authorizationURL = "https://www.facebook.com/v24.0/dialog/oauth"
		value.tokenURL = "https://graph.facebook.com/v24.0/oauth/access_token"
		value.userInfoURL = "https://graph.facebook.com/me?fields=id,name,email,picture"
		value.defaultScopes = []string{"email", "public_profile"}
		value.pkce = false
	case "figma":
		value.authorizationURL = "https://www.figma.com/oauth"
		value.tokenURL = "https://api.figma.com/v1/oauth/token"
		value.userInfoURL = "https://api.figma.com/v1/me"
		value.defaultScopes = []string{"current_user:read"}
	case "github":
		value.authorizationURL = "https://github.com/login/oauth/authorize"
		value.tokenURL = "https://github.com/login/oauth/access_token"
		value.userInfoURL = "https://api.github.com/user"
		value.defaultScopes = []string{"read:user", "user:email"}
	case "gitlab":
		base := strings.TrimSuffix(options.BaseURL, "/")
		if base == "" {
			base = "https://gitlab.com"
		}
		value.authorizationURL = base + "/oauth/authorize"
		value.tokenURL = base + "/oauth/token"
		value.userInfoURL = base + "/oauth/userinfo"
		value.defaultScopes = []string{"read_user"}
	case "google":
		value.authorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
		value.tokenURL = "https://oauth2.googleapis.com/token"
		value.userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
		value.jwksURL = "https://www.googleapis.com/oauth2/v3/certs"
		value.issuers = []string{"https://accounts.google.com", "accounts.google.com"}
		value.defaultScopes = []string{"email", "profile", "openid"}
		value.oidc = true
		value.authorizationExtra = map[string]string{"include_granted_scopes": "true"}
	case "huggingface":
		value.authorizationURL = "https://huggingface.co/oauth/authorize"
		value.tokenURL = "https://huggingface.co/oauth/token"
		value.userInfoURL = "https://huggingface.co/oauth/userinfo"
		value.defaultScopes = []string{"openid", "profile", "email"}
	case "kakao":
		value.authorizationURL = "https://kauth.kakao.com/oauth/authorize"
		value.tokenURL = "https://kauth.kakao.com/oauth/token"
		value.userInfoURL = "https://kapi.kakao.com/v2/user/me"
		value.defaultScopes = []string{"account_email", "profile_image", "profile_nickname"}
		value.pkce = false
	case "kick":
		value.authorizationURL = "https://id.kick.com/oauth/authorize"
		value.tokenURL = "https://id.kick.com/oauth/token"
		value.userInfoURL = "https://api.kick.com/public/v1/users"
		value.defaultScopes = []string{"user:read"}
	case "line":
		value.authorizationURL = "https://access.line.me/oauth2/v2.1/authorize"
		value.tokenURL = "https://api.line.me/oauth2/v2.1/token"
		value.userInfoURL = "https://api.line.me/oauth2/v2.1/userinfo"
		value.defaultScopes = []string{"openid", "profile", "email"}
	case "linear":
		value.authorizationURL = "https://linear.app/oauth/authorize"
		value.tokenURL = "https://api.linear.app/oauth/token"
		value.userInfoURL = "https://api.linear.app/graphql"
		value.userInfoMethod = http.MethodPost
		value.userInfoBody = `{"query":"query { viewer { id name email avatarUrl active createdAt updatedAt } }"}`
		value.userInfoHeaders = map[string]string{"Content-Type": "application/json"}
		value.defaultScopes = []string{"read"}
		value.pkce = false
	case "linkedin":
		value.authorizationURL = "https://www.linkedin.com/oauth/v2/authorization"
		value.tokenURL = "https://www.linkedin.com/oauth/v2/accessToken"
		value.userInfoURL = "https://api.linkedin.com/v2/userinfo"
		value.defaultScopes = []string{"profile", "email", "openid"}
		value.pkce = false
	case "microsoft":
		tenant := strings.TrimSpace(options.Tenant)
		if tenant == "" {
			tenant = "common"
		}
		authority := strings.TrimSuffix(options.Issuer, "/")
		if authority == "" {
			authority = "https://login.microsoftonline.com"
		}
		value.authorizationURL = authority + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/authorize"
		value.tokenURL = authority + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
		value.userInfoURL = "https://graph.microsoft.com/oidc/userinfo"
		value.jwksURL = authority + "/" + url.PathEscape(tenant) + "/discovery/v2.0/keys"
		value.issuers = []string{authority + "/" + tenant + "/v2.0"}
		value.defaultScopes = []string{"openid", "profile", "email", "User.Read", "offline_access"}
		value.oidc = tenant != "common" && tenant != "organizations" && tenant != "consumers"
	case "naver":
		value.authorizationURL = "https://nid.naver.com/oauth2.0/authorize"
		value.tokenURL = "https://nid.naver.com/oauth2.0/token"
		value.userInfoURL = "https://openapi.naver.com/v1/nid/me"
		value.defaultScopes = []string{"profile", "email"}
		value.pkce = false
	case "notion":
		value.authorizationURL = "https://api.notion.com/v1/oauth/authorize"
		value.tokenURL = "https://api.notion.com/v1/oauth/token"
		value.userInfoURL = "https://api.notion.com/v1/users/me"
		value.tokenAuth = TokenAuthBasic
		value.pkce = false
		value.authorizationExtra = map[string]string{"owner": "user"}
		value.userInfoHeaders = map[string]string{"Notion-Version": "2022-06-28"}
	case "paybin":
		issuer := strings.TrimSuffix(options.Issuer, "/")
		if issuer == "" {
			issuer = "https://idp.paybin.io"
		}
		value.authorizationURL = issuer + "/oauth2/authorize"
		value.tokenURL = issuer + "/oauth2/token"
		value.userInfoURL = issuer + "/oauth2/userinfo"
		value.jwksURL = issuer + "/.well-known/jwks.json"
		value.issuers = []string{issuer}
		value.defaultScopes = []string{"openid", "email", "profile"}
		value.oidc = true
	case "paypal":
		base := "https://www.paypal.com"
		api := "https://api-m.paypal.com"
		if strings.Contains(strings.ToLower(options.BaseURL), "sandbox") {
			base = "https://www.sandbox.paypal.com"
			api = "https://api-m.sandbox.paypal.com"
		}
		value.authorizationURL = base + "/signin/authorize"
		value.tokenURL = api + "/v1/oauth2/token"
		value.userInfoURL = api + "/v1/identity/oauth2/userinfo?schema=paypalv1.1"
		value.tokenAuth = TokenAuthBasic
		value.pkce = false
	case "polar":
		value.authorizationURL = "https://polar.sh/oauth2/authorize"
		value.tokenURL = "https://api.polar.sh/v1/oauth2/token"
		value.userInfoURL = "https://api.polar.sh/v1/oauth2/userinfo"
		value.defaultScopes = []string{"openid", "profile", "email"}
	case "railway":
		value.authorizationURL = "https://backboard.railway.com/oauth/auth"
		value.tokenURL = "https://backboard.railway.com/oauth/token"
		value.userInfoURL = "https://backboard.railway.com/oauth/me"
		value.defaultScopes = []string{"openid", "email", "profile"}
	case "reddit":
		value.authorizationURL = "https://www.reddit.com/api/v1/authorize"
		value.tokenURL = "https://www.reddit.com/api/v1/access_token"
		value.userInfoURL = "https://oauth.reddit.com/api/v1/me"
		value.defaultScopes = []string{"identity"}
		value.tokenAuth = TokenAuthBasic
		value.pkce = false
		value.authorizationExtra = map[string]string{"duration": "permanent"}
	case "roblox":
		value.authorizationURL = "https://apis.roblox.com/oauth/v1/authorize"
		value.tokenURL = "https://apis.roblox.com/oauth/v1/token"
		value.userInfoURL = "https://apis.roblox.com/oauth/v1/userinfo"
		value.defaultScopes = []string{"openid", "profile"}
	case "salesforce":
		base := strings.TrimSuffix(options.BaseURL, "/")
		if base == "" {
			base = "https://login.salesforce.com"
		}
		value.authorizationURL = base + "/services/oauth2/authorize"
		value.tokenURL = base + "/services/oauth2/token"
		value.userInfoURL = base + "/services/oauth2/userinfo"
		value.defaultScopes = []string{"openid", "email", "profile"}
	case "slack":
		value.authorizationURL = "https://slack.com/openid/connect/authorize"
		value.tokenURL = "https://slack.com/api/openid.connect.token"
		value.userInfoURL = "https://slack.com/api/openid.connect.userInfo"
		value.defaultScopes = []string{"openid", "profile", "email"}
		value.pkce = false
	case "spotify":
		value.authorizationURL = "https://accounts.spotify.com/authorize"
		value.tokenURL = "https://accounts.spotify.com/api/token"
		value.userInfoURL = "https://api.spotify.com/v1/me"
		value.defaultScopes = []string{"user-read-email"}
		value.tokenAuth = TokenAuthBasic
	case "tiktok":
		value.authorizationURL = "https://www.tiktok.com/v2/auth/authorize"
		value.tokenURL = "https://open.tiktokapis.com/v2/oauth/token/"
		value.userInfoURL = "https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name"
		value.defaultScopes = []string{"user.info.profile"}
		value.clientIDParam = "client_key"
		value.scopeSeparator = ","
		value.pkce = false
	case "twitch":
		value.authorizationURL = "https://id.twitch.tv/oauth2/authorize"
		value.tokenURL = "https://id.twitch.tv/oauth2/token"
		value.userInfoURL = "https://id.twitch.tv/oauth2/userinfo"
		value.defaultScopes = []string{"user:read:email", "openid"}
		value.pkce = false
	case "twitter":
		value.authorizationURL = "https://x.com/i/oauth2/authorize"
		value.tokenURL = "https://api.x.com/2/oauth2/token"
		value.userInfoURL = "https://api.x.com/2/users/me?user.fields=profile_image_url,confirmed_email"
		value.defaultScopes = []string{"users.read", "tweet.read", "offline.access", "users.email"}
		value.tokenAuth = TokenAuthBasic
	case "vercel":
		value.authorizationURL = "https://vercel.com/oauth/authorize"
		value.tokenURL = "https://api.vercel.com/login/oauth/token"
		value.userInfoURL = "https://api.vercel.com/login/oauth/userinfo"
	case "vk":
		value.authorizationURL = "https://id.vk.com/authorize"
		value.tokenURL = "https://id.vk.com/oauth2/auth"
		value.userInfoURL = "https://id.vk.com/oauth2/user_info"
		value.userInfoMethod = http.MethodPost
		value.defaultScopes = []string{"email", "phone"}
	case "wechat":
		value.authorizationURL = "https://open.weixin.qq.com/connect/qrconnect"
		value.tokenURL = "https://api.weixin.qq.com/sns/oauth2/access_token"
		value.userInfoURL = "https://api.weixin.qq.com/sns/userinfo"
		value.defaultScopes = []string{"snsapi_login"}
		value.userInfoAuthQuery = true
		value.userInfoNeedsOpenID = true
		value.tokenMethod = http.MethodGet
		value.tokenSecretParam = "secret"
		value.clientIDParam = "appid"
		value.scopeSeparator = ","
		value.tokenAuth = TokenAuthNone
		value.authorizationExtra = map[string]string{"lang": "cn"}
		value.authorizationFragment = "wechat_redirect"
		value.pkce = false
	case "zoom":
		value.authorizationURL = "https://zoom.us/oauth/authorize"
		value.tokenURL = "https://zoom.us/oauth/token"
		value.userInfoURL = "https://api.zoom.us/v2/users/me"
		value.tokenAuth = TokenAuthBasic
		value.pkce = false
	default:
		if options.AuthorizationURL == "" || options.TokenURL == "" ||
			(options.UserInfoURL == "" && !options.oidcDiscovery) {
			return preset{}, fmt.Errorf("social: unknown provider %q requires explicit authorization, token, and user-info URLs", id)
		}
		value.authorizationURL = options.AuthorizationURL
		value.tokenURL = options.TokenURL
		value.userInfoURL = options.UserInfoURL
		value.defaultScopes = nil
		if options.oidcDiscovery {
			value.jwksURL = options.JWKSURL
			value.issuers = []string{options.Issuer}
			value.oidc = true
		}
	}
	if options.TokenAuth != "" {
		value.tokenAuth = options.TokenAuth
	}
	return value, nil
}
