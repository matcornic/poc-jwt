package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/gobwas/glob"
	"github.com/google/uuid"
)

const (
	defaultRefreshTokenExpiration = 7 * 24 * time.Hour //  1 Week
	defaultAccessTokenExpiration  = 15 * time.Minute
	issuer                        = "SorareData"
	refreshTokenName              = "sd_refresh_token"
)

type AccessDetails struct {
	AccessUuid  string
	RefreshUuid string
	Username    string
}

type TokenDetails struct {
	Access  TokenDetail
	Refresh TokenDetail
}

type TokenDetail struct {
	Token   string
	UUID    string
	Expires int64
}

type LoginController struct {
	cache                  TTLCache
	refreshTokenExpiration time.Duration
	accessTokenExpiration  time.Duration
	refreshSecret          string
	accessSecret           string
}

func NewDefaultAuthenticationController(cache TTLCache, refreshSecret, accessSecret string) *LoginController {
	return &LoginController{
		cache:                  cache,
		refreshTokenExpiration: defaultRefreshTokenExpiration,
		accessTokenExpiration:  defaultAccessTokenExpiration,
		refreshSecret:          refreshSecret,
		accessSecret:           accessSecret,
	}
}

func NewShortLivedLoginController(cache TTLCache, refreshSecret, accessSecret string) *LoginController {
	// Used for testing
	ctrl := NewDefaultAuthenticationController(cache, refreshSecret, accessSecret)
	ctrl.refreshTokenExpiration = 5 * time.Minute
	ctrl.accessTokenExpiration = 30 * time.Second
	return ctrl
}

func (ctrl *LoginController) AuthenticationRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		//Extract the access token metadata
		metadata, err := ctrl.extractAccessTokenMetadata(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			c.Abort()
			return
		}
		if metadata == nil {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			c.Abort()
			return
		}
		username, err := ctrl.fetchAuth(metadata)
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
		c.Set("username", username)
		c.Next()
	}
}

func (ctrl *LoginController) Login(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}
	//compare the user from the request, with the one we defined:
	if user.Username != u.Username || user.Password != u.Password {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}
	ts, err := ctrl.createNewTokens(user.Username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	saveErr := ctrl.saveAuth(user.Username, ts)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}
	ctrl.setRefreshTokenCookie(c, ts.Refresh.Token)
	c.JSON(http.StatusOK, ts.Access.Token)
}

func (ctrl *LoginController) Logout(c *gin.Context) {
	_, claims, err := ctrl.verifyRefreshToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err)
		return
	}
	delErr := ctrl.deleteTokens(claims.Id)
	if delErr != nil {
		c.JSON(http.StatusUnauthorized, delErr.Error())
		return
	}
	ctrl.forceRefreshTokenCookieToExpire(c)
	c.JSON(http.StatusOK, "Successfully logged out")
}

func (ctrl *LoginController) Refresh(c *gin.Context) {
	// Extract refresh token from client
	// Then check if it's still valid
	refreshToken, claims, err := ctrl.verifyRefreshToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	if !refreshToken.Valid {
		c.JSON(http.StatusUnauthorized, "refresh token expired, login required")
		return
	}
	userid, err := ctrl.cache.Get(ctrl.refreshKeyInCache(claims.Id))
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	username, _ := userid.(string)
	if claims.Subject != username {
		c.JSON(http.StatusUnauthorized, "invalid token")
		return
	}

	accessDetail, err := ctrl.createNewAccessToken(username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	tokenDetails := TokenDetails{
		Access: accessDetail,
		Refresh: TokenDetail{
			UUID:    claims.Id,
			Expires: claims.ExpiresAt,
		},
	}
	saveErr := ctrl.saveAccess(username, tokenDetails)
	if saveErr != nil {
		c.JSON(http.StatusForbidden, saveErr.Error())
		return
	}
	c.JSON(http.StatusCreated, accessDetail.Token)
}

func (ctrl *LoginController) setRefreshTokenCookie(c *gin.Context, refreshToken string) {
	maxAge := int(ctrl.refreshTokenExpiration.Seconds())
	// c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(refreshTokenName, refreshToken, maxAge, "", "", true, true)
}

func (ctrl *LoginController) forceRefreshTokenCookieToExpire(c *gin.Context) {
	// force cookie to be expired
	c.SetCookie(refreshTokenName, "", -1, "", "", true, true)
}

func (ctrl *LoginController) createNewToken(username string, secret string, expiration time.Duration) (TokenDetail, error) {
	now := time.Now().UTC()
	td := TokenDetail{
		UUID:    uuid.New().String(),
		Expires: now.Add(expiration).Unix(),
	}
	var err error
	claims := jwt.StandardClaims{
		ExpiresAt: td.Expires,
		Id:        td.UUID,
		IssuedAt:  now.Unix(),
		Issuer:    issuer,
		Subject:   username,
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	td.Token, err = at.SignedString([]byte(secret))
	return td, err
}

func (ctrl *LoginController) createNewRefreshToken(username string) (TokenDetail, error) {
	return ctrl.createNewToken(username, ctrl.refreshSecret, ctrl.refreshTokenExpiration)
}

func (ctrl *LoginController) createNewAccessToken(username string) (TokenDetail, error) {
	return ctrl.createNewToken(username, ctrl.accessSecret, ctrl.accessTokenExpiration)
}

func (ctrl *LoginController) createNewTokens(username string) (TokenDetails, error) {
	accessToken, err := ctrl.createNewAccessToken(username)
	if err != nil {
		return TokenDetails{}, err
	}
	refreshToken, err := ctrl.createNewRefreshToken(username)
	if err != nil {
		return TokenDetails{}, err
	}
	return TokenDetails{
		Access:  accessToken,
		Refresh: refreshToken,
	}, nil
}

func (ctrl *LoginController) saveAccess(username string, td TokenDetails) error {
	now := time.Now()
	if td.Access.Expires == 0 || td.Refresh.UUID == "" || td.Access.UUID == "" {
		return fmt.Errorf("token details require non empty access expiration, refresh and access uuids")
	}
	at := time.Unix(td.Access.Expires, 0)
	return ctrl.cache.SetWithTTL(ctrl.accessKeyInCache(td.Refresh.UUID, td.Access.UUID), username, at.Sub(now))
}

func (ctrl *LoginController) saveRefresh(username string, td TokenDetails) error {
	now := time.Now()
	if td.Refresh.Expires == 0 || td.Refresh.UUID == "" {
		return fmt.Errorf("token details require non empty access expiration and refresh uuid")
	}
	rt := time.Unix(td.Refresh.Expires, 0)
	return ctrl.cache.SetWithTTL(ctrl.refreshKeyInCache(td.Refresh.UUID), username, rt.Sub(now))
}

func (ctrl *LoginController) saveAuth(username string, td TokenDetails) error {
	errAccess := ctrl.saveAccess(username, td)
	if errAccess != nil {
		return errAccess
	}
	errRefresh := ctrl.saveRefresh(username, td)
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func (ctrl *LoginController) extractAccessToken(c *gin.Context) (*jwt.Token, *jwt.StandardClaims, error) {
	tokenString := ctrl.extractToken(c.Request)
	claims := jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(ctrl.accessSecret), nil
	})
	return token, &claims, err
}

func (ctrl *LoginController) verifyRefreshToken(c *gin.Context) (*jwt.Token, *jwt.StandardClaims, error) {
	tokenCookie, err := c.Cookie(refreshTokenName)
	if err != nil {
		return nil, nil, err
	}
	if tokenCookie == "" {
		return nil, nil, fmt.Errorf("empty refresh token")
	}
	claims := jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenCookie, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(ctrl.refreshSecret), nil
	})
	return token, &claims, err
}

func (ctrl *LoginController) extractAccessTokenMetadata(c *gin.Context) (*AccessDetails, error) {
	accessToken, accessClaims, err := ctrl.extractAccessToken(c)
	if err != nil {
		return nil, err
	}
	refreshToken, refreshClaims, err := ctrl.verifyRefreshToken(c)
	if err != nil {
		return nil, err
	}
	if err = accessClaims.Valid(); err != nil {
		return nil, err
	}
	if err = refreshClaims.Valid(); err != nil {
		return nil, err
	}
	if !accessToken.Valid {
		return nil, fmt.Errorf("access token is invalid")
	}
	if !refreshToken.Valid {
		return nil, fmt.Errorf("refresh token is invalid")
	}
	return &AccessDetails{
		AccessUuid:  accessClaims.Id,
		RefreshUuid: refreshClaims.Id,
		Username:    accessClaims.Subject,
	}, nil
}

func (ctrl *LoginController) fetchAuth(authD *AccessDetails) (string, error) {
	userid, err := ctrl.cache.Get(ctrl.accessKeyInCache(authD.RefreshUuid, authD.AccessUuid))
	if err != nil {
		log.Println(err)
		return "", errors.New("unauthorized")
	}
	userName, _ := userid.(string)
	if authD.Username != userName {
		return "", errors.New("unauthorized")
	}
	return userName, nil
}

func (ctrl *LoginController) deleteTokens(refreshUuid string) error {
	if refreshUuid == "" {
		return fmt.Errorf("refresh uuid required")
	}
	_, err := ctrl.cache.DelWithPattern(ctrl.accessKeysOfRefreshPattern(refreshUuid))
	if err != nil {
		return err
	}
	_, err = ctrl.cache.Del(ctrl.refreshKeyInCache(refreshUuid))
	if err != nil {
		return err
	}
	return nil
}

func (ctrl *LoginController) extractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func (ctrl *LoginController) accessKeysOfRefreshPattern(refreshToken string) glob.Glob {
	return glob.MustCompile("authorization:access:" + refreshToken + ":*")
}

func (ctrl *LoginController) accessKeyInCache(refreshToken, accessToken string) string {
	return "authorization:access:" + refreshToken + ":" + accessToken
}

func (ctrl *LoginController) refreshKeyInCache(refreshToken string) string {
	return "authorization:refresh:" + refreshToken
}
