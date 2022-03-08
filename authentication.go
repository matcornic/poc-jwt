package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"poc-jwt/cache"
)

const (
	issuer                        = "SorareData"
	refreshTokenName              = "sd_refresh_token"
	defaultRefreshTokenExpiration = 7 * 24 * time.Hour //  1 Week
	defaultAccessTokenExpiration  = 15 * time.Minute
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
	db            *AuthenticationDB
	refreshSecret string
	accessSecret  string
}

func NewDefaultAuthenticationController(cache cache.TTLCache, refreshSecret, accessSecret string) *LoginController {
	authDB := NewAuthenticationDBWithExpiration(cache, defaultRefreshTokenExpiration, defaultAccessTokenExpiration)
	return &LoginController{
		db:            authDB,
		refreshSecret: refreshSecret,
		accessSecret:  accessSecret,
	}
}

func NewShortLivedLoginController(cache cache.TTLCache, refreshSecret, accessSecret string) *LoginController {
	// Used for testing
	authDB := NewAuthenticationDBWithExpiration(cache, 5*time.Minute, 30*time.Second)
	return &LoginController{
		db:            authDB,
		refreshSecret: refreshSecret,
		accessSecret:  accessSecret,
	}
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
		if !ctrl.db.IsAccessValid(metadata.Username, metadata.AccessUuid) {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			c.Abort()
			return
		}
		c.Set("username", metadata.Username)
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
		return
	}
	ctrl.setRefreshTokenCookie(c, ts.Refresh.Token)
	ctrl.db.cache.PrintAll()
	c.JSON(http.StatusOK, ts.Access.Token)
}

func (ctrl *LoginController) LogoutAllDevices(c *gin.Context) {
	_, claims, err := ctrl.verifyRefreshToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err)
		return
	}
	_, delErr := ctrl.db.DeleteAllUserTokens(claims.Subject)
	if delErr != nil {
		ctrl.forceRefreshTokenCookieToExpire(c)
		c.JSON(http.StatusUnauthorized, delErr.Error())
		return
	}
	ctrl.forceRefreshTokenCookieToExpire(c)
	ctrl.db.cache.PrintAll()
	c.JSON(http.StatusOK, "Successfully logged out every devices")
	return
}

func (ctrl *LoginController) Logout(c *gin.Context) {
	_, claims, err := ctrl.verifyRefreshToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err)
		return
	}
	delErr := ctrl.deleteTokens(claims.Subject, claims.Id)
	if delErr != nil {
		ctrl.forceRefreshTokenCookieToExpire(c)
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	ctrl.forceRefreshTokenCookieToExpire(c)
	ctrl.db.cache.PrintAll()
	c.JSON(http.StatusOK, "Successfully logged out")
}

func (ctrl *LoginController) Refresh(c *gin.Context) {
	refreshToken, claims, err := ctrl.verifyRefreshToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	if !refreshToken.Valid {
		c.JSON(http.StatusUnauthorized, "refresh token expired, login required")
		return
	}
	ok := ctrl.db.IsRefreshValid(claims.Subject, claims.Id)
	if !ok {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	err = ctrl.deleteTokens(claims.Subject, claims.Id)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	tokenDetails, err := ctrl.createNewTokens(claims.Subject)
	if err != nil {
		c.JSON(http.StatusUnauthorized, err.Error())
		return
	}
	err = ctrl.saveAuth(user.Username, tokenDetails)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	ctrl.setRefreshTokenCookie(c, tokenDetails.Refresh.Token)
	ctrl.db.cache.PrintAll()
	c.JSON(http.StatusCreated, tokenDetails.Access.Token)
}

func (ctrl *LoginController) setRefreshTokenCookie(c *gin.Context, refreshToken string) {
	maxAge := int(ctrl.db.refreshTokenExpiration.Seconds())
	// c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(refreshTokenName, refreshToken, maxAge, "", "", true, true)
}

func (ctrl *LoginController) forceRefreshTokenCookieToExpire(c *gin.Context) {
	// force cookie to be expired
	c.SetCookie(refreshTokenName, "", -1, "", "", true, true)
}

func (ctrl *LoginController) createNewToken(username string, secret string, expiration time.Duration, UUID string) (TokenDetail, error) {
	now := time.Now().UTC()
	if UUID == "" {
		UUID = uuid.New().String()
	}
	td := TokenDetail{
		UUID:    UUID,
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

func (ctrl *LoginController) createNewRefreshToken(username string, uuid string) (TokenDetail, error) {
	return ctrl.createNewToken(username, ctrl.refreshSecret, ctrl.db.refreshTokenExpiration, uuid)
}

func (ctrl *LoginController) createNewAccessToken(username string) (TokenDetail, error) {
	return ctrl.createNewToken(username, ctrl.accessSecret, ctrl.db.accessTokenExpiration, "")
}

func (ctrl *LoginController) createNewTokens(username string) (TokenDetails, error) {
	accessToken, err := ctrl.createNewAccessToken(username)
	if err != nil {
		return TokenDetails{}, err
	}
	refreshToken, err := ctrl.createNewRefreshToken(username, accessToken.UUID)
	if err != nil {
		return TokenDetails{}, err
	}
	return TokenDetails{
		Access:  accessToken,
		Refresh: refreshToken,
	}, nil
}

func (ctrl *LoginController) saveAuth(username string, td TokenDetails) error {
	errAccess := ctrl.db.SaveAccessToken(username, td.Access)
	if errAccess != nil {
		return errAccess
	}
	errRefresh := ctrl.db.SaveRefreshToken(username, td.Refresh)
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

func (ctrl *LoginController) deleteTokens(username string, uuid string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if uuid == "" {
		return fmt.Errorf("token uuid is required")
	}
	_, err := ctrl.db.DeleteAccessToken(username, uuid)
	if err != nil {
		return err
	}
	_, err = ctrl.db.DeleteRefreshToken(username, uuid)
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
