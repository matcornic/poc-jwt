package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

// Inspired from https://github.com/victorsteven/jwt-best-practices
// Login returns an access token in body and refresh token in cookie and store tokens in an in-mem database
// 	Access token should be stored in memory (JS). Refresh token is returned in a cookie, so available for provided domain
// Logout removes tokens from in-mem database
// AuthenticationRequired middleware check that token is valid and is in database
func main() {

	refreshSecret := "change_me_and_use_very_long_key"    // TODO comes from Secret store or env variables
	accessSecret := "change_me_too_and_use_very_long_key" // TODO comes from Secret store or env variables

	var router = gin.Default()

	cache := NewInMemCache()
	//authCtrl := NewDefaultAuthenticationController(cache)
	authCtrl := NewShortLivedLoginController(cache, refreshSecret, accessSecret)

	router.POST("/login", authCtrl.Login)
	router.POST("/logout", authCtrl.Logout)
	router.POST("/refresh", authCtrl.Refresh)

	router.POST("/todo", authCtrl.AuthenticationRequired(), CreateTodo)

	log.Fatal(router.Run(":8080"))
}
