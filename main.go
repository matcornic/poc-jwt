package main

import (
	"log"

	"github.com/gin-gonic/gin"

	"poc-jwt/cache"
)

func main() {

	refreshSecret := "change_me_and_use_very_long_key"    // TODO comes from Secret store or env variables
	accessSecret := "change_me_too_and_use_very_long_key" // TODO comes from Secret store or env variables

	var router = gin.Default()

	c := cache.NewInMemCache()
	authCtrl := NewDefaultAuthenticationController(c, refreshSecret, accessSecret)

	router.POST("/login", authCtrl.Login) // Login returns
	router.POST("/logout", authCtrl.Logout)
	router.POST("/logout-all-devices", authCtrl.LogoutAllDevices)
	router.POST("/refresh", authCtrl.Refresh)

	router.POST("/todo", authCtrl.AuthenticationRequired(), CreateTodo)

	log.Fatal(router.Run(":8080"))
}
