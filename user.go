package main

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var user = User{
	Username: "username",
	Password: "password",
}
