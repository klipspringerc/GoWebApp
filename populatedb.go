package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"encoding/base64"
	mrand "math/rand"
)

func getUserID() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	result := base64.URLEncoding.EncodeToString(b)
	return result[:len(result)-1]
}

func populateDB(count int) {
	db, err := sql.Open("mysql", "admin:1991@/serverdb")
	if err != nil {
		fmt.Println("db connection error")
	}
	defer db.Close()
	stmtIns, err := db.Prepare("INSERT INTO useraccounts VALUES(?, ?, ?, ?)") // ? as placeholder
	if err != nil {
		panic(err.Error())
	}
	defer stmtIns.Close()
	for i := 0; i < count; i++ {
		buf := make([]byte, 10)
		for i := range buf {
			buf[i] = byte(97 + mrand.Intn(26))
		}
		nickname := string(buf)
		username := getUserID()
		// use the same info below to ease testing by script
		password := "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
		picture := "fqd7yGzczdcwxhqDcr_EkQ=="
		stmtIns.Exec(username, password, nickname, picture)
	}
}
