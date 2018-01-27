package main

import (
	_ "github.com/go-sql-driver/mysql"
	"fmt"
	"database/sql"
	"net/http"
	"net/url"
	"time"
	"net"
)

func main() {
	// for faster request
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 1000
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 500
    users := getUserList(200)
    tsChannel := make(chan time.Time, 1000)
	fmt.Println("start:", time.Now())
	if users != nil {
		for _, user := range users {
			go makeRequest(user, tsChannel)
		}
	}
	var t time.Time
	for i := 0; i < 200 ;i++ {
    	t = <- tsChannel
	}
	fmt.Println("end:", t)
}

func makeRequest(username string, tsChan chan time.Time) {
	for i:=0; i<5; i++ {
	    res, err := http.PostForm("http://127.0.0.1:8080/login/", url.Values{"username": {username}, "password":{"1234"}})
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				fmt.Println("HTTP request fatal error", err)
				return
			} else {
				i := 0
				for ; i <= 10; i++ {
					time.Sleep(5 * time.Microsecond)
					res, err = http.PostForm("http://127.0.0.1:8080/login/", url.Values{"username": {username}, "password":{"1234"}})
					if err == nil {
						break
					}
				}
				if i == 10 {
					fmt.Println("retry failure", err)
				}
			}
		}
		if res.Status != "200 OK" {
			fmt.Println("server error,", err)
		}
		//time.Sleep(3*time.Microsecond)
	}
	tsChan <- time.Now()
}

func getUserList(n int) []string {
	db, err := sql.Open("mysql", "admin:1991@/serverdb")
	if err != nil {
		fmt.Println("sql server connecton error")
		return nil
	}
	defer db.Close()
	rows, err:= db.Query("SELECT username FROM useraccounts LIMIT 100,?", n)
	if err != nil {
		fmt.Println("sql query error")
		return nil
	}
	users := make([]string, n)
	i := 0
	for rows.Next() {
		rows.Scan(&users[i])
		i++
		if i == n {
			break
		}
	}
	return users
}
