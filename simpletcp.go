package main

import (
	"fmt"
	"net"
	"os"
	"path"
	//"sync"
	//"github.com/golang/protobuf/proto"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang/protobuf/proto"
	"bytes"
	"time"
	"crypto/sha256"
	"io/ioutil"
)

const (
	CONN_HOST = "localhost"
	CONN_PORT = "3000"
	CONN_TYPE = "tcp"
	IMG_DIR = "./static/image/"
)

func runTCPServer() {
	//defer wg.Done()
	// Listen for incoming connections.
	l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	db, err := sql.Open("mysql", "admin:1991@/serverdb")
	if err != nil {
		fmt.Println("SQL Connection Error", err)
	} else {
		defer db.Close()
	}
	db.SetMaxOpenConns(130)
	db.SetMaxIdleConns(50)
	go cleanDBStatic(db)
	fmt.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go handleRequest(db, conn)
	}
}

func handleRequest(db *sql.DB, conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Time{})
	// Make a buffer to hold incoming data.
	// 18kb
	buf := make([]byte, 18432)
	for {
		reqLen, err := conn.Read(buf)
		if err != nil {
			e, ok := err.(net.Error)
			if !ok || !e.Temporary() {
				fmt.Println("TCP: Network error", err)
				return
			}
			time.Sleep(1*time.Microsecond)
		} else {
			req := &Request{}
			err := proto.Unmarshal(buf[:reqLen], req)
			if err != nil {
				fmt.Println("TCP unmarshal error", err)
			}
			if req == nil {
				fmt.Println("nil request detected, reqLen", reqLen)
				continue
			}
			switch req.Command {
			case Command_LOGIN:
				fmt.Println("TCP Processing Login")
				handleLoginRequest(db, req, conn)
			case Command_GETPROFILE:
				fmt.Println("TCP Processing Profile")
				handleProfileRequest(db, req, conn)
			default:
				fmt.Println("TCP Processing Update Profile")
				handleProfileUpdate(db, req, conn)
			}
		}
	}
}

func handleLoginRequest(db *sql.DB, req *Request, conn net.Conn) {
	success := false
	loginReq := req.GetLogin()
	if loginReq != nil {
		result, err := dbLoginLookUp(db, loginReq.Username, loginReq.Password)
		if err == nil && result {
			ackRes := &AckResponse{
				Status: true,
				Token:  "secret_key",
			}
			success = protoBufHTTP(ackRes, conn)
		}
	}
	if !success {
		ackRes :=  &AckResponse{
			Status: false,
			Token: "secret_key",
		}
		protoBufHTTP(ackRes, conn)
	}
}

func handleProfileRequest(db *sql.DB, req *Request, conn net.Conn) {
	success := false
	username := req.GetGetprofile().Username
	if nickname, pictureName, err := dbRetrieveProfile(db, username); err == nil {
		if file, err := os.Open(path.Join(IMG_DIR, pictureName)); err == nil {
			buffer := new(bytes.Buffer)
			io.Copy(buffer, file)
			res := &QueryResponse{
				Status: true,
				Token: "secret_key",
				Username: username,
				Nickname: nickname,
				Picture: buffer.Bytes(),
			}
			success = protoBufHTTP(res, conn)
		} else {
			fmt.Println("TCP picture read error", err)
		}
	} else {
		fmt.Println("TCP handle profile error", err)
	}
    if !success {
		res := &QueryResponse{
			Status: false,
			Token: "secret_key",
			Username: "",
			Nickname: "",
			Picture: nil,
		}
		protoBufHTTP(res, conn)
	}
}

func getUpdateInfo(req *Request) (string, string, string) {
	nickname := ""
	pictureID := ""
	username := ""
	switch req.Command {
	case Command_UPDATENICKNAME:
		updateReq := req.GetUpdatenickname()
		username = updateReq.Username
		nickname = updateReq.Nickname
	case Command_UPDATEBOTH:
		updateReq := req.GetUpdateboth()
		username = updateReq.Username
		fileBytes := updateReq.Picture
		pictureID = savePicture(fileBytes)
		nickname = updateReq.Nickname
	case Command_UPDATEPICTURE:
		updateReq := req.GetUpdatepicture()
		username = updateReq.Username
		fileBytes := updateReq.Picture
		pictureID = savePicture(fileBytes)
	}
	return username, nickname, pictureID
}

func savePicture(fileBytes []byte) string {
	pictureID := getId()
	f, err := os.OpenFile(path.Join(IMG_DIR, pictureID), os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)
		return ""
	} else {
		defer f.Close()
		f.Write(fileBytes)
		return pictureID
	}
}

func handleProfileUpdate(db *sql.DB, req *Request, conn net.Conn) {
	username, nickname, pictureID := getUpdateInfo(req)
	fmt.Println("picture id", pictureID)
	success := dbUpdateProfile(db, username, nickname, pictureID)
	ackRes := &AckResponse{
		Status: success,
		Token: "secret_key",
	}
	protoBufHTTP(ackRes, conn)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func CheckPasswordHashSHA(password, hash string) bool {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(password))) == hash
}

func dbLoginLookUp(db *sql.DB, username string, attemptpwd string) (bool, error){
	var password string
	err := db.QueryRow("SELECT password FROM useraccounts WHERE username = ?", username).Scan(&password)
	if err != nil {
		fmt.Println("Login Query Error", err)
		return false, fmt.Errorf("SQL Error")
	}
	if CheckPasswordHashSHA(attemptpwd, password) {
		fmt.Println("login success")
        return true, nil
	} else {
		fmt.Println("login failed")
		return false, nil
	}
}

func dbRetrieveProfile(db *sql.DB, username string) (string, string, error) {
	stmtOut, err := db.Prepare("SELECT nickname, picture FROM useraccounts WHERE username = ?")
	if err != nil {
		fmt.Println("SQL Statement Error", err)
		return "", "", fmt.Errorf("SQL Error")
	}
	defer stmtOut.Close()
	var nickname, picture string
	err = stmtOut.QueryRow(username).Scan(&nickname, &picture)
	if err != nil {
		fmt.Println("Profile Query Error", err)
		return "", "", fmt.Errorf("SQL Error")
	}
	return nickname, picture, nil
}

func dbUpdateProfile(db *sql.DB, username string, nickname string, picture string) bool {
	var err error
	var stmtIns *sql.Stmt
	switch {
	case nickname == "":
		stmtIns, err = db.Prepare("UPDATE useraccounts SET picture = ? WHERE username = ?")
		defer stmtIns.Close()
		if err == nil {
		    _, err = stmtIns.Exec(picture, username)
		} else {
			fmt.Println("DB query error", err)
		}
	case picture == "":
		stmtIns, err = db.Prepare("UPDATE useraccounts SET nickname = ? WHERE username = ?")
		defer stmtIns.Close()
		if err == nil {
			_, err = stmtIns.Exec(nickname, username)
		} else {
			fmt.Println("DB query error", err)
		}
	default:
		stmtIns, err = db.Prepare("UPDATE useraccounts SET nickname = ?, picture = ? WHERE username = ?")
		defer stmtIns.Close()
		if err == nil {
			_, err = stmtIns.Exec(nickname, picture, username)
		} else {
			fmt.Println("DB query error", err)
		}
	}
	if err != nil {
		fmt.Println("Update Error", err)
		return false
	}
	return true
}

func getId() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func protoBufHTTP (res interface{}, conn net.Conn) bool {
    var payload []byte
    var err error
	switch res.(type) {
	case *AckResponse:
		payload, err = proto.Marshal(res.(*AckResponse))
	case *QueryResponse:
		payload, err = proto.Marshal(res.(*QueryResponse))
	default:
		fmt.Println("TCP sending error: unrecognised type")
		return false
	}
	if err != nil {
		fmt.Printf("TCP Marshal Error %v %T \n", err, err)
		return false
	}
	//defer conn.Close()
	_, err = conn.Write(payload)
	//message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("TCP sending error: %v, %T\n", err, err)
		return false
	}
	//fmt.Println("TCP resLen:", resLen)
	return true
}

func cleanDBStatic (db *sql.DB) {
	rows, err := db.Query("SELECT DISTINCT picture FROM useraccounts")
	if err != nil {
		fmt.Println("SQL query error", err)
	}
	picSet := make(map[string]bool)
	var picName string
	for rows.Next() {
	    rows.Scan(&picName)
	    picSet[picName] = true
	}
	picFiles, err := ioutil.ReadDir(IMG_DIR)
	if err != nil {
		fmt.Println("file io error", err)
	}
	for _, f := range picFiles {
		if _, ok := picSet[f.Name()]; !ok {
			err := os.Remove(path.Join(IMG_DIR, f.Name()))
			if err != nil {
				fmt.Println("file io error", err)
			}
		}
	}
    fmt.Println("Static files cleaned")
}

func testDBLogin() {
	db, _ := sql.Open("mysql", "admin:1991@/serverdb")
	fmt.Println(dbLoginLookUp(db, "kevin", "1234"))
	fmt.Println(dbLoginLookUp(db, "kevin", "1111"))
	fmt.Println(dbLoginLookUp(db, "kevin", "7659"))
}

func main() {
	runTCPServer()
}


