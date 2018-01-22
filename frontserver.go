package main

import (
	"net/http"
	"fmt"
	"time"
	"html/template"
	"crypto/md5"
	"io"
	"strconv"
	"encoding/base64"
	"log"
	"github.com/golang/protobuf/proto"
	"net"
	"sync"
	"mime/multipart"
	"bytes"
	"github.com/fatih/pool"
	"github.com/go-redis/redis"
	"github.com/dgrijalva/jwt-go"
	"image"
    "github.com/nfnt/resize"
	_ "image/png"
	_ "image/jpeg"
	_ "image/gif"
	"image/png"
)

type Profile struct {
	Username string
	Nickname string
	Picture string
}

var templates = template.Must(template.ParseFiles("./templates/loginform.html", "./templates/profile.html", "./templates/uploadform.html", "./templates/loginsuccess.html"))
var factory = func() (net.Conn, error) {return net.Dial("tcp", "localhost:3000")}
var p pool.Pool
var client *redis.Client

type cache_map struct {
	mux sync.Mutex
	cache map[string]string
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if login, username := checkLogin(r); login {
		//fmt.Println("method:", r.Method)
		if r.Method == "GET" {
			curtime := time.Now().Unix()
			h := md5.New()
			io.WriteString(h, strconv.FormatInt(curtime, 10))
			payload := map[string]interface{}{"Token": getCSRFToken(), "Username": "Kevin"}
			renderTemplates(w, "uploadform.html", payload)
		} else {
			err := r.ParseMultipartForm(32 << 20)
			if err != nil {
				fmt.Println("Parse Multipart Form Error")
			}
			file, _, _ := r.FormFile("uploadfile")

			//fmt.Printf("empty file: %T %s", file)
			nickname := template.HTMLEscapeString(r.FormValue("nickname"))
			csrfToken := template.HTMLEscapeString(r.FormValue("token"))
			if !checkCSRF(csrfToken) {
				http.Redirect(w, r, "/profile/", http.StatusFound)
				return
			}
			switch {
			case nickname == "" && file == nil:
				fmt.Println("Uploading none")
				http.Redirect(w, r, "/profile/", http.StatusFound)
			case nickname == "":
				fmt.Println("Uploading picture")
				updatePicture(username, file)
			case file == nil:
				fmt.Println("Uploading nickname")
				updateNickname(username, nickname)
			default:
				fmt.Println("Uploading both")
				updateProfile(username, nickname, file)
			}
			if file != nil {
				defer file.Close()
			}
			http.Redirect(w, r, "/profile/",  http.StatusFound)
		}
	} else {
		http.Redirect(w, r, "/login/", http.StatusFound)
	}
}

func updatePicture(username string, picFile multipart.File) {
	buffer := new(bytes.Buffer)
	io.Copy(buffer, picFile)
	newImgBytes, err := compressImage(buffer.Bytes(), 64)
	if err != nil {
	    return
	}
	picReq := &UpdatePicRequest{
		Username: username,
		Picture: newImgBytes,
	}
	req := &Request{
		Command: Command_UPDATEPICTURE,
		Token: "secret_key",
		Req: &Request_Updatepicture {
			Updatepicture: picReq,
		},
	}
	res := protoBufTCPIn(req)
	fmt.Println("response", res.Status)
	if !res.Status {
		fmt.Println(res.Status)
		fmt.Println("Update failure")
	}
}

func updateNickname(username string, nickname string) {
	nickReq := &UpdateNickRequest{
		Username: username,
		Nickname: nickname,
	}
	req := &Request{
		Command: Command_UPDATENICKNAME,
		Token: "secret_key",
		Req: &Request_Updatenickname {
			Updatenickname: nickReq,
		},
	}
	res := protoBufTCPIn(req)
	if !res.Status {
		fmt.Println("Update failure")
	}
}

func updateProfile(username string, nickname string, picFile multipart.File) {
	buffer := new(bytes.Buffer)
	io.Copy(buffer, picFile)
	newImgBytes, err := compressImage(buffer.Bytes(), 64)
	if err != nil {
		return
	}
	updateReq := &UpdateBothRequest{
		Username: username,
		Nickname: nickname,
		Picture: newImgBytes,
	}
	req := &Request{
		Command: Command_UPDATEBOTH,
		Token: "secret_key",
		Req: &Request_Updateboth {
			Updateboth: updateReq,
		},
	}
	res := protoBufTCPIn(req)
	if !res.Status {
		fmt.Println("Update failure")
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	//fmt.Println("method:", r.Method)
	if login, username := checkLogin(r); login {
		data := map[string]string{"Username": username}
		renderTemplates(w, "loginsuccess.html", data)
		return
	}
	if r.Method == "GET" {
		//crutime := time.Now().Unix()
		//h := md5.New()
		//io.WriteString(h, strconv.FormatInt(crutime, 10))
		//token := fmt.Sprintf("%x", h.Sum(nil))
		//payload := map[string]interface{}{"Token": token, "Username": "Kevin"}
		renderTemplates(w, "loginform.html", nil)
	} else {
		fmt.Println("HTTP: handle login request")
		username := template.HTMLEscapeString(r.FormValue("username"))
		password := template.HTMLEscapeString(r.FormValue("password"))
		// redis experiment
		if checkRedisLogin(username, password) {
			fmt.Println("cached redis")
			loginUser(w, username)
			data := map[string]string{"Username": username}
			renderTemplates(w, "loginsuccess.html", data)
			return
		}
        loginReq := &LoginRequest{
        	Username: username,
        	Password: password,
		}
		req := &Request{
			Command: Command_LOGIN,
			Token: "secret_key",
            Req: &Request_Login{
            	loginReq,
			},
		}
		ackRes := protoBufTCPIn(req)
		if ackRes.Status {
		    loginUser(w, username)
		    redisLogin(username, password)
		    data := map[string]string{"Username": username}
		    renderTemplates(w, "loginsuccess.html", data)
		} else {
		    http.Redirect(w, r, "/login/", http.StatusFound)
		}
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    if login, username := checkLogin(r); login {
		//img, err := png.Decode(f)
		//fmt.Printf("type %T \n", img)
		getReq := &GetProfileRequest{
			Username: username,
		}
		req := &Request{
			Command: Command_GETPROFILE,
			Token: "secret_key",
			Req: &Request_Getprofile{
				Getprofile: getReq,
			},
		}
		res := protoBufTCPGetProfile(req)
		if res.Status == true {
			picBytes := res.Picture
			nickname := res.Nickname
			rawImagestr := base64.StdEncoding.EncodeToString(picBytes)  // transfer to raw image
			profile := Profile{Username: username, Nickname: nickname, Picture: rawImagestr}
			renderTemplates(w, "profile.html", profile)
		} else {
			logoutUser(w, username)
			http.Redirect(w, r, "/login/", http.StatusFound)
		}
	} else {
		http.Redirect(w, r, "/login/", http.StatusFound)
	}
}

func protoBufTCPIn (req *Request) *AckResponse {
	payload, err := proto.Marshal(req)
	if err != nil {
		fmt.Printf("Marshal Error %v %T \n", err, err)
		return nil
	}
	//conn, err := net.Dial("tcp", "localhost:3000")

	conn, err := p.Get()
    if p == nil {
    	fmt.Println("pool init error")
	}
	if conn == nil {
		fmt.Println("conn init error")
	}
	defer conn.Close()
	if err != nil {
		fmt.Printf("http-dial error \n %v\n", err)
		return nil
	}
	_, err = conn.Write(payload)
	if err != nil {
		e, ok := err.(net.Error)
		if !ok || !e.Temporary() {
			fmt.Println("HTTP sending fatal error", err)
		} else {
			fmt.Println("HTTP sending error", err)
		}
	}
	//message, err := bufio.NewReader(conn).ReadString('\n')
	buf := make([]byte, 1024)
	resLen, err := conn.Read(buf)
	if err != nil {
		e, ok := err.(net.Error)
		if !ok || !e.Temporary() {
			fmt.Println("HTTP receiving fatal error", err)
		} else {
		    fmt.Println("HTTP receiving error", err)
		}
	}
	fmt.Printf("HTTP: tcp response length %d\n", resLen)
	res := &AckResponse{}
	err = proto.Unmarshal(buf[:resLen], res)
	if err != nil {
		fmt.Printf("HTTP: tcp response unmarshal error: %v, %T\n", err, err)
		return nil
	}
	return res
}

func protoBufTCPGetProfile (req *Request) *QueryResponse {
	payload, err := proto.Marshal(req)
	if err != nil {
		fmt.Printf("Marshal Error %v %T \n", err, err)
		return nil
	}
	//conn, err := net.Dial("tcp", "localhost:3000")

	conn, err := p.Get()
	defer conn.Close()
	if err != nil {
		fmt.Printf("http-dial error \n %v\n", err)
		return nil
	}
	_, err = conn.Write(payload)
	if err != nil {
		e, ok := err.(net.Error)
		if !ok || !e.Temporary() {
			fmt.Println("HTTP sending fatal error", err)
		} else {
			fmt.Println("HTTP sending error", err)
		}
	}
	//message, err := bufio.NewReader(conn).ReadString('\n')
	buf := make([]byte, 18432)
	resLen, err := conn.Read(buf)
	if err != nil {
		e, ok := err.(net.Error)
		if !ok || !e.Temporary() {
			fmt.Println("HTTP receiving fatal error", err)
		} else {
			fmt.Println("HTTP receiving error", err)
		}
	}
	fmt.Printf("HTTP: tcp response length %d\n", resLen)
	res := &QueryResponse{}
	err = proto.Unmarshal(buf[:resLen], res)
	if err != nil {
		fmt.Printf("HTTP: tcp response unmarshal error: %v, %T\n", err, err)
		return nil
	}
	return res
}

func runFrontServer() {
	var err error
	p, err = pool.NewChannelPool(200, 1200, factory)
	if err != nil {
		fmt.Println("Create channel pool error", err)
	}
	client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	http.HandleFunc("/login/", loginHandler)
	http.HandleFunc("/profile/", profileHandler)
	http.HandleFunc("/edit/", uploadHandler)
	http.ListenAndServe(":8080", nil)
}

func renderTemplates(w http.ResponseWriter, name string, data interface{}) {
	err := templates.ExecuteTemplate(w, name, data)
	if err != nil {
		log.Println("unable to execute template.", err)
	}
}

func getCSRFToken() (ss string) {
	mySigningKey := []byte("nBewzo9SueQ")
	// Create the Claims
	claims := &jwt.StandardClaims{
		ExpiresAt: int64(30 * time.Minute),
		Issuer:    "test",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, _ = token.SignedString(mySigningKey)   // signed by a string
	return
}

func checkLogin(r *http.Request) (bool, string) {
	cookie, _ := r.Cookie("username")
	if cookie == nil {
		return false, ""
	} else {
		return true, cookie.Value
	}
}

func redisLogin(username string, password string) {
	err := client.Set(username, password, 40*time.Second).Err()
	if err != nil {
		fmt.Println("Redis caching error")
	}
}

func checkRedisLogin(username string, password string) bool {
	pwd, err := client.Get(username).Result()
	if err == nil && pwd == password {
		return true
	}
	return false
}

func loginUser(w http.ResponseWriter, username string) {
	cookie := http.Cookie{Name: "username", Value: username, Path: "/", Expires: time.Now().Add(1 * 60 * time.Second)}
	http.SetCookie(w, &cookie)
}

func logoutUser(w http.ResponseWriter, username string) {
	cookie := http.Cookie{Name: "username", Value: username, Path: "/", MaxAge: -10, Expires: time.Now()}
	http.SetCookie(w, &cookie)
}

func checkCSRF(ss string) bool {
	tokenN, err := jwt.ParseWithClaims(ss, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("nBewzo9SueQ"), nil
	})
	if err != nil {
		return false
	}
	if _, ok := tokenN.Claims.(*jwt.StandardClaims); ok && tokenN.Valid {
		return true
	} else {
		return false
	}
}

func compressImage(originImg []byte, size uint) ([]byte, error) {
	image, _, err := image.Decode(bytes.NewReader(originImg))
	if err != nil {
		//image, err = jpeg.Decode(bytes.NewReader(originImg))
		fmt.Println("image compression: decode error")
        return nil, fmt.Errorf("Decode error")
	}
	//fmt.Printf("%T,  \n %v \n", image, image)
	newImg := resize.Resize(size, 0, image, resize.Bilinear) // current best compression result
	buf := new(bytes.Buffer)
	err = png.Encode(buf, newImg)
	if err != nil {
		fmt.Println("image serialization error")
		return nil, fmt.Errorf("compression error")
	}
	return buf.Bytes(), nil
}



func main() {
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go runTCPServer()
	go runFrontServer()
	wg.Wait()
}
