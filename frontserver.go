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
	"github.com/go-redis/cache"
	"github.com/dgrijalva/jwt-go"
	"image"
    "github.com/nfnt/resize"
	_ "image/png"
	_ "image/jpeg"
	_ "image/gif"
	"image/png"
	"github.com/vmihailenco/msgpack"
)

type Profile struct {
	Username string
	Nickname string
	Picture string
}

var templates = template.Must(template.ParseFiles("./templates/loginform.html", "./templates/profile.html", "./templates/uploadform.html", "./templates/loginsuccess.html"))
var factory = func() (net.Conn, error) {return net.Dial("tcp", "localhost:3000")}
var p pool.Pool
var codec *cache.Codec
var redisMutex sync.Mutex

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if login, username := checkLogin(r); login {
		if r.Method == "GET" {
			curtime := time.Now().Unix()
			h := md5.New()
			io.WriteString(h, strconv.FormatInt(curtime, 10))
			payload := map[string]interface{}{"Token": getCSRFToken(), "Username": username}
			renderTemplates(w, "uploadform.html", payload)
		} else {
			err := r.ParseMultipartForm(32 << 20)
			if err != nil {
				fmt.Println("Parse Multipart Form Error")
				http.Redirect(w, r, "/profile/", http.StatusFound)
				return
			}
			file, _, _ := r.FormFile("uploadfile")
			nickname := template.HTMLEscapeString(r.FormValue("nickname"))
			if len(nickname) > 20 {
				nickname = nickname[:20]
			}
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
	if !res.Status {
		fmt.Println("Update failure")
	} else {
		updateRedisCache(Profile{Username: username, Nickname: "", Picture: base64.StdEncoding.EncodeToString(newImgBytes)})
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
	} else {
		updateRedisCache(Profile{Username: username, Nickname:nickname, Picture:""})
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
	} else {
		updateRedisCache(Profile{Username: username, Nickname:nickname, Picture:base64.StdEncoding.EncodeToString(newImgBytes)})
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if login, username := checkLogin(r); login {
		data := map[string]string{"Username": username}
		renderTemplates(w, "loginsuccess.html", data)
		return
	}
	if r.Method == "GET" {
		renderTemplates(w, "loginform.html", nil)
	} else {
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
    	// check redis cache first
		if profile, err := checkRedisCache(username); err == nil {
			renderTemplates(w, "profile.html", profile)
			return
		}
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
			rawImagestr := base64.StdEncoding.EncodeToString(res.Picture)  // transfer to raw image
			profile := Profile{Username: username, Nickname: res.Nickname, Picture: rawImagestr}
			redisCacheProfile(profile)
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

func renderTemplates(w http.ResponseWriter, name string, data interface{}) {
	err := templates.ExecuteTemplate(w, name, data)
	if err != nil {
		log.Println("unable to execute template.", err)
	}
}

func loginUser(w http.ResponseWriter, username string) {
	signBytes := []byte("nBewzo9SueQ")
	// Create the Claims
	claims := &jwt.StandardClaims{
		ExpiresAt: int64(30 * time.Second),
		Issuer:    username,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(signBytes)   // signed by a string
	cookie := http.Cookie{Name: "username", Value: tokenStr, Path: "/", Expires: time.Now().Add(1 * 60 * time.Second)}
	http.SetCookie(w, &cookie)
}

func logoutUser(w http.ResponseWriter, username string) {
	cookie := http.Cookie{Name: username, Value: "", Path: "/", MaxAge: -10, Expires: time.Now()}
	http.SetCookie(w, &cookie)
}

func checkLogin(r *http.Request) (bool, string) {
	cookie, _ := r.Cookie("username")
	if cookie != nil {
		token, err := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte("nBewzo9SueQ"), nil
		})
		if err == nil {
			claims, ok := token.Claims.(*jwt.StandardClaims)
			if ok && token.Valid {
				return true, claims.Issuer
			}
		}
	}
	return false, ""
}

func redisLogin(username string, password string) {
	err := codec.Set(&cache.Item{
		Key:        username,
		Object:     password,
		Expiration: 30 * time.Second,   // a relatively short time for testing
	})
	if err != nil {
		fmt.Println("Redis caching error")
	}
}

func checkRedisLogin(username string, password string) bool {
    var pwd string
	if err := codec.Get(username, &pwd); err == nil && pwd == password {
		return true
	}
	return false
}

func redisCacheProfile(p Profile) {
	err := codec.Set(&cache.Item{
		Key: p.Username + "<profile/>",
		Object: p,
		Expiration: 30 * time.Second,   // a relatively short time for testing
	})
	if err != nil {
		fmt.Println("Redis caching error")
	}
}

func checkRedisCache(username string) (p Profile, err error) {
	if err = codec.Get(username+"<profile/>", &p); err == nil {
		return p, nil
	}
	return p, err
}

func updateRedisCache(newP Profile) {
	redisMutex.Lock()
	defer redisMutex.Unlock()
	var originP Profile
	if err := codec.Get(newP.Username+"<profile/>", &originP); err == nil {
		switch  {
		case newP.Nickname == "":
			newP.Nickname = originP.Nickname
		case newP.Picture == "":
		    newP.Picture = originP.Picture
		}
		redisCacheProfile(newP)
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
		fmt.Println("image compression: decode error")
        return nil, fmt.Errorf("Decode error")
	}
	newImg := resize.Resize(size, 0, image, resize.Bilinear) // current best compression result
	buf := new(bytes.Buffer)
	err = png.Encode(buf, newImg)
	if err != nil {
		fmt.Println("image serialization error")
		return nil, fmt.Errorf("compression error")
	}
	return buf.Bytes(), nil
}

func runFrontServer() {
	var err error
	p, err = pool.NewChannelPool(200, 1200, factory)
	if err != nil {
		fmt.Println("Create channel pool error", err)
	}
	//client = redis.NewClient(&redis.Options{
	//	Addr:     "localhost:6379",
	//	Password: "", // no password set
	//	DB:       0,  // use default DB
	//})
	ring := redis.NewRing(&redis.RingOptions{
		Addrs: map[string]string {
			"server1": "localhost:6379",
		},
	})
	codec = &cache.Codec{
		Redis: ring,
		Marshal: func(s interface{}) ([]byte, error) {
			return msgpack.Marshal(s)
		},
		Unmarshal: func(b []byte, s interface{}) error {
			return msgpack.Unmarshal(b, s)
		},
	}
	codec.UseLocalCache(20000, 40 * time.Second)
	http.HandleFunc("/login/", loginHandler)
	http.HandleFunc("/profile/", profileHandler)
	http.HandleFunc("/edit/", uploadHandler)
	http.ListenAndServe(":8080", nil)
}

func main() {
	//wg := &sync.WaitGroup{}
	//wg.Add(2)
	//go runTCPServer()
	//go runFrontServer()
	//wg.Wait()
	runFrontServer()
}
