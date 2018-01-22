package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"html/template"
	"regexp"
	"errors"
	"sync"
	//"github.com/golang/protobuf/proto"
	//"net"
	//"io"
	//"encoding/json"
	//"strings"
	//"time"
	//"github.com/dgrijalva/jwt-go"
	"time"
	"os"
	image "image"

	//"image/png"
	"log"
	"bytes"
	//"image/jpeg"
	"encoding/base64"
	"io"
)

type Page struct {
	Title string
	Body []byte
}

/*
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user UserCredentials

	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Error in request")
		return
	}

	if strings.ToLower(user.Username) != "someone" {
		if user.Password != "p@ssword" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Println("Error logging in")
			fmt.Fprint(w, "Invalid credentials")
			return
		}
	}

	token := jwt.New(jwt.SigningMethodRS256)
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * time.Duration(1)).Unix()
	claims["iat"] = time.Now().Unix()
	token.Claims = claims

	tokenString, err := token.SignedString(signKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error while signing the token")
		fatal(err)
	}

	response := Token{tokenString}
	JsonResponse(response, w)
}
*/

var tokenEncodeString string = "something"

/*
func createToken(user models.User) (string, error) {
	// create the token
	token := jwt.New(jwt.SigningMethodHS256)
    claims := make(jwt.MapClaims)
	// set some claims
	claims["username"] = user.Username;
	claims["password"] = user.Password;
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	token.Claims = claims

	//Sign and get the complete encoded token as string
	return (token.SignedString(tokenEncodeString))
}
*/

// Must is a helper function that panics if the returning err is non-nil. Usually used in variable initialisation
var wikitemplates = template.Must(template.ParseFiles("./templates/edit.html", "./templates/view.html"))

func (p *Page) save() error {
	filename := p.Title + ".txt"
	return ioutil.WriteFile(filename, p.Body, 0600)
}

func loadPage(title string) (*Page, error) {
    filename := title + ".txt"
    body, err := ioutil.ReadFile(filename)
    if err != nil {
    	return nil, err
	}
	return &Page{title, body}, nil
}

func testSaveLoadPages() {
    p1 := &Page{Title: "TestPage", Body: []byte("Test Page Body")}
    p1.save()
    p, _ := loadPage("TestPage")
    fmt.Println(string(p.Body))
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Test - path: %s", r.URL.Path[1:])
}

var validPath = regexp.MustCompile("^/(edit|save|view)/([a-zA-Z0-9]+)$")

func getTitle(w http.ResponseWriter, r *http.Request) (string, error) {
	m:= validPath.FindStringSubmatch(r.URL.Path)  // return the matched string and each matched part, a () for a part
    if m == nil {
    	http.NotFound(w, r)
    	return "", errors.New("Invalid Page Title")
	}
	return m[2], nil
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	//title := r.URL.Path[len("/view/"):]
	//authorizationHeader := r.Header.Get("authorization")
	//fmt.Printf("authentication header: %v %T", authorizationHeader, authorizationHeader)
	title, err := getTitle(w, r)
	if err != nil {
		return
	}
	p, err := loadPage(title)
	if err != nil {
		http.Redirect(w, r, "/edit/" + title, http.StatusFound)
		return
	}
	//t := time.Now()
	//fmt.Printf("current time: %v %T \n", t, t)
	//t2 := time.Now().Add(1 * 24 * time.Hour)
	//fmt.Printf("current time: %v %T \n", t2, t2)
	cookie, _ := r.Cookie("username")
	if cookie == nil {
		fmt.Println("Set cookies")
		//expiration := time.Now().Add(1 * 24 * time.Hour)
		cookie := http.Cookie{Name: "username", Value: "kevin", Path: "/", Expires: time.Now().Add(1 * 15 * time.Second)}
		http.SetCookie(w, &cookie)
	} else {
		fmt.Println("Retreive cookies")
		// force expire a cookie
		//cookie := http.Cookie{Name: "username", Value: "kevin", MaxAge: -10, Expires: time.Now()}
		//http.SetCookie(w, &cookie)
		fmt.Println(cookie.Name)
		fmt.Println(cookie.Value)
		fmt.Println(cookie.Expires)
	}
	renderTemplate(w, "view", p)
	//fmt.Fprintf(w, "<h1>%s</h1><div>%s</div>", p.Title, p.Body)
}

func editHandler(w http.ResponseWriter, r *http.Request, title string) {
	//title := r.URL.Path[len("/edit/"):]
	//title, err := getTitle(w, r)
	//if err != nil {
	//	return
	//}
	p, err := loadPage(title)
	if err != nil {
		p = &Page{Title: title}
	}
	cookie, _ := r.Cookie("username")
	if cookie == nil {
		fmt.Println("Edit: no cookies")
	} else {
		fmt.Println("Edit: retreive cookies")
		// force expire a cookie
		//cookie := http.Cookie{Name: "username", Value: "kevin", MaxAge: -10, Expires: time.Now()}
		//http.SetCookie(w, &cookie)
		fmt.Println(cookie.Value)
	}
	//t, _ := template.ParseFiles("edit.html")  // read html and return a Template
	//fmt.Fprintf(w, "<h1>Editing %s</h1>"+
	//	"<form action=\"/save/%s\" method=\"POST\">" +
	//	"<textarea name=\"body\">%s</textarea><br>" +
	//	"<input type=\"submit\" value=\"Save\">"+
	//	"</form>",
	//	p.Title, p.Title, p.Body)
	renderTemplate(w, "edit", p)
}

func saveHandler(w http.ResponseWriter, r *http.Request) {
	//title := r.URL.Path[len("/save/"):]
	title, err := getTitle(w, r)
	if err != nil {
		return
	}
	body := r.FormValue("body")
	p := &Page{title, []byte(body)}
	err = p.save()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/view/" + title, http.StatusFound)
}

// to further reduce redundant code
// type HandlerFunc func(ResponseWriter, *Request)
func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m:= validPath.FindStringSubmatch(r.URL.Path)  // return the matched string and each matched part, a () for a part
		if m == nil {
			http.NotFound(w, r)
			return
		}
		fn(w, r, m[2])
	}
}

func renderTemplate(w http.ResponseWriter, tmpl string, p *Page) {

	//t, err := template.ParseFiles(tmpl + ".html")
	//if err != nil {
	//	http.Error(w, err.Error(), http.StatusInternalServerError)
	//	return
	//}
	//err = t.Execute(w, p)
	//if err != nil {
	//	http.Error(w, err.Error(), http.StatusInternalServerError)
	//}
	err := wikitemplates.ExecuteTemplate(w, tmpl + ".html", p) // Execute applies a parsed template to the data object
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

//func clientTestHandler(w http.ResponseWriter, r *http.Request) {
//	//resp, err := http.Get("http://localhost:3000")
//	person := &Person{
//		Id:    1234,
//		Name:  "John Doe",
//		Email: "jdoe@example.com",
//		Phones: []*Person_PhoneNumber{
//			{Number: "555-4321", Type: Person_HOME},
//		},
//	}
//    payload, err := proto.Marshal(person)
//	if err != nil {
//		fmt.Printf("Marshal Error %v %T \n", err, err)
//	} else {
//		fmt.Printf("Marshaled %T \n", payload)
//	}
//	//resp, err := http.NewRequest("GET", "http://localhost:3000", bytes.NewBuffer(payload))
//	conn, err := net.Dial("tcp", "localhost:3000/users")
//	if err != nil {
//		fmt.Printf("http-dial error \n %v\n", err)
//		return
//	}
//	conn.Write(payload)
//	//message, err := bufio.NewReader(conn).ReadString('\n')
//	buf := make([]byte, 1024)
//	resLen, err := conn.Read(buf)
//	fmt.Printf("tcp-handleRequest resLen %d\n", resLen)
//	if err != nil {
//		if err == io.EOF {
//			conn.Close()
//			fmt.Fprint(w, "<h1>Message from server</h1><div>no message</div>")
//		} else {
//			fmt.Printf("http-dial receiving error: %v, %T\n", err, err)
//		}
//		return
//	}
//	conn.Close()
//	fmt.Fprintf(w, "<h1>Message from server</h1><div>%s</div>", buf[:resLen])
//}

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}


type imagepage struct {
	Img image.Image
	Name string
}

func imageViewHandler(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open("./test/test_img_3.jpg")
	defer f.Close()
	//img, err := png.Decode(f)
	//fmt.Printf("type %T \n", img)
	buffer := new(bytes.Buffer)
	io.Copy(buffer, f)
	str := base64.StdEncoding.EncodeToString(buffer.Bytes())  // transfer to raw image
    t, err := template.ParseFiles("./wikitemplates/imageview.html")
    if err != nil {
    	fmt.Println("template parsing error")
	} else {
        //payload := &imagepage{Img: img, Name: "test image"}
		payload := map[string]interface{}{"Img": str, "Name": "test"}
		if err = t.Execute(w, payload); err != nil {
			log.Println("unable to execute template.")
		}
	}
}

func runHttpServer(wg *sync.WaitGroup) {
	defer wg.Done()
	http.HandleFunc("/view/", viewHandler)
	http.HandleFunc("/edit/", makeHandler(editHandler)) // check implementation
	http.HandleFunc("/save/", saveHandler)
	http.HandleFunc("/imagetest/", imageViewHandler)
	//http.HandleFunc("/clienttest/", clientTestHandler)
	//http.HandleFunc("/login/", loginHandler)
	http.ListenAndServe(":8080", nil)
}

//func main() {
//	wg := &sync.WaitGroup{}
//	wg.Add(2)
	//go runHttpServer(wg)
	//go runTCPServer(wg)
	//testDBLogin()
//	wg.Wait()
//}



