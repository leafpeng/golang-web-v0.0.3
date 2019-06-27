package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	gomail "gopkg.in/gomail.v2"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

// UserInfo session save in memory
type UserInfo struct {
	UserName string
	Email    string
}

// inMemorySessions map[ cookie uuid ]UserInfo
var inMemorySessions = make(map[string]UserInfo)
var resetPasswordToken = make(map[string]string)

var (
	tpl *template.Template

	createTableStatements = []string{
		`CREATE DATABASE IF NOT EXISTS leaf`,
		`USE leaf;`,
		`CREATE TABLE IF NOT EXISTS userinfo (
		id INT UNSIGNED NOT NULL AUTO_INCREMENT,
		useremail VARCHAR(64) NOT NULL,
		username VARCHAR(64) NOT NULL,
		password VARCHAR(64) NOT NULL,
		PRIMARY KEY (id))`,
	}
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	db := dbConn()
	defer db.Close()
	err := createTable(db)
	if err != nil {
		log.Fatal(err)
	}

}

func main() {

	logger()

	hub := newHub()
	go hub.run()

	r := mux.NewRouter()

	r.PathPrefix("/styles/").Handler(http.StripPrefix("/styles/", http.FileServer(http.Dir("./styles"))))
	r.PathPrefix("/reset-password/styles/").Handler(http.StripPrefix("/reset-password/styles/", http.FileServer(http.Dir("./styles"))))
	r.PathPrefix("/confirm-password/styles/").Handler(http.StripPrefix("/confirm-password/styles/", http.FileServer(http.Dir("./styles"))))
	r.HandleFunc("/", index).Methods("GET")
	r.HandleFunc("/livechat", func(w http.ResponseWriter, r *http.Request) {
		livechat(hub, w, r)
	}).Methods("GET")
	r.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	}).Methods("GET")
	r.HandleFunc("/register", registerPost).Methods("POST")
	r.HandleFunc("/login", loginGet).Methods("GET")
	r.HandleFunc("/login", loginPost).Methods("POST")
	r.HandleFunc("/logout", logout).Methods("GET")
	r.HandleFunc("/profile", profile).Methods("GET")
	r.HandleFunc("/update", updateAccount).Methods("POST")
	r.HandleFunc("/reset-password", resetPasswordGet).Methods("GET")
	r.HandleFunc("/reset-password", resetPasswordPost).Methods("POST")
	r.HandleFunc("/confirm-password/", confirmPasswordGet).Methods("GET")
	r.HandleFunc("/confirm-password/", confirmPasswordPost).Methods("POST")
	r.HandleFunc("/delete", deleteAccount)

	log.Println("Server starting at port 8080.")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func dbConn() *sql.DB {
	conn, err := sql.Open("mysql", "root:leaf@tcp(127.0.0.1:3306)/")
	if err != nil {
		log.Fatal("Can not open database", err)
	}
	if err := conn.Ping(); err != nil {
		conn.Close()
		log.Fatal("Can not establish connection.", err)
	}
	log.Println("Database connected.")
	return conn
}

// dbGetUserID get user id from database
func dbGetUserID(db *sql.DB, username string) (int, error) {
	var id int
	err := db.QueryRow("SELECT id FROM leaf.userinfo WHERE username=?", username).Scan(&id)
	if err == sql.ErrNoRows {
		log.Fatal(err)
	}
	return id, nil
}

// createTable creates the table, and if necessary, the database.
func createTable(conn *sql.DB) error {
	for _, stmt := range createTableStatements {
		_, err := conn.Exec(stmt)
		if err != nil {
			return err
		}
	}
	log.Println("Table created.")
	return nil
}

// setCookieAndCreateSession set cookie to user's browser and create session in server memory.
func setCookieAndCreateSession(w http.ResponseWriter, un, email string) {
	sID := uuid.NewV4()

	cookie := &http.Cookie{
		Name:  "session",
		Value: sID.String(),
	}
	http.SetCookie(w, cookie)
	inMemorySessions[cookie.Value] = UserInfo{
		UserName: un,
		Email:    email,
	}
}

// AlreadyLoggedIn check if user already loggedin
func AlreadyLoggedIn(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}
	if _, ok := inMemorySessions[cookie.Value]; ok {
		return ok
	}
	return false
}

// CheckEmail check email exists in database or not
func CheckEmail(email string) bool {

	db := dbConn()
	defer db.Close()

	// check if user exists
	var un string
	err := db.QueryRow("SELECT username FROM leaf.userinfo WHERE useremail=?", email).Scan(&un)
	if err == sql.ErrNoRows {
		// not exit in database
		log.Printf("CheckEmail() %v not exists in db.", email)
		return false
	} else if un != "" {
		return true
	}

	return true
}

// getUserName helper function for later websocket sendmessage use.
func getUserName(r *http.Request) []byte {
	cookie, err := r.Cookie("session")
	if err != nil {
		log.Fatal("can not get user cookie", err)
	}
	username := []byte(inMemorySessions[cookie.Value].UserName + " : ")
	return username

}

func logger() {
	file, err := os.OpenFile("log.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal("OpenFile failed.")
	}
	multi := io.MultiWriter(file, os.Stdout)
	log.SetOutput(multi)
	log.Println("Logger start:")

}

// loggerHelper return userinfo
func loggerHelper(r *http.Request) UserInfo {
	cookie, _ := r.Cookie("session")
	userinfo := inMemorySessions[cookie.Value]
	return userinfo
}

func index(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if sessionInfo, ok := inMemorySessions[cookie.Value]; ok {
		err = tpl.ExecuteTemplate(w, "index.html", sessionInfo)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
}

func loginGet(w http.ResponseWriter, r *http.Request) {

	if AlreadyLoggedIn(w, r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "login.html", nil)
}

func loginPost(w http.ResponseWriter, r *http.Request) {

	if AlreadyLoggedIn(w, r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseForm()
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")

	if email == "" || password == "" {
		http.Error(w, "field can not be empty.", http.StatusSeeOther)
		return
	}
	db := dbConn()
	defer db.Close()

	// check if user exists
	var un string
	var pw string
	err := db.QueryRow("SELECT username, password FROM leaf.userinfo WHERE useremail=?", email).Scan(&un, &pw)
	if err == sql.ErrNoRows {
		// not exit in database
		http.Error(w, "User does not exist", http.StatusForbidden)
		return
	}

	// compare hashedpassword
	err = bcrypt.CompareHashAndPassword([]byte(pw), []byte(password))
	if err != nil {
		http.Error(w, "Wrong password.", http.StatusForbidden)
		return
	}
	setCookieAndCreateSession(w, un, email)
	log.Printf("username: %v email: %v logged in.", un, email)

	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func registerPost(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	username := r.PostForm.Get("username")
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	if email == "" || password == "" || username == "" {
		http.Error(w, "Field can not be empty", http.StatusForbidden)
		return
	}

	var un string
	db := dbConn()
	defer db.Close()
	// check if user already exists
	err := db.QueryRow("SELECT username FROM leaf.userinfo WHERE username=? OR useremail=?", username, email).Scan(&un)
	// if user not exsts in database, err = sql.ErrNoRows
	if err == sql.ErrNoRows {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Server Error!", http.StatusInternalServerError)
			return
		}
		strHashedPassword := string(hashedPassword)
		stmt, err := db.Prepare("INSERT INTO leaf.userinfo (username, useremail, password) VALUES (?, ?, ?)")
		if err != nil {
			log.Fatal(err)
		}
		defer stmt.Close()
		_, err = stmt.Exec(username, email, strHashedPassword)
		if err != nil {
			log.Fatal(err)
		}
		setCookieAndCreateSession(w, username, email)
		log.Printf("username: %v email: %v created.", username, email)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		http.Error(w, "User already existed.", http.StatusForbidden)
		return
	}

}

func logout(w http.ResponseWriter, r *http.Request) {

	if !AlreadyLoggedIn(w, r) {
		http.Error(w, "Not Authorized.", http.StatusForbidden)
		return
	}
	cookie, _ := r.Cookie("session")
	// call loggerHelper before delete userinfo from memory
	userinfo := loggerHelper(r)
	log.Printf("username: %v email: %v logout.", userinfo.UserName, userinfo.Email)

	delete(inMemorySessions, cookie.Value)
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)

}

func profile(w http.ResponseWriter, r *http.Request) {

	if !AlreadyLoggedIn(w, r) {
		http.Error(w, "Not Authorized.", http.StatusForbidden)
		return
	}
	cookie, _ := r.Cookie("session")
	sessionInfo := inMemorySessions[cookie.Value]

	tpl.ExecuteTemplate(w, "profile.html", sessionInfo)
}

func deleteAccount(w http.ResponseWriter, r *http.Request) {

	if !AlreadyLoggedIn(w, r) {
		http.Error(w, "Not Authorized.", http.StatusForbidden)
		return
	}
	db := dbConn()
	defer db.Close()

	cookie, _ := r.Cookie("session")
	// call loggerHelper before delete userinfo from memory
	userinfo := loggerHelper(r)
	log.Printf("username: %v email: %v deleted.", userinfo.UserName, userinfo.Email)

	delete(inMemorySessions, cookie.Value)
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)

	id, err := dbGetUserID(db, userinfo.UserName)
	if err != nil {
		log.Fatal("Can not get user id from db.")
		return
	}

	stmt, err := db.Prepare("DELETE FROM leaf.userinfo WHERE id=?")
	if err != nil {
		log.Fatal("Can not delete user from db.")
		return
	}
	defer stmt.Close()
	_, err = stmt.Exec(id)
	if err != nil {
		log.Fatal(err)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)

}

func updateAccount(w http.ResponseWriter, r *http.Request) {

	if !AlreadyLoggedIn(w, r) {
		http.Error(w, "Not Authorized.", http.StatusForbidden)
		return
	}

	r.ParseForm()
	email := r.PostForm.Get("email")
	username := r.PostForm.Get("username")

	if username == "" && email == "" {
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	db := dbConn()
	defer db.Close()

	var un string
	// check if user already exists
	err := db.QueryRow("SELECT username FROM leaf.userinfo WHERE username=? OR useremail=?", username, email).Scan(&un)
	// if user not exsts in database, err = sql.ErrNoRows
	if err == sql.ErrNoRows {

		cookie, _ := r.Cookie("session")
		// call loggerHelper before delete userinfo from memory
		userinfo := loggerHelper(r)
		log.Printf("username: %v email: %v try updating.", userinfo.UserName, userinfo.Email)
		id, err := dbGetUserID(db, userinfo.UserName)
		if err != nil {
			log.Fatal("Can not get user id from db.")
			return
		}
		delete(inMemorySessions, cookie.Value)
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)

		stmt, err := db.Prepare("UPDATE leaf.userinfo SET useremail=?, username=? WHERE id=?")
		if err != nil {
			log.Fatal("Can not update user from db.")
			return
		}
		switch {
		case email == "":
			defer stmt.Close()
			_, err = stmt.Exec(userinfo.Email, username, id)
			if err != nil {
				log.Fatal(err)
				return
			}
			log.Printf("username: %v email: %v updated.", username, userinfo.Email)
			setCookieAndCreateSession(w, username, userinfo.Email)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
		case username == "":
			defer stmt.Close()
			_, err = stmt.Exec(email, userinfo.UserName, id)
			if err != nil {
				log.Fatal(err)
				return
			}
			log.Printf("username: %v email: %v updated.", userinfo.UserName, email)
			setCookieAndCreateSession(w, userinfo.UserName, email)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
		default:
			defer stmt.Close()
			_, err = stmt.Exec(email, username, id)
			if err != nil {
				log.Fatal(err)
				return
			}
			log.Printf("username: %v email: %v updated.", username, email)
			setCookieAndCreateSession(w, username, email)
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
		}

	} else {
		http.Error(w, "User or Email already existed.", http.StatusForbidden)
		return
	}

}

func resetPasswordGet(w http.ResponseWriter, r *http.Request) {
	tpl.ExecuteTemplate(w, "reset-password.html", nil)
}

// helper function for run goroutine on emailSender
func emailSender(d *gomail.Dialer, m *gomail.Message) {
	if err := d.DialAndSend(m); err != nil {
		panic(err)
	}
}

func resetPasswordPost(w http.ResponseWriter, r *http.Request) {

	host := r.Host

	r.ParseForm()

	email := r.PostForm.Get("email")
	log.Printf("email: %v try to reset password.", email)
	outlook := os.Getenv("EMAIL_OUTLOOK")
	outlookPW := os.Getenv("EMAIL_OUTLOOK_PW")

	sID := uuid.NewV4()

	token := sID.String()
	resetPasswordToken[token] = email

	s := fmt.Sprintf("<a href='http://%s/confirm-password/?token=%s'>Reset Password</a>", host, token)
	log.Println(s)
	// log.Println(outlook)
	m := gomail.NewMessage()
	m.SetAddressHeader("From", outlook, "Leaf Peng")
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Reset Password")
	m.SetBody("text/html", s)
	// m.Attach("/home/Alex/lolcat.jpg")

	d := gomail.NewDialer("smtp.office365.com", 587, outlook, outlookPW)

	// Send the email to Bob, Cora and Dan.
	// if err := d.DialAndSend(m); err != nil {
	// 	panic(err)
	// }
	go emailSender(d, m)

	log.Println("email sent.")

	http.Redirect(w, r, "/", http.StatusSeeOther)

}

func confirmPasswordGet(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()

	token := r.Form.Get("token")

	if email, ok := resetPasswordToken[token]; ok {
		if CheckEmail(email) {
			log.Printf("email: %v token: %v", email, token)

			tpl.ExecuteTemplate(w, "confirm-password.html", token)
		} else {

			http.Error(w, "Not Authorized.", http.StatusForbidden)

		}
	}

}

func confirmPasswordPost(w http.ResponseWriter, r *http.Request) {

	r.ParseForm()
	token := r.Form.Get("token")
	email := resetPasswordToken[token]

	pwA := r.PostForm.Get("password-a")
	pwB := r.PostForm.Get("password-b")

	log.Printf("token: %v\nemail: %v\npwa: %v\npwb: %v", token, email, pwA, pwB)
	if pwA == pwB {

		db := dbConn()
		defer db.Close()
		// get user id for update
		var id int
		err := db.QueryRow("SELECT id FROM leaf.userinfo WHERE useremail=?", email).Scan(&id)
		if err == sql.ErrNoRows {
			log.Fatal(err)
		}
		// hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(pwA), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Server Error!", http.StatusInternalServerError)
			return
		}
		strHashedPassword := string(hashedPassword)
		// update password
		stmt, err := db.Prepare("UPDATE leaf.userinfo SET password=? WHERE id=?")
		if err != nil {
			log.Fatal("Can not update user from db.")
			return
		}
		defer stmt.Close()
		_, err = stmt.Exec(strHashedPassword, id)
		if err != nil {
			log.Fatal(err)
			return
		}
		// delete reset token

		delete(resetPasswordToken, token)

		log.Println(resetPasswordToken)
		// redirect to login page
		http.Redirect(w, r, "/login", http.StatusSeeOther)

	} else {
		http.Error(w, "Two passwords have to be same", http.StatusForbidden)
		return
	}

}

func livechat(hub *Hub, w http.ResponseWriter, r *http.Request) {

	if !AlreadyLoggedIn(w, r) {
		http.Error(w, "Not Authorized.", http.StatusForbidden)
		return
	}

	tpl.ExecuteTemplate(w, "livechat.html", len(hub.clients))

}
