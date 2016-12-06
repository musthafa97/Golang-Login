package main

import "fmt"
import "net/http"
import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "github.com/kataras/go-sessions"
import "golang.org/x/crypto/bcrypt"

var db *sql.DB
var err error

type user struct{

	id int
	username string
	password string
	email string
	
}

func koneksi(){

	db, err = sql.Open("mysql", "root:root@/db_go")
	
	if err != nil{
		panic(err.Error())
	}
	
	err = db.Ping()
	if err !=nil {
		panic(err.Error())
	}

}

func route(){

	http.HandleFunc("/daftar", register)
	
	http.HandleFunc("/", home)
	
	http.HandleFunc("/login", login)
	
	http.HandleFunc("/logout", logout)

}


func main(){

	koneksi()
	
	route()
	
	defer db.Close()
	
	fmt.Println("jalankan web server di http://localhost:9090/")
	http.ListenAndServe(":9090", nil)

}


func QueryUser(username string)(user){

	var users=user{}
	
	err = db.QueryRow("SELECT id, username, password, email from tbl_user WHERE username=? ", username).Scan(&users.id, &users.username, &users.password,&users.email)
	
	return users
}

func cekError(res http.ResponseWriter, req *http.Request, err error) bool{
	
	if err != nil {
		http.Redirect(res, req, req.Host + req.URL.Path, 301)
		return false
	}
	
	return true
}

func Auth( users *user, password string, res http.ResponseWriter, req *http.Request){

	err = bcrypt.CompareHashAndPassword([]byte(users.password), []byte(password))
	if cekError(res, req, err){
	
	session := sessions.Start(res, req)
	
	session.Set("username", users.username)
	
	http.Redirect(res, req, "/",302)
	}
}

func register(res http.ResponseWriter, req *http.Request){

	if req.Method != "POST"{
		http.ServeFile(res, req, "SignUp.html")
		return
	}
	
	username := req.FormValue("username")
	email := req.FormValue("email")
	password := req.FormValue("password")
	
	users := QueryUser(username)
	
	if(user{}) == users {
	
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		
		if len(hashedPassword) != 0 && cekError(res, req, err) {
		
			stmt, err := db.Prepare("INSERT tbl_user SET username=?, password=?, email=?")
		
			if cekError(res, req, err) {
				r, err := stmt.Exec(&username, &hashedPassword, &email)
				if cekError(res, req, err){
					id, _ := r.LastInsertId();
					
					Auth(&user{int(id), string(username), string(hashedPassword), string(email)}, password, res, req)
				}
			}
		}
	}
}



func home(res http.ResponseWriter, req *http.Request){

	session := sessions.Start(res, req)
	
	if len(session.GetString("username")) != 0 && cekError(res, req, err) {
	
		res.Header().Set("Content-Type", "text/html")
		res.Write([]byte("Hello " + session.GetString("username")))
		res.Write([]byte("</br><a href='/logout'>Logout</a>"))	
	
	}
	
	if len(session.GetString("username")) == 0 {
		http.Redirect(res, req, "/login", 301)
	}
}


func login(res http.ResponseWriter, req *http.Request){

	if req.Method != "POST" {
	
		http.ServeFile(res, req, "SignIn.html")
		return
	}
	
	username := req.FormValue("username")
	password := req.FormValue("password")
	
	users := QueryUser(username)
	
	if cekError(res, req, err){
	
		Auth(&users, password, res, req)
	}
}	

func logout(res http.ResponseWriter, req *http.Request){
	
	session := sessions.Start(res, req)
	
	session.Clear()
	
	sessions.Destroy(res, req)
	
	http.Redirect(res, req, "/", 302) 


}