package main

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var db *sqlx.DB

func main() {
	dbInit, err := sqlx.Connect("postgres", "host=34.101.216.10 user=skilvul password=skilvul123apa dbname=skilvul-groupchat sslmode=disable")
	if err != nil {
		log.Fatalln(err)
	}

	db = dbInit

	r := gin.Default()
	r.POST("/register", register)
	r.POST("/login", login)
	r.PUT("/change_profile", change_profile)
	r.PUT("/change_password", change_password)
	r.GET("/profile/:user_id", show_profile)
	r.POST("/group", create_group)
	r.POST("/group/:room_id", join_gorup)
	r.Run()
}

func register(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	confirmPassword := c.Request.FormValue("confirm_password")

	if confirmPassword != password {
		c.JSON(400, StandardAPIResponse{
			Err: "Confirmed password is not matched",
		})
		return
	}
	salt := RandStringBytes(32)
	password += salt

	h := sha256.New()
	h.Write([]byte(password))
	password = fmt.Sprintf("%x", h.Sum(nil))

	query := `
		INSERT INTO
			account
		(
			username,
			password,
			salt,
			created_at,
			profile_pic
		)
		VALUES
		(
			$1,
			$2,
			$3,
			$4,
			$5
		)
	`

	_, err := db.Exec(query, username, password, salt, time.Now(), "")
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	c.JSON(201, StandardAPIResponse{
		Err:     "null",
		Message: "Success create new user",
	})
}

func login(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")

	query := `
	SELECT 
		user_id,
		username,
		password,
		salt,
		created_at,
		profile_pic
	FROM
		account
	WHERE
		username = $1
	`

	var user UserDB
	err := db.Get(&user, query, username)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(400, StandardAPIResponse{
				Err: "Not authorized",
			})
			return
		}

		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	password += user.Salt.String
	h := sha256.New()
	h.Write([]byte(password))
	hashedPassword := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password.String != hashedPassword {
		c.JSON(401, StandardAPIResponse{
			Err: "password mismatch",
		})
		return
	}

	resp := User{
		Username:   user.UserName.String,
		ProfilePic: user.ProfilePic.String,
		CreatedAt:  user.CreatedAt.UnixNano(),
	}

	c.JSON(200, StandardAPIResponse{
		Err:  "null",
		Data: resp,
	})
}
func change_profile(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	profile_pic := c.Request.FormValue("profile_pic")

	query := `
	UPDATE
	account
	SET
	profile_pic = $1
	WHERE
	username = $2
	`

	query_get_user := `
	SELECT 
		user_id,
		username,
		password,
		salt,
		created_at,
		profile_pic
	FROM
		account
	WHERE
		username = $1
	`

	var user UserDB
	err := db.Get(&user, query_get_user, username)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	password += user.Salt.String
	h := sha256.New()
	h.Write([]byte(password))
	hashed_password := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password.String != hashed_password {
		c.JSON(401, StandardAPIResponse{
			Err: "Wrong password",
		})
		return
	}

	_, err2 := db.Exec(query, profile_pic, username)
	if err2 != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err2.Error(),
		})
		return
	}

	c.JSON(200, StandardAPIResponse{
		Err:     "null",
		Message: "Success update user profile",
		Data: User{
			Username:   username,
			ProfilePic: profile_pic,
			CreatedAt:  user.CreatedAt.Unix(),
		},
	})
}

func change_password(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	new_password := c.Request.FormValue("new_password")
	confirm_new_password := c.Request.FormValue("confirm_new_password")

	query_change_password := `
	UPDATE
	account
	SET
	password = $1
	WHERE
	username = $2
	`

	query_get_user := `
	SELECT 
		user_id,
		username,
		password,
		salt,
		created_at,
		profile_pic
	FROM
		account
	WHERE
		username = $1
	`

	var user UserDB
	err := db.Get(&user, query_get_user, username)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	password += user.Salt.String
	h := sha256.New()
	h.Write([]byte(password))
	hashed_password := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password.String != hashed_password {
		c.JSON(401, StandardAPIResponse{
			Err: "Wrong password",
		})
		return
	}

	if new_password != confirm_new_password {
		c.JSON(401, StandardAPIResponse{
			Err: "New password confirmation does not match",
		})
		return
	}

	new_password += user.Salt.String
	encryptor := sha256.New()
	encryptor.Write([]byte(new_password))
	hashed_new_password := fmt.Sprintf("%x", encryptor.Sum(nil))
	log.Print(hashed_new_password)

	log.Print("salt: ", user.Salt.String)

	_, err_up := db.Exec(query_change_password, hashed_new_password, username)
	if err_up != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err_up.Error(),
		})
		return
	}

	msg := fmt.Sprintf("%v password has been changed successfully.", username)
	c.JSON(200, StandardAPIResponse{
		Message: msg,
	})

}

func show_profile(c *gin.Context) {
	user_id := c.Param("user_id")

	query_get_user := `
	SELECT
	user_id, username, profile_pic, created_at
	FROM
	account
	WHERE
	user_id=$1
	`

	var user UserDB
	err := db.Get(&user, query_get_user, user_id)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	resp := User{
		Username:   user.UserName.String,
		ProfilePic: user.ProfilePic.String,
		CreatedAt:  user.CreatedAt.UnixNano(),
	}

	c.JSON(200, StandardAPIResponse{
		Err:  "null",
		Data: resp,
	})
}

func create_group(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	group_name := c.Request.FormValue("group_name")
	category_id := c.Request.FormValue("category_id")
	description := c.Request.FormValue("description")

	query_get_user := `
	SELECT
	user_id, password, salt
	FROM
	account
	WHERE username=$1
	`
	var user UserDB
	err := db.Get(&user, query_get_user, username)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	password += user.Salt.String
	h := sha256.New()
	h.Write([]byte(password))
	hashed_password := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password.String != hashed_password {
		c.JSON(401, StandardAPIResponse{
			Err: "Wrong password",
		})
		return
	}

	query_create_group := `
	INSERT INTO room(
		name,
		admin_user_id,
		description,
		category_id,
		created_at
	)
	VALUES
	(
		$1,
		$2,
		$3,
		$4,
		$5
	)
	`

	_, err_up := db.Exec(query_create_group, group_name, user.UserID.Int64, description, category_id, time.Now())
	if err_up != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err_up.Error(),
		})
		return
	}

	msg := fmt.Sprintf("Room has been created successfully")
	c.JSON(200, StandardAPIResponse{
		Message: msg,
	})
}

func join_gorup(c *gin.Context) {
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	room_id := c.Param("room_id")

	query_get_user := `
	SELECT
	user_id, password, salt
	FROM
	account
	WHERE username=$1
	`
	var user UserDB
	err := db.Get(&user, query_get_user, username)
	if err != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	password += user.Salt.String
	h := sha256.New()
	h.Write([]byte(password))
	hashed_password := fmt.Sprintf("%x", h.Sum(nil))

	if user.Password.String != hashed_password {
		c.JSON(401, StandardAPIResponse{
			Err: "Wrong password",
		})
		return
	}

	query_join_group := `
	INSERT INTO room_participant(
		room_id,
		user_id
	)
	VALUES
	(
		$1,
		$2
	)
	`
	query_get_group := `
	SELECT
	*
	FROM
	room
	WHERE
	room_id=$1
	`

	var room RoomDB
	err2 := db.Get(&room, query_get_group, room_id)
	if err2 != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err.Error(),
		})
		return
	}

	_, err3 := db.Exec(query_join_group, room_id, user.UserID.Int64)
	if err3 != nil {
		c.JSON(400, StandardAPIResponse{
			Err: err3.Error(),
		})
		return
	}

	msg := fmt.Sprintf("User has joined the group!")
	c.JSON(200, StandardAPIResponse{
		Message: msg,
	})

}

//random string generator
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

type StandardAPIResponse struct {
	Err     string      `json:"err"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type User struct {
	Username   string `json:"username"`
	ProfilePic string `json:"profile_pic"`
	CreatedAt  int64  `json:"created_at"`
}

type UserDB struct {
	UserID     sql.NullInt64  `db:"user_id"`
	UserName   sql.NullString `db:"username"`
	ProfilePic sql.NullString `db:"profile_pic"`
	Salt       sql.NullString `db:"salt"`
	Password   sql.NullString `db:"password"`
	CreatedAt  time.Time      `db:"created_at"`
}

type Room struct {
	RoomID      int64  `json:"room_id"`
	Name        string `json:"name"`
	AdminUserID int64  `json:"admin_user_id"`
	Description string `json:"description"`
	CategoryID  int64  `json:"category_id"`
	CreatedAt   int64  `json:"created_at"`
}

type RoomDB struct {
	RoomID      sql.NullInt64  `db:"room_id"`
	Name        sql.NullString `db:"name"`
	AdminUserID sql.NullInt64  `db:"admin_user_id"`
	Description sql.NullString `db:"description"`
	CategoryID  sql.NullInt64  `db:"category_id"`
	CreatedAt   time.Time      `db:"created_at"`
}