package main

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// global config
const maxUploadSizeMB = 20

// user role levels.
const (
	userRoleAdmin   = 1
	userRoleManager = 2
	userRoleUser    = 3
)

// member table scopes.
const (
	SCOPE_ORG        = "org"
	SCOPE_COLLECTION = "col"
	SCOPE_ENTITY     = "ent"
	SCOPE_ITEM       = "item"
	SCOPE_FILE       = "file"
)

// member table roles.
const (
	MEMBER_ROLE_OWNER  = "owner"
	MEMBER_ROLE_MEMBER = "member"
)

var (
	secret            = os.Getenv("APP_SECRET")
	defaultBucketName = os.Getenv("APP_DEFAULT_BUCKET_NAME")
	origin            = os.Getenv("APP_ALLOW_ORIGIN_HOST")
)

// storage clients
var (
	db          = &sql.DB{}
	minioClient = &minio.Client{}
)

// User info struct for serializing auth response
type User struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	First     string `json:"firstName"`
	Last      string `json:"lastName"`
	Role      string `json:"role"`
	RoleID    int    `json:"roleID"`
	LastLogin string `json:"lastLogin"`
	Token     string `json:"token"`
}

// Dashboard data with counts by type
type Dashboard struct {
	Size        int64 `json:"size"`
	Collections int   `json:"collections"`
	Items       int   `json:"items"`
	Entities    int   `json:"entities"`
	Files       int   `json:"files"`
}

// Top-level grouping for all collections, items, entities, and files
type Org struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Desc        string       `json:"desc"`
	Collections []Collection `json:"collections"`
	Owners      []User       `json:"owners"`
}

// Grouping for all items, entities, and files
type Collection struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Org   Org    `json:"org"`
	Items []Item `json:"items"`
	// Metadata []Metadata `json:"metadata"`
}

// Grouping for all entities and files
type Item struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Desc       string     `json:"desc"`
	Collection Collection `json:"collection"`
	Entities   []Entity   `json:"entities"`
	// Metadata []Metadata `json:"metadata"`
}

// Grouping for all sub-item entities
type Entity struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Item  Item   `json:"item"`
	Files []File `json:"files"`
	// Metadata []Metadata `json:"metadata"`
}

// File record with object metadata
type File struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Desc     string `json:"desc"`
	Entity   Entity `json:"entity"`
	Filename string `json:"filename"`
	MD5      string `json:"md5"`
	Size     int    `json:"size"`
	Ext      string `json:"ext"`
	// Metadata []Metadata `json:"metadata"`
}

// DepositEvent is an atomic event relating to an existing deposit, such as updating a metadata field value.
type DepositEvent struct {
	ID        int    `json:"id"`
	User      string `json:"user"`
	DepositID string `json:"depositID"`
	Scope     string `json:"scope"`
	Target    int    `json:"target"`
	Type      string `json:"type"`
	Time      string `json:"time"`
}

// MetadataField keeps information about a metadata field, including the value
type MetadataField struct {
	ID           int           `json:"id"`
	Label        string        `json:"label"`
	Schema       string        `json:"schema"`
	Tag          string        `json:"tag"`
	Scope        string        `json:"scope"`
	Note         string        `json:"note"`
	Required     bool          `json:"required"`
	OrgID        int           `json:"org_id"`
	CollectionID int           `json:"collection_id"`
	Value        MetadataValue `json:"value"`
	Vocab        []string      `json:"vocab"`
}

// MetadataValue tracks specific values relating to a metadata field, with a reference to the field id
type MetadataValue struct {
	ID         int    `json:"id"`
	DepositID  string `json:"depositID"`
	FileID     string `json:"fileID"`
	MetadataID int    `json:"metadataID"`
	Value      string `json:"value"`
	Updated    string `json:"updated"`
	UpdatedBy  int    `json:"updatedBy"`
}

func createDBClient() *sql.DB {
	// https://github.com/go-sql-driver/mysql/#usage
	host := os.Getenv("DB_HOST")
	user := os.Getenv("MYSQL_USER")
	password := os.Getenv("MYSQL_ROOT_PASSWORD")
	dbName := os.Getenv("MYSQL_DATABASE")
	connectionString := user + ":" + password + "@tcp(" + host + ")" + "/" + dbName
	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		log.Fatalln(err)
	}
	return db
}

func initDB() {
	// https://github.com/go-sql-driver/mysql/#important-settings
	db.SetConnMaxLifetime(time.Minute * 3)
	// db.SetMaxOpenConns(10)
	// db.SetMaxIdleConns(10)

	// Open doesn't open a connection. Validate DSN data:
	err := db.Ping()
	if err != nil {
		log.Fatalln(err)
	}

	// https://github.com/go-sql-driver/mysql/wiki/Examples
	rows, err := db.Query(`SHOW TABLES;`)
	if err != nil {
		log.Fatalln(err)
	}

	var table *string
	var tables []string
	for rows.Next() {
		err := rows.Scan(&table)
		if err != nil {
			log.Println(err)
		}
		tables = append(tables, *table)
	}
	log.Println("DB pool initialized with tables:", tables)
}

func createMinioClient() *minio.Client {
	// https://docs.min.io/docs/golang-client-api-reference.html
	appMode := os.Getenv("APP_MODE")
	endpoint := os.Getenv("MINIO_ENDPOINT")
	keyID := os.Getenv("MINIO_ACCESS_KEY")
	secret := os.Getenv("MINIO_SECRET_KEY")
	secure := true
	if appMode == "development" {
		secure = false
	}

	// Initialize minio client object.
	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(keyID, secret, ""),
		Secure: secure,
	})
	if err != nil {
		log.Fatalln(err)
	}
	return minioClient
}

func initAdmin() {
	// check for admin user
	adminEmail := os.Getenv("APP_ADMIN_EMAIL")
	if adminEmail == "" {
		log.Fatalln("No admin email set in environment. Exiting.")
	}
	rows, err := db.Query(`SELECT id FROM users WHERE email = ?;`, adminEmail)
	if err != nil {
		log.Fatalln(err)
	}

	user := User{}
	for rows.Next() {
		err := rows.Scan(&user.ID)
		if err != nil {
			log.Fatalln(err)
		}
	}
	if user.ID != 0 {
		log.Println("Using admin user: " + adminEmail)
		return
	}

	// create admin with default password
	defaultPassword := os.Getenv("APP_ADMIN_DEFAULT_PASSWORD") // raw password string from env
	if defaultPassword == "" {
		log.Fatalln("No admin password set in environment. Exiting.")
	}
	if len(defaultPassword) < 16 {
		log.Fatalln("Admin password is too short. Must be at least 16 characters. Exiting.")
	}

	hashedDefault := sha1.New() // create sha1 hash: requests from the web frontend will only pass sha1 hashed password values from the form.
	hashedDefault.Write([]byte(defaultPassword))
	bs := hashedDefault.Sum(nil)
	s := hex.EncodeToString(bs)

	hashedAndSalted := getHashedPassword(s) // generate hashed and salted value to actually store in database.

	_, err = db.Exec(`INSERT INTO users (email, password, role_id, first_name, last_name) VALUES (?, ?, ?, ?, ?);`, adminEmail, hashedAndSalted, 1, "3deposit", "Admin")
	if err != nil {
		log.Println(err)
		log.Fatalln("Unable to create default user. Exiting.")
	}
	log.Println("Admin user created successfully: " + adminEmail)
}

func initMinio() {
	exists, err := minioClient.BucketExists(context.Background(), defaultBucketName)
	if err != nil {
		log.Fatalln(err)
	}
	if !exists {
		err := minioClient.MakeBucket(context.Background(), defaultBucketName, minio.MakeBucketOptions{})
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("Default bucket created:", defaultBucketName)
	}
	log.Println("MinIO client initialized with bucket:", defaultBucketName)
}

func getHashedPassword(password string) string {
	raw := password + secret
	hash := sha1.New()
	hash.Write([]byte(raw))
	bs := hash.Sum(nil)
	s := hex.EncodeToString(bs)
	return s
}

func userHasPermissions(token string, maxRole int) (User, error) {
	// Get user that owns this token and check permission exceeds requested maxRole value
	user := User{}
	rows, err := db.Query(
		`SELECT
			u.id,
			u.email,
			u.first_name,
			u.last_name,
			u.role_id,
			r.role_name,
			u.last_login_at
		FROM tokens t
		JOIN users u ON u.id = t.user_id
		JOIN roles r ON r.id = u.role_id
		WHERE t.token = ? AND t.expires > ?;`,
		token, time.Now(),
	)
	if err != nil {
		return User{}, err
	}
	for rows.Next() {
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.First,
			&user.Last,
			&user.RoleID,
			&user.Role,
			&user.LastLogin,
		)
		if err != nil {
			return User{}, err
		}
	}

	if user.RoleID == 0 {
		return User{}, nil
	}

	if user.RoleID > maxRole {
		return User{}, nil
	}
	return user, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")
		hashed := getHashedPassword(password)

		if email != "" && password != "" {
			// db query and compare
			success := false
			rows, err := db.Query(
				`SELECT 
					u.id, 
					email, 
					first_name, 
					last_name, 
					role_name 
				FROM users u 
				JOIN roles r ON u.role_id = r.id 
				WHERE email = ? AND password = ?`,
				email, hashed)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}

			user := User{}
			for rows.Next() {
				err := rows.Scan(&user.ID, &user.Email, &user.First, &user.Last, &user.Role)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				break // only get first row result
			}

			// record login
			now := time.Now()
			_, err = db.Exec(`UPDATE users SET last_login_at = ? WHERE id = ?;`, now, user.ID)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}

			if user.ID != 0 && user.Role != "" {
				success = true
			} else {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintln(w, "Invalid login information.")
				return
			}

			if success {
				log.Println("Login user:", user)

				// remove old token
				_, err = db.Exec(`DELETE FROM tokens WHERE user_id = ?`, user.ID)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, "Database error.")
					return
				}

				// generate new token and expiration
				expires := now.AddDate(0, 0, 1)
				user.Token = uuid.New().String()

				// write db record
				_, err = db.Exec(`INSERT INTO tokens (token, user_id, expires) VALUES (?, ?, ?);`, user.Token, user.ID, expires)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, "Database error.")
					return
				}

				// construct user data payload
				userJSON, err := json.Marshal(user)
				if err != nil {
					log.Println("Error encoding user data", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				fmt.Fprint(w, string(userJSON))
				return
			}
		}
		// no email and/or password in request
		fmt.Fprintln(w, "Missing login information.")
		return
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)

	if r.Method == "GET" {
		dashboard := Dashboard{}

		// get collection count
		rows, err := db.Query(`SELECT count(*) from collections;`)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		for rows.Next() {
			err := rows.Scan(&dashboard.Collections)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// get item count
		rows, err = db.Query(`SELECT count(*) from items;`)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		for rows.Next() {
			err := rows.Scan(&dashboard.Items)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// get entity count
		rows, err = db.Query(`SELECT count(*) from entities;`)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		for rows.Next() {
			err := rows.Scan(&dashboard.Entities)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// get file count
		rows, err = db.Query(`SELECT count(*) from files;`)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		for rows.Next() {
			err := rows.Scan(&dashboard.Files)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// get total size of deposits
		rows, err = db.Query(`SELECT IFNULL(SUM(size), 0) FROM files WHERE size IS NOT NULL;`)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		for rows.Next() {
			err := rows.Scan(&dashboard.Size)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// construct dashboard data payload
		dashboardJSON, err := json.Marshal(dashboard)
		if err != nil {
			log.Println("Error encoding dashboard data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(dashboardJSON))
		return

	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {

	// TODO(rob): use new object path format from filesHandler POST

	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)

	if r.Method == "GET" {
		depositID := r.URL.Query().Get("id")
		filename := r.URL.Query().Get("fn")

		if filename == "" {
			// https://docs.min.io/docs/golang-client-api-reference.html#ComposeObject
			// compose and download entire deposit as zip
			return
		}

		object := depositID + "/" + filename

		// Generate a presigned url which expires in one minute.
		presignedURL, err := minioClient.PresignedGetObject(context.Background(), defaultBucketName, object, time.Second*60, url.Values{})
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Fprintln(w, presignedURL)
		return
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleAdmin)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Database error.")
	}
	if user.RoleID == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "User not permitted.")
		return
	}

	if r.Method == "GET" {
		rows, err := db.Query(`SELECT u.id, u.email, u.first_name, u.last_name, r.role_name, u.last_login_at FROM users u JOIN roles r ON u.role_id = r.id;`)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		users := []User{}
		for rows.Next() {
			user := User{}
			err := rows.Scan(&user.ID, &user.Email, &user.First, &user.Last, &user.Role, &user.LastLogin)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			users = append(users, user)
		}
		// construct users data payload
		usersJSON, err := json.Marshal(users)
		if err != nil {
			log.Println("Error encoding users data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(usersJSON))
		return
	}

	if r.Method == "POST" {
		err := r.ParseMultipartForm(10 << maxUploadSizeMB) // maxUploadSizeMB will be held in memory, the rest of the form data will go to disk.
		if err != nil {
			log.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		existingID := r.FormValue("id")
		email := r.FormValue("email")
		password := r.FormValue("password")
		firstName := r.FormValue("firstName")
		lastName := r.FormValue("lastName")
		role := r.FormValue("role")
		org := r.FormValue("org")

		hashed := getHashedPassword(password)

		roleID := 0
		row, err := db.Query(`SELECT id FROM roles WHERE role_name = ?;`, role)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Error updating user data.")
			return
		}
		for row.Next() {
			err := row.Scan(&roleID)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		if len(existingID) > 0 {
			log.Println("Update user data for id:", existingID)

			// update existing user data
			if len(password) > 0 { // new password is being set.
				_, err = db.Exec(`UPDATE users SET email=?, password=?, role_id=?, first_name=?, last_name=? WHERE id=?;`, email, hashed, roleID, firstName, lastName, existingID)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, "Error updating user data.")
					return
				}
			} else {
				_, err = db.Exec(`UPDATE users SET email=?, role_id=?, first_name=?, last_name=? WHERE id=?;`, email, roleID, firstName, lastName, existingID)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, "Error updating user data.")
					return
				}
			}

			// update org membership
			_, err = db.Exec(`UPDATE members SET role = ? WHERE user_id=? AND ref_id=?;`, MEMBER_ROLE_MEMBER, existingID, org)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Error updating user org membership.")
				return
			}

			fmt.Fprintf(w, "User data saved successfully: "+email)
			return
		}

		// write db record
		result, err := db.Exec(`INSERT INTO users (email, password, role_id, first_name, last_name) VALUES (?, ?, ?, ?, ?);`, email, hashed, roleID, firstName, lastName)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		userId, err := result.LastInsertId()
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		// set org membership
		_, err = db.Exec(`INSERT INTO members (role, user_id, ref_id);`, MEMBER_ROLE_MEMBER, userId, org)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Error updating user org membership.")
			return
		}
		fmt.Fprintf(w, "User added successfully: "+email)
		return
	}

	if r.Method == "DELETE" {
		userID := r.URL.Query().Get("id")
		// cleanup existing tokens and foreign key constraint
		_, err = db.Exec(`DELETE FROM tokens WHERE user_id = ?`, userID)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		// remove user record by id
		_, err = db.Exec(`DELETE FROM users WHERE id = ?;`, userID)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		fmt.Fprintf(w, "User deleted successfully: "+userID)
		return
	}
}

func orgsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleUser)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Database error.")
	}
	if user.RoleID == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "User not permitted.")
		return
	}

	if r.Method == "GET" {
		// Permissions: all valid users can GET.
		rows, err := db.Query(`SELECT o.id, o.name, o.desc FROM organizations o;`)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		orgs := []Org{}
		for rows.Next() {
			org := Org{}
			err := rows.Scan(&org.ID, &org.Name, &org.Desc)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			org.Owners = []User{} // init with empty array; json serialization will be null otherwise.

			// Get org owners.
			owners, err := db.Query(`SELECT DISTINCT u.id, u.email FROM users u JOIN members o ON u.id = o.user_id WHERE o.scope = ? AND o.ref_id = ?;`, SCOPE_ORG, org.ID)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Error getting organization owners.")
				return
			}
			for owners.Next() {
				owner := User{}
				err := owners.Scan(&owner.ID, &owner.Email)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				org.Owners = append(org.Owners, owner)
			}
			orgs = append(orgs, org)
		}
		// construct users data payload
		orgsJSON, err := json.Marshal(orgs)
		if err != nil {
			log.Println("Error encoding orgs data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(orgsJSON))
		return
	}

	if r.Method == "POST" {
		// Permissions: only valid admins can POST.
		if user.RoleID != userRoleAdmin {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "User not permitted.")
			return
		}

		err := r.ParseMultipartForm(10 << maxUploadSizeMB) // maxUploadSizeMB will be held in memory, the rest of the form data will go to disk.
		if err != nil {
			log.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
		name := r.FormValue("name")
		desc := r.FormValue("desc")
		owners := r.FormValue("owners")

		if id != 0 {
			// update existing org record
			log.Println("Update org data for:", name)
			_, err = db.Exec(`UPDATE organizations o SET o.name=?, o.desc=? WHERE id=?;`, name, desc, id)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Error updating organization data.")
				return
			}
		} else {
			// write new db record
			result, err := db.Exec("INSERT INTO organizations (name, `desc`) VALUES (?, ?);", name, desc)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
			id, err = result.LastInsertId()
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Error assigning owner to organization.")
			}
		}

		// update org owners
		ownerIds := strings.Replace(owners, ",", " ", -1)
		ownersSlice := strings.Fields(ownerIds)
		for i := range ownersSlice {
			if ownersSlice[i] != "0" {
				_, err := db.Exec("INSERT IGNORE INTO members (user_id, ref_id, scope, role) VALUES (?, ?, ?, ?);", ownersSlice[i], id, SCOPE_ORG, MEMBER_ROLE_OWNER)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, "Database error.")
					return
				}
			}
		}

		fmt.Fprintf(w, "Organization data saved successfully: "+name)
		return
	}

	if r.Method == "DELETE" {
		// Permissions: only valid admins can DELETE.
		if user.RoleID != userRoleAdmin {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "User not permitted.")
			return
		}
		id := r.URL.Query().Get("id")
		_, err = db.Exec(`DELETE FROM organizations WHERE id = ?`, id)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		fmt.Fprintf(w, "Org deleted successfully: "+id)
		return
	}
}

func collectionsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleUser)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Database error.")
	}
	if user.RoleID == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "User not permitted.")
		return
	}

	if r.Method == "GET" {
		// Permissions: only admins or org members can GET.
		// TODO(rob): check perms.

		var rows *sql.Rows
		var err error
		if user.RoleID == 1 {
			// return everything if user is admin.
			rows, err = db.Query(`SELECT c.id, c.name, c.desc, o.id, o.name, o.desc FROM collections c JOIN organizations o ON c.org_id = o.id;`)
		} else {
			// only return collections where user is member or owner.
			rows, err = db.Query(`SELECT c.id, c.name, c.desc, o.id, o.name, o.desc FROM collections c JOIN organizations o ON c.org_id = o.id JOIN members m ON m.user_id = ? WHERE m.scope = ? AND (m.role = ? OR m.role = ?) ;`, user.ID, SCOPE_COLLECTION, MEMBER_ROLE_MEMBER, MEMBER_ROLE_OWNER)
		}
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		cols := []Collection{}
		for rows.Next() {
			col := Collection{}
			err := rows.Scan(&col.ID, &col.Name, &col.Desc, &col.Org.ID, &col.Org.Name, &col.Org.Desc)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			cols = append(cols, col)
		}

		// construct users data payload
		colsJSON, err := json.Marshal(cols)
		if err != nil {
			log.Println("Error encoding collections data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(colsJSON))
		return
	}

	if r.Method == "POST" {
		// Permissions: only admins or org members can POST.
		// TODO(rob): check perms.
		err := r.ParseMultipartForm(10 << maxUploadSizeMB) // maxUploadSizeMB will be held in memory, the rest of the form data will go to disk.
		if err != nil {
			log.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
		name := r.FormValue("name")
		desc := r.FormValue("desc")
		org := r.FormValue("org")

		if id != 0 {
			// update existing org record
			log.Println("Update collection data for:", name)
			_, err = db.Exec(`UPDATE collections c SET c.name=?, c.desc=? c.org_id=? WHERE c.id=?;`, name, desc, org, id)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Error updating collection data.")
				return
			}
		} else {
			// write new db record
			_, err := db.Exec("INSERT INTO collections (name, `desc`, org_id) VALUES (?, ?, ?);", name, desc, org)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
		}

		fmt.Fprintf(w, "Collection data saved successfully: "+name)
		return
	}

	if r.Method == "DELETE" {
		// Permissions: only admins or collection owners can DELETE.
		// TODO(rob): check perms
		id := r.URL.Query().Get("id")
		_, err = db.Exec(`DELETE FROM collections WHERE id = ?`, id)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		fmt.Fprintf(w, "Collection deleted successfully: "+id)
		return
	}
}

func itemsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleUser)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Database error.")
	}
	if user.RoleID == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "User not permitted.")
		return
	}

	if r.Method == "GET" {
		// Permissions: only admins or collection members can GET.
		// TODO(rob): check perms.

		var rows *sql.Rows
		var err error
		if user.RoleID == 1 {
			// return everything if user is admin.
			rows, err = db.Query(`SELECT 
									i.id, i.name, i.desc, 
									c.id, c.name, c.desc,
									o.id, o.name, o.desc
									FROM items i 
									JOIN collections c ON i.collection_id = c.id
									JOIN organizations o ON c.org_id = o.id;`)
		} else {
			// only return items where user is member or owner of collection.
			rows, err = db.Query(`SELECT 
									i.id, i.name, i.desc, 
									c.id, c.name, c.desc,
									o.id, o.name, o.desc
									FROM items i 
									JOIN collections c ON i.collection_id = c.id
									JOIN organizations o ON c.org_id = o.id
									JOIN members m ON m.user_id = ?
									WHERE m.scope = ? AND (m.role = ? OR m.role = ?) ;`, user.ID, SCOPE_COLLECTION, MEMBER_ROLE_MEMBER, MEMBER_ROLE_OWNER)
		}
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		items := []Item{}
		for rows.Next() {
			item := Item{}
			err := rows.Scan(
				&item.ID, &item.Name, &item.Desc,
				&item.Collection.ID, &item.Collection.Name, &item.Collection.Desc,
				&item.Collection.Org.ID, &item.Collection.Org.Name, &item.Collection.Org.Desc)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// construct Files slice using item id
			entityRows, err := db.Query(`SELECT e.id, e.name, e.desc FROM entities e WHERE e.item_id = ?;`, item.ID)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
			for entityRows.Next() {
				entity := Entity{}
				err := entityRows.Scan(&entity.ID, &entity.Name, &entity.Desc)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				item.Entities = append(item.Entities, entity)
			}

			items = append(items, item)
		}

		// construct users data payload
		itemsJSON, err := json.Marshal(items)
		if err != nil {
			log.Println("Error encoding items data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(itemsJSON))
		return
	}

	if r.Method == "POST" {
		// Permissions: only admins or org members can POST.
		// TODO(rob): check perms.
		err := r.ParseMultipartForm(10 << maxUploadSizeMB) // maxUploadSizeMB will be held in memory, the rest of the form data will go to disk.
		if err != nil {
			log.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
		name := r.FormValue("name")
		desc := r.FormValue("desc")
		collection := r.FormValue("collection")

		if id != 0 {
			// update existing org record
			log.Println("Update item data for:", name)
			_, err = db.Exec(`UPDATE items i SET i.name=?, i.desc=? i.collection_id=? WHERE i.id=?;`, name, desc, collection, id)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Error updating item data.")
				return
			}
		} else {
			// write new db record
			_, err := db.Exec("INSERT INTO items (name, `desc`, collection_id) VALUES (?, ?, ?);", name, desc, collection)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
		}

		fmt.Fprintf(w, "Item data saved successfully: "+name)
		return
	}

	if r.Method == "DELETE" {
		// Permissions: only admins or collection owners can DELETE.
		// TODO(rob): check perms
		id := r.URL.Query().Get("id")
		_, err = db.Exec(`DELETE FROM items WHERE id = ?`, id)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		fmt.Fprintf(w, "Item deleted successfully: "+id)
		return
	}
}

func entitiesHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleUser)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Database error.")
	}
	if user.RoleID == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "User not permitted.")
		return
	}

	if r.Method == "GET" {
		// Permissions: only admins or collection members can GET.
		// TODO(rob): check perms.

		var rows *sql.Rows
		var err error
		if user.RoleID == 1 {
			// return everything if user is admin.
			rows, err = db.Query(`SELECT 
									e.id, e.name, e.desc, 
									i.id, i.name, i.desc,
									c.id, c.name, c.desc,
									o.id, o.name, o.desc
									FROM entities e 
									JOIN items i ON e.item_id = i.id
									JOIN collections c ON c.id = i.collection_id
									JOIN organizations o ON o.id = c.org_id;`)
		} else {
			// only return items where user is member or owner of collection.
			rows, err = db.Query(`SELECT 
									e.id, e.name, e.desc, 
									i.id, i.name, i.desc,
									c.id, c.name, c.desc,
									o.id, o.name, o.desc
									FROM entities e 
									JOIN items i ON e.item_id = i.id 
									JOIN collections c ON i.collection_id = c.id
									JOIN organizations o ON o.id = c.org_id
									JOIN members m ON m.user_id = ? 
									WHERE m.scope = ? AND (m.role = ? OR m.role = ?) ;`, user.ID, SCOPE_COLLECTION, MEMBER_ROLE_MEMBER, MEMBER_ROLE_OWNER)
		}
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		entities := []Entity{}
		for rows.Next() {
			entity := Entity{}
			err := rows.Scan(
				&entity.ID, &entity.Name, &entity.Desc,
				&entity.Item.ID, &entity.Item.Name, &entity.Item.Desc,
				&entity.Item.Collection.ID, &entity.Item.Collection.Name, &entity.Item.Collection.Desc,
				&entity.Item.Collection.Org.ID, &entity.Item.Collection.Org.Name, &entity.Item.Collection.Org.Desc)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// construct Files slice using entity id
			fileRows, err := db.Query(`SELECT f.id, f.name, f.desc, f.filename, f.md5, f.size, f.ext FROM files f WHERE f.entity_id = ?;`, entity.ID)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
			for fileRows.Next() {
				file := File{}
				err := fileRows.Scan(&file.ID, &file.Name, &file.Desc, &file.Filename, &file.MD5, &file.Size, &file.Ext)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				entity.Files = append(entity.Files, file)
			}

			entities = append(entities, entity)
		}

		// construct users data payload
		entitiesJSON, err := json.Marshal(entities)
		if err != nil {
			log.Println("Error encoding entities data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(entitiesJSON))
		return
	}

	if r.Method == "POST" {
		// Permissions: only admins or org members can POST.
		// TODO(rob): check perms.
		err := r.ParseMultipartForm(10 << maxUploadSizeMB) // maxUploadSizeMB will be held in memory, the rest of the form data will go to disk.
		if err != nil {
			log.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
		name := r.FormValue("name")
		desc := r.FormValue("desc")
		item := r.FormValue("item")

		if id != 0 {
			// update existing org record
			log.Println("Update entity data for:", name)
			_, err = db.Exec(`UPDATE entities e SET e.name=?, e.desc=? e.item_id=? WHERE e.id=?;`, name, desc, item, id)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Error updating entity data.")
				return
			}
		} else {
			// write new db record
			_, err := db.Exec("INSERT INTO entities (name, `desc`, item_id) VALUES (?, ?, ?);", name, desc, item)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
		}

		fmt.Fprintf(w, "Entity data saved successfully: "+name)
		return
	}

	if r.Method == "DELETE" {
		// Permissions: only admins or collection owners can DELETE.
		// TODO(rob): check perms
		id := r.URL.Query().Get("id")
		_, err = db.Exec(`DELETE FROM entities WHERE id = ?`, id)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		fmt.Fprintf(w, "Entity deleted successfully: "+id)
		return
	}
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleManager)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Database error.")
	}
	if user.RoleID == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "User not permitted.")
		return
	}

	if r.Method == "GET" {
		// Permissions: only admins or collection members can GET.
		// TODO(rob): check perms.

		var rows *sql.Rows
		var err error
		if user.RoleID == 1 {
			// return everything if user is admin.
			rows, err = db.Query(`SELECT 
									f.id, f.name, f.desc, f.filename, f.md5, f.size, f.ext,
									e.id, e.name, e.desc, 
									i.id, i.name, i.desc, 
									c.id, c.name, c.desc,
									o.id, o.name, o.desc
								FROM files f
								JOIN entities e ON e.id = f.entity_id
								JOIN items i ON i.id = e.item_id 
								JOIN collections c ON i.collection_id = c.id
								JOIN organizations o on c.org_id = o.id;`)
		} else {
			// only return items where user is member or owner of collection.
			rows, err = db.Query(`SELECT 
									f.id, f.name, f.desc, f.filename, f.md5, f.size, f.ext,
									e.id, e.name, e.desc, 
									i.id, i.name, i.desc, 
									c.id, c.name, c.desc,
									o.id, o.name, o.desc
									FROM files f
									JOIN entities e ON e.id = f.entity_id
									JOIN items i ON i.id = e.item_id 
									JOIN collections c ON i.collection_id = c.id
									JOIN organization o ON c.org_id = o.id
									JOIN members m ON m.user_id = ? 
									WHERE m.scope = ? AND (m.role = ? OR m.role = ?) ;`, user.ID, SCOPE_ORG, MEMBER_ROLE_MEMBER, MEMBER_ROLE_OWNER)
		}
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		files := []File{}
		for rows.Next() {
			file := File{}
			err := rows.Scan(&file.ID, &file.Name, &file.Desc, &file.Filename, &file.MD5, &file.Size, &file.Ext,
				&file.Entity.ID, &file.Entity.Name, &file.Entity.Desc,
				&file.Entity.Item.ID, &file.Entity.Item.Name, &file.Entity.Item.Desc,
				&file.Entity.Item.Collection.ID, &file.Entity.Item.Collection.Name, &file.Entity.Item.Collection.Desc,
				&file.Entity.Item.Collection.Org.ID, &file.Entity.Item.Collection.Org.Name, &file.Entity.Item.Collection.Org.Desc)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			files = append(files, file)
		}

		// construct users data payload
		filesJSON, err := json.Marshal(files)
		if err != nil {
			log.Println("Error encoding files data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(filesJSON))
		return
	}

	if r.Method == "POST" {
		err := r.ParseMultipartForm(10 << maxUploadSizeMB)
		if err != nil {
			log.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		// Unpack and store form data
		formdata := r.MultipartForm
		file := formdata.File["file"][0]
		id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
		name := r.FormValue("name")
		desc := r.FormValue("desc")
		entity := r.FormValue("entity")
		item := ""
		col := ""
		org := ""

		// get hierarchy info
		rows, err := db.Query(`SELECT i.id, c.id, o.id 
							   FROM entities e 
							   JOIN items i ON e.item_id = i.id 
							   JOIN collections c ON i.collection_id = c.id 
							   JOIN organizations o ON c.org_id = o.id
							   WHERE e.id = ?;`, entity)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		for rows.Next() {
			err := rows.Scan(&item, &col, &org)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		// get some file info
		filename := file.Filename
		size := file.Size
		ext := strings.Split(file.Filename, ".")[1]

		// store the file object.
		fileData, err := file.Open()
		if err != nil {
			log.Println("Error opening file:", file.Filename)
			fmt.Fprintln(w, err)
			return
		}
		defer fileData.Close()

		// construct object "path"
		// TODO(rob): generate guid for object "name", instead of using filename.
		pathElements := []string{org, col, item, entity, file.Filename}
		objectName := strings.Join(pathElements, "/")

		// put object into default bucket
		info, err := minioClient.PutObject(context.Background(), defaultBucketName, objectName, fileData, size, minio.PutObjectOptions{})
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Error putting object.")
			return
		}
		log.Println("Successfully put object:", info)
		md5 := info.ETag

		if id != 0 {
			// update existing org record
			log.Println("Update file data for:", name)
			_, err = db.Exec(`UPDATE files f SET f.name=?, f.desc=?, f.entity_id=?, f.filename=?,f.md5=?, f.size=?, f.ext=? WHERE f.id=?;`, name, desc, entity, filename, md5, ext, id)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
		} else {
			// write new db record
			_, err := db.Exec("INSERT INTO files (name, `desc`, entity_id, filename, md5, size, ext) VALUES (?, ?, ?, ?, ?, ?, ?);", name, desc, entity, filename, md5, size, ext)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
		}

		// TODO(rob): generate file metadata.
	}

	// if r.Method == "DELETE" {
	// 	id := r.URL.Query().Get("id")
	// 	filename := r.URL.Query().Get("fn")
	// 	if id == "" || filename == "" {
	// 		log.Println("Missing required data.")
	// 		w.WriteHeader(http.StatusInternalServerError)
	// 		fmt.Fprint(w, "Missing required data for this request.")
	// 		return
	// 	}
	// 	object := id + "/" + filename
	// 	opts := minio.RemoveObjectOptions{}
	// 	err = minioClient.RemoveObject(context.Background(), defaultBucketName, object, opts)
	// 	if err != nil {
	// 		log.Println(err)
	// 		w.WriteHeader(http.StatusInternalServerError)
	// 		fmt.Fprint(w, "Storage error.")
	// 		return
	// 	}

	// 	// TODO(rob): update deposit size.

	// 	fmt.Fprint(w, "Sucessfully deleted object: "+object)
	// 	return
	// }

}

func metadataHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleUser)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Database error.")
	}
	if user.RoleID == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "User not permitted.")
		return
	}

	fields := []MetadataField{}

	if r.Method == "GET" {
		// get metadata fields
		rows, err := db.Query("SELECT `id`, `label`, `schema`, `tag`, IFNULL(`scope`, 'None'), `note`, `required` FROM metadata_fields;")
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		for rows.Next() {
			field := MetadataField{}
			err := rows.Scan(&field.ID, &field.Label, &field.Schema, &field.Tag, &field.Scope, &field.Note, &field.Required)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fields = append(fields, field)
		}

		// construct users data payload
		metadataJSON, err := json.Marshal(fields)
		if err != nil {
			log.Println("Error encoding metadata fields data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(metadataJSON))
		return
	}

	if r.Method == "POST" {
		err := r.ParseMultipartForm(10 << maxUploadSizeMB)
		if err != nil {
			log.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		formdata := r.MultipartForm
		log.Println("Metadata field data:", formdata.Value)

		existingID := r.FormValue("id")
		label := r.FormValue("label")
		schema := r.FormValue("schema")
		tag := r.FormValue("tag")
		scope := r.FormValue("scope")
		note := r.FormValue("note")
		req := r.FormValue("required")

		required := false
		if req == "true" {
			required = true
		}

		if len(existingID) > 0 {
			log.Println("Update metadata field data for id:", existingID)

			_, err = db.Exec("UPDATE metadata_fields SET `label`=?, `schema`=?, `tag`=?, `scope`=?, `note`=?, `required`=? WHERE id=?;", label, schema, tag, scope, note, required, existingID)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Error updating metadata field data.")
				return
			}

			fmt.Fprintf(w, "Metadata field data saved successfully: "+label)
			return
		}

		// write db record
		_, err = db.Exec("INSERT INTO metadata_fields (`label`, `schema`, `tag`, `scope`, `note`, `required`) VALUES (?, ?, ?, ?, ?, ?);", label, schema, tag, scope, note, required)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		fmt.Fprintf(w, "Metadata field added successfully: "+label)
		return
	}

	if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		// remove metadata values that reference this field
		_, err = db.Exec(`DELETE FROM metadata_values WHERE metadata_id = ?`, id)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		// remove field record by id
		_, err = db.Exec(`DELETE FROM metadata_fields WHERE id = ?;`, id)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		fmt.Fprintf(w, "Metadata field and corresponding values deleted successfully: "+id)
		return
	}
}

func depositMetadataHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleManager)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Database error.")
	}
	if user.RoleID == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "User not permitted.")
		return
	}

	if r.Method == "POST" {
		err := r.ParseMultipartForm(10 << maxUploadSizeMB)
		if err != nil {
			log.Println(err)
			fmt.Fprintln(w, err)
			return
		}

		formdata := r.MultipartForm
		fmt.Println(formdata)

		depositID := r.FormValue("depositID")
		metadataID := r.FormValue("metadataID")
		value := r.FormValue("value")

		// get value id, if exists
		rows, err := db.Query(
			`SELECT id from metadata_values WHERE deposit_id = ? AND metadata_id = ?;`,
			depositID,
			metadataID,
		)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		mv := MetadataValue{}
		for rows.Next() {
			err := rows.Scan(&mv.ID)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		if mv.ID != 0 {
			_, err = db.Exec(
				`UPDATE metadata_values SET value = ? WHERE id = ?;`,
				value,
				mv.ID,
			)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
			fmt.Fprintf(w, "Metadata value updated successfully.")
			return
		}

		// write metadata records
		_, err = db.Exec(
			`INSERT INTO metadata_values (deposit_id, metadata_id, value, updated, updated_by) VALUES (?, ?, ?, ?, ?);`,
			depositID, metadataID, value, time.Now(), user.ID,
		)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		// write event record
		_, err = db.Exec(
			`INSERT INTO events 
				(user_id, deposit_id, event_scope, event_target, event_type, event_timestamp) 
			VALUES (?, ?, ?, ?, ?, ?);`,
			user.ID, depositID, "metadata", metadataID, "update", time.Now())
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		fmt.Fprintf(w, "Metadata value added successfully.")
		return
	}

	if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		// remove metadata value by id
		_, err = db.Exec(`DELETE FROM metadata_values WHERE id = ?`, id)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		fmt.Fprintf(w, "Metadata value deleted successfully.")
		return
	}

	// No handled method.
	fmt.Fprintf(w, "Method not supported.")
}

func main() {

	// check that application secret is configured
	if secret == "" {
		log.Fatalln("No app secret set. Exiting.")
	}

	// create and initialize database connection
	db = createDBClient()
	defer db.Close()
	initDB()

	// create and initialize minio connection
	minioClient = createMinioClient()
	initMinio()

	// create admin user, if necessary
	initAdmin()

	// route handlers
	http.HandleFunc("/", dashboardHandler)
	http.HandleFunc("/deposit/metadata", depositMetadataHandler)
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/metadata", metadataHandler)
	http.HandleFunc("/users", usersHandler)
	http.HandleFunc("/orgs", orgsHandler)
	http.HandleFunc("/collections", collectionsHandler)
	http.HandleFunc("/items", itemsHandler)
	http.HandleFunc("/entities", entitiesHandler)
	http.HandleFunc("/files", filesHandler)

	// serve
	log.Println("Serving on :8081")
	http.ListenAndServe(":8081", nil)
}
