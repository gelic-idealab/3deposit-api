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
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// global config
const maxUploadSizeMB = 20
const (
	userRoleAdmin    = 1
	userRoleManager  = 2
	userRoleUploader = 3
	userRoleViewer   = 4
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
	Size   int64 `json:"size"`
	Total  int   `json:"total"`
	Models int   `json:"models"`
	Videos int   `json:"videos"`
	VR     int   `json:"vr"`
}

// Deposit data representation of deposit values in db
type Deposit struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Desc     string          `json:"desc"`
	Updated  string          `json:"updated"`
	Type     string          `json:"type"`
	Size     int64           `json:"size"`
	Items    []DepositItem   `json:"items"`
	Creator  User            `json:"creator"`
	Events   []DepositEvent  `json:"events"`
	Metadata []MetadataField `json:"metadata"`
}

// DepositItem is a single item of a deposit, usually a file.
type DepositItem struct {
	Name    string `json:"name"`
	Ext     string `json:"ext"`
	Size    int64  `json:"size"`
	Updated string `json:"updated"`
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
	ID        int           `json:"id"`
	Label     string        `json:"label"`
	Schema    string        `json:"schema"`
	Tag       string        `json:"tag"`
	Note      string        `json:"note"`
	Required  bool          `json:"required"`
	Scope     string        `json:"scope"`
	MediaType string        `json:"mediaType"`
	Value     MetadataValue `json:"value"`
	Vocab     []string      `json:"vocab"`
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
		return
	}
	log.Println("Admin user created successfully: " + adminEmail)
	return
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
				fmt.Fprintln(w, "User record is invalid.")
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

				fmt.Println("expires:", expires)

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
		fmt.Fprintln(w, "Invalid login information.")
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)

	if r.Method == "GET" {
		dashboard := Dashboard{}

		// get model count
		rows, err := db.Query(`SELECT count(*) from deposits WHERE type_id = ?`, 1)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		for rows.Next() {
			err := rows.Scan(&dashboard.Models)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// get video count
		rows, err = db.Query(`SELECT count(*) from deposits WHERE type_id = ?`, 2)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		for rows.Next() {
			err := rows.Scan(&dashboard.Videos)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		// get vr count
		rows, err = db.Query(`SELECT count(*) from deposits WHERE type_id = ?`, 3)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		for rows.Next() {
			err := rows.Scan(&dashboard.VR)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		dashboard.Total = dashboard.Models + dashboard.Videos + dashboard.VR

		// get total size of deposits
		rows, err = db.Query(`SELECT IFNULL(SUM(size), 0) FROM deposits WHERE size IS NOT NULL;`)
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

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleUploader)
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
		err := r.ParseMultipartForm(10 << maxUploadSizeMB) // maxUploadSizeMB will be held in memory, the rest of the form data will go to disk.
		if err != nil {
			fmt.Fprintln(w, err)
			return
		}

		// Unpack and store form data
		formdata := r.MultipartForm
		files := formdata.File["file"]

		depositID := uuid.New().String()
		depositName := r.FormValue("deposit_name")
		depositDesc := r.FormValue("deposit_desc")
		dt := r.FormValue("deposit_type")
		depositType := 0
		switch dt {
		case "model":
			depositType = 1
		case "video":
			depositType = 2
		case "vr":
			depositType = 3
		}

		var depositSize int64
		for i := range files {
			filename := files[i].Filename
			log.Println("Processing file:", filename)

			size := files[i].Size
			depositSize += size

			file, err := files[i].Open()
			defer file.Close()
			if err != nil {
				fmt.Fprintln(w, err)
				return
			}

			// put object into default bucket
			info, err := minioClient.PutObject(context.Background(), defaultBucketName, depositID+"/"+filename, file, size, minio.PutObjectOptions{})
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Storage error.")
				return
			}
			log.Println("Successfully put object:", info)

			// genereate boilerplate metadata xml file
			// see: https://golang.org/src/encoding/xml/example_test.go
			// cmd := exec.Command("python", "./premis/generate.py", "fileID", filename)
			// cmd.Stdout = os.Stdout
			// cmd.Stderr = os.Stderr
			// log.Println(cmd.Run())
		}

		// write deposit record
		_, err = db.Exec(
			`INSERT INTO deposits VALUES (?, ?, ?, ?, ?, ?, ?);`,
			depositID, depositName, depositDesc, time.Now(), depositType, depositSize, user.ID)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}

		for field := range formdata.Value {
			if field != "deposit_name" && field != "deposit_desc" && field != "deposit_type" {
				mf := MetadataField{}
				json.Unmarshal([]byte(r.FormValue(field)), &mf)

				// write metadata records
				_, err = db.Exec(
					`INSERT INTO metadata_values (deposit_id, metadata_id, value, updated, updated_by) VALUES (?, ?, ?, ?, ?);`,
					depositID, mf.ID, mf.Value.Value, time.Now(), user.ID)
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
					user.ID, depositID, "metadata", mf.ID, "create", time.Now())
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, "Database error.")
					return
				}
			}
		}

		// genereate boilerplate metadata xml file
		// see: https://golang.org/src/encoding/xml/example_test.go
		// cmd := exec.Command("python", "./premis/generate.py", "depositID", depositID)
		// cmd.Stdout = os.Stdout
		// cmd.Stderr = os.Stderr
		// log.Println(cmd.Run())

		fmt.Fprintf(w, "Deposit uploaded successfully: "+depositName)
		return
	}

	// unhandled method
	fmt.Fprintln(w, "No handler for method:", r.Method)
	return

}

func depositsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method, r.RequestURI, r.RemoteAddr)
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "X-API-KEY")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")

	if r.Method == "OPTIONS" {
		return
	}

	token := r.Header.Get("X-API-KEY")
	user, err := userHasPermissions(token, userRoleViewer)
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

	// if r.Method == "POST" {
	// 	err := r.ParseMultipartForm(10 << maxUploadSizeMB) // maxUploadSizeMB will be held in memory, the rest of the form data will go to disk.
	// 	if err != nil {
	// 		log.Println(err)
	// 		fmt.Fprintln(w, err)
	// 		return
	// 	}

	// 	formdata := r.MultipartForm
	// 	fmt.Println(formdata)
	//  }

	if r.Method == "GET" {
		// get specific deposit data if id query
		depositID := r.URL.Query().Get("id")
		if len(depositID) > 0 {
			rows, err := db.Query(
				`SELECT
					d.id,
					d.name,
					d.desc,
					d.updated,
					dt.type,
					d.size,
					u.id,
					u.email,
					u.first_name,
					u.last_name
				FROM deposits d
				JOIN deposit_types dt on d.type_id = dt.id
				JOIN users u on u.id = d.upload_by
				WHERE d.id = ?;`,
				depositID)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
			deposit := Deposit{}
			for rows.Next() {
				err := rows.Scan(
					&deposit.ID,
					&deposit.Name,
					&deposit.Desc,
					&deposit.Updated,
					&deposit.Type,
					&deposit.Size,
					&deposit.Creator.ID,
					&deposit.Creator.Email,
					&deposit.Creator.First,
					&deposit.Creator.Last,
				)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}

			// Get deposit events
			rows, err = db.Query(
				`SELECT 
					id, 
					user_id, 
					deposit_id, 
					event_scope,
					event_target,
					event_type, 
					event_timestamp 
				FROM events 
				WHERE deposit_id = ?`,
				deposit.ID,
			)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
			events := []DepositEvent{}
			for rows.Next() {
				de := DepositEvent{}
				err := rows.Scan(
					&de.ID,
					&de.User,
					&de.DepositID,
					&de.Scope,
					&de.Target,
					&de.Type,
					&de.Time,
				)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				events = append(events, de)
			}

			deposit.Events = events

			// Get deposit metadata values
			// Query selects all required fields, or any fields that have metadata values
			rows, err = db.Query(
				`SELECT
					f.id, 
					f.label, 
					f.schema, 
					f.tag, 
					f.note, 
					f.required, 
					IFNULL(v.id, 0), 
					IFNULL(v.deposit_id, 0), 
					IFNULL(v.metadata_id, 0), 
					IFNULL(v.value, ""), 
					IFNULL(v.updated, 0), 
					IFNULL(v.updated_by, 0)
				FROM metadata_fields f
				LEFT JOIN metadata_values v
				ON (v.metadata_id = f.id AND v.deposit_id = ?)
				WHERE (f.required = 1 OR v.value IS NOT NULL);`,
				deposit.ID,
			)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Database error.")
				return
			}
			metadata := []MetadataField{}
			for rows.Next() {
				val := MetadataField{}
				err := rows.Scan(
					&val.ID,
					&val.Label,
					&val.Schema,
					&val.Tag,
					&val.Note,
					&val.Required,
					&val.Value.ID,
					&val.Value.DepositID,
					&val.Value.MetadataID,
					&val.Value.Value,
					&val.Value.Updated,
					&val.Value.UpdatedBy,
				)
				if err != nil {
					log.Println(err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				metadata = append(metadata, val)
			}

			deposit.Metadata = metadata

			// construct deposit file tree
			for object := range minioClient.ListObjects(context.Background(), defaultBucketName, minio.ListObjectsOptions{Prefix: depositID, Recursive: true}) {
				item := DepositItem{}
				splits := strings.Split(object.Key, "/")
				item.Name = strings.Join(splits[1:], "/")
				splits = strings.Split(object.Key, ".")
				item.Ext = splits[len(splits)-1]
				item.Size = object.Size
				item.Updated = object.LastModified.String()
				deposit.Items = append(deposit.Items, item)
			}

			// construct deposits data payload
			depositJSON, err := json.Marshal(deposit)
			if err != nil {
				log.Println("Error encoding deposit data", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			fmt.Fprint(w, string(depositJSON))
			return
		}

		// else get all deposits data
		rows, err := db.Query(
			`SELECT
				d.id,
				d.name,
				d.desc,
				d.updated,
				dt.type,
				d.size,
				u.id,
				u.email,
				u.first_name,
				u.last_name
			FROM deposits d
			JOIN deposit_types dt on d.type_id = dt.id
			JOIN users u on u.id = d.upload_by;`,
		)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		deposits := []Deposit{}
		for rows.Next() {
			deposit := Deposit{}
			err := rows.Scan(
				&deposit.ID,
				&deposit.Name,
				&deposit.Desc,
				&deposit.Updated,
				&deposit.Type,
				&deposit.Size,
				&deposit.Creator.ID,
				&deposit.Creator.Email,
				&deposit.Creator.First,
				&deposit.Creator.Last,
			)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			deposits = append(deposits, deposit)
		}
		// construct deposits data payload
		depositsJSON, err := json.Marshal(deposits)
		if err != nil {
			log.Println("Error encoding deposits data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, string(depositsJSON))
		return
	}

	// unhandled method
	fmt.Fprintln(w, "No handler for method:", r.Method)
	return
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
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
			if len(password) > 0 {
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

			fmt.Fprintf(w, "User data saved successfully: "+email)
			return
		}

		// write db record
		_, err = db.Exec(`INSERT INTO users (email, password, role_id, first_name, last_name) VALUES (?, ?, ?, ?, ?);`, email, hashed, roleID, firstName, lastName)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
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

func metadataHandler(w http.ResponseWriter, r *http.Request) {
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

	fields := []MetadataField{}

	if r.Method == "GET" {
		// get metadata fields
		rows, err := db.Query("SELECT `id`, `label`, `schema`, `tag`, `note`, `required` FROM metadata_fields;")
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Database error.")
			return
		}
		for rows.Next() {
			field := MetadataField{}
			err := rows.Scan(&field.ID, &field.Label, &field.Schema, &field.Tag, &field.Note, &field.Required)
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
		note := r.FormValue("note")
		req := r.FormValue("required")

		required := false
		if req == "true" {
			required = true
		}

		if len(existingID) > 0 {
			log.Println("Update metadata field data for id:", existingID)

			_, err = db.Exec("UPDATE metadata_fields SET `label`=?, `schema`=?, `tag`=?, `note`=?, `required`=? WHERE id=?;", label, schema, tag, note, required, existingID)
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
		_, err = db.Exec("INSERT INTO metadata_fields (`label`, `schema`, `tag`, `note`, `required`) VALUES (?, ?, ?, ?, ?);", label, schema, tag, note, required)
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
	return
}

func depositFileHandler(w http.ResponseWriter, r *http.Request) {
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

		// Unpack and store form data
		formdata := r.MultipartForm
		files := formdata.File["file"]

		depositID := r.FormValue("id")
		if depositID == "" {
			log.Println("No deposit id.")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Deposit ID required.")
			return
		}

		for i := range files {
			filename := files[i].Filename
			log.Println("Processing file:", filename)

			size := files[i].Size

			file, err := files[i].Open()
			defer file.Close()
			if err != nil {
				fmt.Fprintln(w, err)
				return
			}

			// put object into default bucket
			info, err := minioClient.PutObject(context.Background(), defaultBucketName, depositID+"/"+filename, file, size, minio.PutObjectOptions{})
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "Storage error.")
				return
			}
			log.Println("Successfully put object:", info)

			// TODO(rob): generate file metadata.
		}
	}

	if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		filename := r.URL.Query().Get("fn")
		if id == "" || filename == "" {
			log.Println("Missing required data.")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Missing required data for this request.")
			return
		}
		object := id + "/" + filename
		opts := minio.RemoveObjectOptions{}
		err = minioClient.RemoveObject(context.Background(), defaultBucketName, object, opts)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Storage error.")
			return
		}

		// TODO(rob): update deposit size.

		fmt.Fprint(w, "Sucessfully deleted object: "+object)
		return
	}

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
	http.HandleFunc("/deposit/files", depositFileHandler)
	http.HandleFunc("/deposit/metadata", depositMetadataHandler)
	http.HandleFunc("/deposits", depositsHandler)
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/metadata", metadataHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/users", usersHandler)

	// serve
	log.Println("Serving on :8081")
	http.ListenAndServe(":8081", nil)
}
