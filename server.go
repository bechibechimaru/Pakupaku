package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// セッション管理のためのCookieStoreを作成
var store = sessions.NewCookieStore([]byte("something-very-secret"))

type UserInfo struct {
	Username       string
	Email          string
	UniversityName string
	Campus         string
	Password       string
}

type Post struct {
	User      string
	Message   string
	CreatedAt string
}

var tempUserInfo UserInfo

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		email := r.FormValue("email")
		universityName := r.FormValue("nameofuniversity")
		campus := r.FormValue("campusofuniversity")
		password := r.FormValue("password")

		tempUserInfo = UserInfo{
			Username:       username,
			Email:          email,
			UniversityName: universityName,
			Campus:         campus,
			Password:       password,
		}

		http.Redirect(w, r, "/confirm", http.StatusSeeOther)
	} else {
		http.ServeFile(w, r, "./screen/signup.html")
	}
}

func searchUniversitiesHandler(w http.ResponseWriter, r *http.Request){
	query := r.URL.Query().Get("q")
	var universities []string

	rows, err := db.Query("SELECT universityname FROM University WHERE universityname LIKE ?", query+"%")
	if err != nil {
		http.Error(w, "データベースクエリに失敗しました", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	for rows.Next(){
		var universityname string
		if err := rows.Scan(&universityname); err != nil {
			http.Error(w, "データの読み込みに失敗しました", http.StatusInternalServerError)
			return
		}
		universities = append(universities, universityname)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "データベースエラー", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(universities)
}

func getUniversityUIDHandler(w http.ResponseWriter, r *http.Request) {
    universityName := r.URL.Query().Get("universityname")
    var universityUID string

    err := db.QueryRow("SELECT university_uid FROM University WHERE universityname = ?", universityName).Scan(&universityUID)
    if err != nil {
        http.Error(w, "大学UIDの取得に失敗しました", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"university_uid": universityUID})
}


func getCampusesByUniversityUIDHandler(w http.ResponseWriter, r *http.Request) {
    universityUID := r.URL.Query().Get("university_uid")
	fmt.Println("取得した大学UID:", universityUID)

    var campuses []string

    rows, err := db.Query("SELECT campusname FROM Campus WHERE university_uid = ?", universityUID)
    if err != nil {
        http.Error(w, "データベースクエリに失敗しました", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    for rows.Next() {
        var campusname string
        if err := rows.Scan(&campusname); err != nil {
			fmt.Println("キャンパス名の読み込みに失敗しました")
            http.Error(w, "データの読み込みに失敗しました", http.StatusInternalServerError)
            return
        }
        campuses = append(campuses, campusname)
    }

    if err := rows.Err(); err != nil {
        http.Error(w, "データベースエラー", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(campuses)
}


func confirmHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./screen/confirm.html")
	if err != nil {
		http.Error(w, "テンプレートの読み込みに失敗しました", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, tempUserInfo)
	if err != nil {
		http.Error(w, "テンプレートの実行に失敗しました", http.StatusInternalServerError)
	}
}

var db *sql.DB

func initDB() {
	// envファイルを読みこむ　
	err := godotenv.Load("./gitignore/.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",dbUser, dbPassword, dbHost, dbPort, dbName)
	
	// データベースに接続
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println("データベース接続に失敗しました:", err)
		return
	}

	if err := db.Ping(); err != nil {
		fmt.Println("データベースが応答しません")
	} else {
		fmt.Println("データベース接続成功")
	}
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func getUniversityUID(universityName string) (string, error) {
	var universityUID string
	err := db.QueryRow("SELECT university_uid FROM University WHERE universityname = ?", universityName).Scan(&universityUID)
	if err != nil {
		return "", err
	}
	return universityUID, nil
}

func getCampusUID(campusName string) (string, error) {
	var campusUID string
	err := db.QueryRow("SELECT campus_uid FROM Campus WHERE campusname = ?", campusName).Scan(&campusUID)
	if err != nil {
		return "", err
	}
	return campusUID, nil
}

func registerUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		hashedPassword, err := hashPassword(tempUserInfo.Password)
		if err != nil {
			http.Error(w, "パスワードの暗号化に失敗しました。", http.StatusInternalServerError)
			return
		}

		universityUID, err := getUniversityUID(tempUserInfo.UniversityName)
		if err != nil {
			http.Error(w, "大学UIDの取得に失敗しました。", http.StatusInternalServerError)
			return
		}

		campusUID, err := getCampusUID(tempUserInfo.Campus)
		if err != nil {
			http.Error(w, "キャンパスUIDの取得に失敗しました。", http.StatusInternalServerError)
			return
		}

		query := "INSERT INTO User (user_uid, username, encrypted_password, email, university_uid, campus_uid) VALUES (UUID(), ?, ?, ?, ?, ?)"
		_, err = db.Exec(query, tempUserInfo.Username, hashedPassword, tempUserInfo.Email, universityUID, campusUID)
		if err != nil {
			http.Error(w, "データベースへの登録に失敗しました", http.StatusInternalServerError)
			fmt.Println("SQLエラー:", err)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		fmt.Fprintf(w, "ユーザー登録が完了しました")
	}
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func loginhandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var hashedPassword string
		query := "SELECT encrypted_password FROM User WHERE email = ?"
		err := db.QueryRow(query, email).Scan(&hashedPassword)
		if err != nil {
			http.Error(w, "メールアドレスまたはパスワードが間違っています。", http.StatusUnauthorized)
			return
		}

		if !checkPasswordHash(password, hashedPassword) {
			http.Error(w, "メールアドレスまたはパスワードが間違っています", http.StatusUnauthorized)
			return
		}

		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "セッションの取得に失敗しました", http.StatusInternalServerError)
			return
		}
		session.Values["authenticated"] = true
		session.Values["email"] = email
		session.Save(r, w)

		http.Redirect(w, r, "/postscreen", http.StatusSeeOther)
	} else {
		http.ServeFile(w, r, "./screen/login.html")
	}
}

func postscreenHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "セッションの取得に失敗しました", http.StatusInternalServerError)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "アクセス権がありません", http.StatusForbidden)
		return
	}

	email, ok := session.Values["email"].(string)
	if !ok {
		http.Error(w, "セッションにメールアドレスがありません", http.StatusInternalServerError)
		return
	}

	var username, universityUID, campusUID, universityName string
	query := `SELECT u.username, u.university_uid, u.campus_uid, uni.universityname
			  FROM User u
			  JOIN University uni ON u.university_uid = uni.university_uid
			  WHERE u.email = ?`
	err = db.QueryRow(query, email).Scan(&username, &universityUID, &campusUID, &universityName)
	if err != nil {
		http.Error(w, "ユーザー情報の取得に失敗しました。", http.StatusInternalServerError)
		return
	}

	posts, err := getPostsByCampus(campusUID)
	if err != nil {
		http.Error(w, "投稿データの取得に失敗しました", http.StatusInternalServerError)
		return
	}

	queryUniversity := "SELECT universityname FROM University WHERE university_uid = ?"
	err = db.QueryRow(queryUniversity, universityUID).Scan(&universityName)
	if err != nil {
		http.Error(w, "大学名の取得に失敗しました", http.StatusInternalServerError)
		return
	}

	var campusName string
	queryCampus := "SELECT campusname FROM Campus WHERE campus_uid = ?"
	err = db.QueryRow(queryCampus, campusUID).Scan(&campusName)
	if err != nil {
		http.Error(w, "キャンパス名の取得に失敗しました", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("./screen/postscreen.html")
	if err != nil {
		http.Error(w, "テンプレートの読み込みに失敗しました", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username       string
		UniversityName string
		CampusName     string
		Posts          []Post
	}{
		Username:       username,
		UniversityName: universityName,
		CampusName:     campusName,
		Posts:          posts,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "テンプレートの実行に失敗しました", http.StatusInternalServerError)
	}
}

func postMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "セッションの取得に失敗しました", http.StatusInternalServerError)
			return
		}

		email, ok := session.Values["email"].(string)
		if !ok {
			http.Error(w, "セッションにメールアドレスがありません", http.StatusInternalServerError)
			return
		}

		var userUID, campusUID string
		query := "SELECT user_uid, campus_uid FROM User WHERE email = ?"
		err = db.QueryRow(query, email).Scan(&userUID, &campusUID)
		if err != nil {
			http.Error(w, "ユーザー情報の取得に失敗しました", http.StatusInternalServerError)
			return
		}

		document := r.FormValue("message")
		if document == "" {
			tmpl, _ := template.ParseFiles("./screen/postscreen.html")
			data := struct {
				ErrorMessage string
			}{
				ErrorMessage: "投稿内容が空です。",
			}
			tmpl.Execute(w, data)
			return
		}

		queryInsert := "INSERT INTO Threads (document_uid, document, created_by, campus_uid) VALUES (UUID(),?,?,?)"
		_, err = db.Exec(queryInsert, document, userUID, campusUID)
		if err != nil {
			http.Error(w, "投稿の保存に失敗しました", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/postscreen", http.StatusSeeOther)
	} else {
		http.Error(w, "無効なリクエストです", http.StatusMethodNotAllowed)
	}
}

func getPostsByCampus(campusUID string) ([]Post, error) {
	rows, err := db.Query(
		`SELECT u.username, t.document, t.created_at
		FROM Threads t
		JOIN User u ON t.created_by = u.user_uid
		WHERE t.campus_uid = ?
		ORDER BY t.created_at DESC`, campusUID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		if err := rows.Scan(&post.User, &post.Message, &post.CreatedAt); err != nil {
			return nil, err
		}
		posts = append(posts, post)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return posts, nil
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "セッションの取得に失敗しました", http.StatusInternalServerError)
		return 
	}

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "セッションにメールアドレスがありません", http.StatusForbidden)
		return 
	}

	email, ok := session.Values["email"].(string)
	if !ok {
		http.Error(w, "セッションにメールアドレスがありません", http.StatusInternalServerError)
		return
	}

	var username, universityName, campusName string
	query := `SELECT u.username, uni.universityname, c.campusname 
	          FROM User u  
			  JOIN University uni ON u.university_uid = uni.university_uid 
			  JOIN Campus c ON u.campus_uid = c.campus_uid 
			  WHERE u.email = ?`

	err = db.QueryRow(query, email).Scan(&username, &universityName, &campusName)
	if err != nil {
		http.Error(w, "プロフィール情報の取得に失敗しました。", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("./screen/profile.html")
	if err != nil {
		http.Error(w, "テンプレートの読み込みに失敗しました", http.StatusInternalServerError)
		return
	}

	data := struct {
		Username string
		UniversityName string
		CampusName string
	}{
		Username: username,
		UniversityName: universityName,
		CampusName: campusName,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "テンプレートの実行に失敗しました", http.StatusInternalServerError)
	}
}

func saverestaurantHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        session, err := store.Get(r, "session-name")
        if err != nil {
            http.Error(w, "セッションの取得に失敗しました", http.StatusInternalServerError)
            return
        }

        email, ok := session.Values["email"].(string)
        if !ok {
            http.Error(w, "セッションにメールアドレスがありません", http.StatusInternalServerError)
            return
        }

        // ユーザーUIDを取得
        var userUID, campusUID string
        err = db.QueryRow("SELECT user_uid, campus_uid FROM User WHERE email = ?", email).Scan(&userUID, &campusUID)
        if err != nil {
            http.Error(w, "ユーザー情報の取得に失敗しました", http.StatusInternalServerError)
            return
        }

        // フォームからデータを取得
        restaurantName := r.FormValue("restaurant_name")
        category := r.FormValue("category")
        distance := r.FormValue("distance")
        crowdedLevel := r.FormValue("crowded_level")
        speed := r.FormValue("speed")
        foodQuantity := r.FormValue("food_quantity")
        price := r.FormValue("price")
        isForGroup := r.FormValue("is_for_group")
        detail := r.FormValue("detail")
        address := r.FormValue("address")

        // データベースに挿入
        query := `INSERT INTO Restaurants (restaurant_uid, restaurant_name, category, campus_uid, distance, crowded_level, speed, food_quantity, price, is_for_group, detail, address, recommended_by) 
                  VALUES (UUID(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        _, err = db.Exec(query, restaurantName, category, campusUID, distance, crowdedLevel, speed, foodQuantity, price, isForGroup, detail, address, userUID)
        if err != nil {
            http.Error(w, "レストラン情報の保存に失敗しました", http.StatusInternalServerError)
            return
        }

        // 成功した場合、リスト画面にリダイレクト
        http.Redirect(w, r, "/recommendlist", http.StatusSeeOther)
    } else {
        http.Error(w, "無効なリクエストです", http.StatusMethodNotAllowed)
    }
}


func recommendlistHandler(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, "セッションの取得に失敗しました", http.StatusInternalServerError)
        return
    }

    email, ok := session.Values["email"].(string)
    if !ok {
        http.Error(w, "セッションにメールアドレスがありません", http.StatusInternalServerError)
        return
    }

    // ユーザーのusername, universityName, campusNameを取得
    var username, universityName, campusName string
    query := `SELECT u.username, uni.universityname, c.campusname 
              FROM User u 
              JOIN University uni ON u.university_uid = uni.university_uid 
              JOIN Campus c ON u.campus_uid = c.campus_uid 
              WHERE u.email = ?`
    err = db.QueryRow(query, email).Scan(&username, &universityName, &campusName)
    if err != nil {
        http.Error(w, "ユーザー情報の取得に失敗しました", http.StatusInternalServerError)
        return
    }

    // Restaurantsテーブルからレストラン情報を取得
    var campusUID string
    err = db.QueryRow("SELECT campus_uid FROM User WHERE email = ?", email).Scan(&campusUID)
    if err != nil {
        http.Error(w, "キャンパスUIDの取得に失敗しました", http.StatusInternalServerError)
        return
    }

    rows, err := db.Query(`
        SELECT restaurant_name, category, address, distance, crowded_level, speed, food_quantity, price, is_for_group, detail 
        FROM Restaurants 
        WHERE campus_uid = ?`, campusUID)
    if err != nil {
        http.Error(w, "レストラン情報の取得に失敗しました", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var restaurants []struct {
        Name         string
        Category     string
        Address      string
        Distance     int
        CrowdedLevel int
        Speed        int
        FoodQuantity int
        Price        int
        IsForGroup   bool
        Detail       string // 追加: 詳細フィールドを取得
    }

    for rows.Next() {
        var restaurant struct {
            Name         string
            Category     string
            Address      string
            Distance     int
            CrowdedLevel int
            Speed        int
            FoodQuantity int
            Price        int
            IsForGroup   bool
            Detail       string
        }
        err := rows.Scan(&restaurant.Name, &restaurant.Category, &restaurant.Address, &restaurant.Distance, &restaurant.CrowdedLevel, &restaurant.Speed, &restaurant.FoodQuantity, &restaurant.Price, &restaurant.IsForGroup, &restaurant.Detail)
        if err != nil {
            http.Error(w, "データの読み込みに失敗しました", http.StatusInternalServerError)
            return
        }
        restaurants = append(restaurants, restaurant)
    }

    // テンプレートをパース
    tmpl, err := template.ParseFiles("./screen/recommendlist.html")
    if err != nil {
        http.Error(w, "テンプレートの読み込みに失敗しました", http.StatusInternalServerError)
        return
    }

    // テンプレートに渡すデータ
    data := struct {
        Username       string
        UniversityName string
        CampusName     string
        Restaurants    []struct {
            Name         string
            Category     string
            Address      string
            Distance     int
            CrowdedLevel int
            Speed        int
            FoodQuantity int
            Price        int
            IsForGroup   bool
            Detail       string // 詳細情報を追加
        }
    }{
        Username:       username,
        UniversityName: universityName,
        CampusName:     campusName,
        Restaurants:    restaurants,
    }

    // テンプレートを実行
    err = tmpl.Execute(w, data)
    if err != nil {
        log.Printf("テンプレートの実行に失敗しました: %v", err)
        http.Error(w, "テンプレートの実行に失敗しました", http.StatusInternalServerError)
    }
}



func makelistHandler(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "session-name")
    if err != nil {
        http.Error(w, "セッションの取得に失敗しました", http.StatusInternalServerError)
        return
    }

    email, ok := session.Values["email"].(string)
    if !ok {
        http.Error(w, "セッションにメールアドレスがありません", http.StatusInternalServerError)
        return
    }

    // ユーザー名を取得
    var username string
    err = db.QueryRow("SELECT username FROM User WHERE email = ?", email).Scan(&username)
    if err != nil {
        http.Error(w, "ユーザー情報の取得に失敗しました", http.StatusInternalServerError)
        return
    }

    // テンプレートをパース
    tmpl, err := template.ParseFiles("./screen/makelist.html")
    if err != nil {
        http.Error(w, "テンプレートの読み込みに失敗しました", http.StatusInternalServerError)
        return
    }

    // テンプレートに渡すデータ
    data := struct {
        Username string
    }{
        Username: username,
    }

    // テンプレートを実行
    err = tmpl.Execute(w, data)
    if err != nil {
        http.Error(w, "テンプレートの実行に失敗しました", http.StatusInternalServerError)
    }
}

func main() {
    initDB()

    http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))
    http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/search-universities", searchUniversitiesHandler) 
	http.HandleFunc("/get-university-uid", getUniversityUIDHandler)  
    http.HandleFunc("/get-campuses", getCampusesByUniversityUIDHandler)  
    http.HandleFunc("/confirm", confirmHandler)
    http.HandleFunc("/register", registerUserHandler)
    http.HandleFunc("/login", loginhandler)
    http.HandleFunc("/postscreen", postscreenHandler)
    http.HandleFunc("/post", postMessageHandler)
    http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/makelist", makelistHandler)
    http.HandleFunc("/recommendlist", recommendlistHandler)
    http.HandleFunc("/saverestaurant", saverestaurantHandler)

    fmt.Println("サーバーを開始しました")
    err := http.ListenAndServe(":8080", nil)
    if err != nil {
        fmt.Println("サーバーの起動に失敗しました:", err)
    }
}
