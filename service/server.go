package service

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"
)

type ConfigMessage struct {
	Env       string `yaml:"env" env:"ENV" env-default:"local"`
	AppSecret string `yaml:"app_secret" env:"APP_SECRET" env-required:"true"`

	Storage struct {
		Path string `yaml:"path" env:"STORAGE_PATH" env-required:"true"`
	} `yaml:"storage"`

	GRPC struct {
		Server struct {
			Port    int           `yaml:"port" env:"GRPC_PORT"`
			Timeout time.Duration `yaml:"timeout" env:"GRPC_TIMEOUT"`
		} `yaml:"server"`
	} `yaml:"grpc"`

	Clients struct {
		CRUD struct {
			Addr         string        `yaml:"addr" env:"CRUD_ADDR"`
			Timeout      time.Duration `yaml:"timeout" env:"CRUD_TIMEOUT"`
			RetriesCount int           `yaml:"retries_count" env:"CRUD_RETRIES_COUNT"`
		} `yaml:"crud"`
	} `yaml:"clients"`
}

type ConfigSSO struct {
	Env         string        `yaml:"env" env-default:"local"`
	StoragePath string        `yaml:"storage_path" env-required:"true"`
	TokenTTL    time.Duration `yaml:"token_ttl" env-required:"true"`

	GRPC struct {
		Port    int           `yaml:"port"`
		Timeout time.Duration `yaml:"timeout"`
	}

	Clients struct {
		SSO struct {
			Addr         string        `yaml:"addr" env:"SSO_ADDR"`
			Timeout      time.Duration `yaml:"timeout" env:"SSO_TIMEOUT"`
			RetriesCount int           `yaml:"retries_count" env:"SSO_RETRIES_COUNT"`
		} `yaml:"sso"`
	}
}

type Fabric struct {
	CRUD       *ClientCRUD
	SSO        *ClientSSO
	HttpServer *http.Server
}

func MustLoad(cnf1 *ConfigMessage, cnf2 *ConfigSSO, logger *slog.Logger) *Fabric {
	crudClient, err := NewCRUD(
		context.Background(),
		logger,
		cnf1.Clients.CRUD.Addr,
		cnf1.Clients.CRUD.Timeout,
		cnf1.Clients.CRUD.RetriesCount,
	)
	if err != nil {
		logger.Error("failed to initialize CRUD client", err)
		os.Exit(1)
	}
	logger.Info("ClientCRUD initialized")

	ssoClient, err := NewSSO(
		context.Background(),
		logger,
		cnf2.Clients.SSO.Addr,
		cnf2.Clients.SSO.Timeout,
		cnf2.Clients.SSO.RetriesCount,
	)
	if err != nil {
		logger.Error("failed to initialize SSO client", err)
		os.Exit(1)
	}
	logger.Info("ClientSSO initialized")

	httpServerMes := &http.Server{
		Addr:    ":8080",
		Handler: setupRoutes(ssoClient, crudClient, logger),
	}

	return &Fabric{
		HttpServer: httpServerMes,
		CRUD:       crudClient,
		SSO:        ssoClient,
	}
}

//go:embed all:front/*
var frontFS embed.FS

func setupRoutes(cliSso *ClientSSO, cliMes *ClientCRUD, logger *slog.Logger) *http.ServeMux {
	mux := http.NewServeMux()

	templates := template.Must(template.ParseFS(frontFS,
		"front/templates/index.html", "front/templates/login.html",
		"front/templates/register.html", "front/templates/profile.html",
	))

	// Обработчик статических файлов (CSS, JS)
	staticFS, _ := fs.Sub(frontFS, "front/static")
	fileServer := http.FileServer(http.FS(staticFS))

	mux.Handle("/static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Устанавливаем правильные MIME-типы
		switch {
		case strings.HasSuffix(r.URL.Path, ".css"):
			w.Header().Set("Content-Type", "text/css")
		case strings.HasSuffix(r.URL.Path, ".js"):
			w.Header().Set("Content-Type", "application/javascript")
		case strings.HasSuffix(r.URL.Path, ".png"):
			w.Header().Set("Content-Type", "image/png")
		}
		fileServer.ServeHTTP(w, r)
	})))

	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			email := r.FormValue("email")
			password := r.FormValue("password")
			username := r.FormValue("username")

			_, err := cliSso.Register(r.Context(), username, email, password)
			if err != nil {
				http.Error(w, "Register failed", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			w.Header().Set("Content-Type", "text/html")
			if err := templates.ExecuteTemplate(w, "register.html", nil); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	})

	// Страница входа
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			email := r.FormValue("email")
			password := r.FormValue("password")
			appID := int64(1)

			token, err := cliSso.Login(r.Context(), email, password, appID)
			if err != nil {
				http.Error(w, "Login failed", http.StatusUnauthorized)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:  "token",
				Value: token,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			w.Header().Set("Content-Type", "text/html")
			if err := templates.ExecuteTemplate(w, "login.html", nil); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	})

	//// Страница профиля
	//mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
	//	tokenCookie, err := r.Cookie("token")
	//	if err != nil {
	//		http.Redirect(w, r, "/login", http.StatusSeeOther)
	//		return
	//	}
	//
	//	TokenInfo := jwt.ValidateToken(tokenCookie.Value, os.Getenv("SECRET"))
	//	if TokenInfo.Error != nil {
	//		http.Error(w, "Invalid token", http.StatusUnauthorized)
	//		return
	//	}
	//
	//	if r.Method == "POST" {
	//		newName := r.FormValue("new_name")
	//		_, err := cliSso.ChangeName(r.Context(), TokenInfo.UserID, newName)
	//		if err != nil {
	//			http.Error(w, "Failed to change name", http.StatusInternalServerError)
	//			return
	//		}
	//		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	//	} else {
	//		w.Header().Set("Content-Type", "text/html")
	//		if err := templates.ExecuteTemplate(w, "profile.html", nil); err != nil {
	//			http.Error(w, err.Error(), http.StatusInternalServerError)
	//		}
	//	}
	//})

	// Serve index.html for root path
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if err := templates.ExecuteTemplate(w, "index.html", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// API endpoints for messages
	mux.HandleFunc("/api/messages", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				// Кука не найдена
				http.Error(w, "Token cookie not found", http.StatusBadRequest)
				return
			}
			// Другая ошибка
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		token := cookie.Value
		switch r.Method {
		case "POST":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			messageType := r.FormValue("type")
			content := r.FormValue("message-content")
			datetime := time.Now().String()[0:16]

			mid, err := cliMes.SentMessage(r.Context(), datetime, messageType, content, token)
			if err != nil {
				logger.Error("failed to send message", "error", err.Error())
				http.Error(w, "Failed to send message", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			fprintf, err := fmt.Fprintf(w, `{"status": "success", "message_id": %d, "datetime": %q}`, mid, datetime)
			if _ = fprintf; err != nil {
				return
			}

		case "GET":
			// Получаем все сообщения
			messages, err := cliMes.ShowAllMessages(r.Context(), token)
			if err != nil {
				logger.Error("failed to get messages",
					"error", err.Error())
				http.Error(w, "Failed to retrieve messages", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			response := map[string]interface{}{
				"status":   "success",
				"count":    len(messages),
				"messages": messages,
			}

			if err := json.NewEncoder(w).Encode(response); err != nil {
				logger.Error("failed to encode response",
					"error", err.Error())
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	return mux
}
