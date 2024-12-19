package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"database/sql"
	"os"

	"github.com/Osirous/Chirpy/Chirpy/internal/auth"
	"github.com/Osirous/Chirpy/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiHandler struct{}

type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
	jwtSecret      string
}

type User struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"-"` // - means do not include this field in client JSON responses.
	Token          string    `json:"token"`
	RefreshToken   string    `json:"refresh_token"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (apiHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	count := cfg.fileserverHits.Load()
	w.Write([]byte(fmt.Sprintf(metricsTemplate, count)))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	isDev := os.Getenv("PLATFORM")
	if isDev != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := cfg.DB.DeleteAllUsers(r.Context())
	if err != nil {
		http.Error(w, "Failed to reset users", http.StatusInternalServerError)
		return
	}

	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) queryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	chirpIDStr := r.PathValue("chirpID")
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		http.Error(w, "Invalid UUID format", http.StatusBadRequest)
		return
	}

	chirp, err := cfg.DB.GetSingleChirp(r.Context(), chirpID)
	if err != nil {
		http.Error(w, "Chirp not found!", http.StatusNotFound)
		return
	}

	chirpResponse := Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}

	data, err := json.Marshal(chirpResponse)
	if err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)

}

// Handle those chirps!

func (cfg *apiConfig) chirpHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	// handle getting chirps here
	case http.MethodGet:
		getChirps, err := cfg.DB.GetChirps(r.Context())
		if err != nil {
			http.Error(w, "Failed to retrieve chirps", http.StatusInternalServerError)
			return
		}

		chirpResponses := []Chirp{}

		for _, chirp := range getChirps {
			chirpResponse := Chirp{
				ID:        chirp.ID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    chirp.UserID,
			}
			chirpResponses = append(chirpResponses, chirpResponse)
		}

		data, err := json.Marshal(chirpResponses)
		if err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return

	// handle create chirps here
	case http.MethodPost:

		type parameters struct {
			Body string `json:"body"`
		}

		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Unauthorized access: %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
		if err != nil {
			log.Printf("Unauthorized access: %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err = decoder.Decode(&params)
		if err != nil {
			// an error will be thrown if the JSON is invalid or has the wrong types
			// any missing fields will simply have their values in the struct set to their zero value
			log.Printf("Error decoding parameters: %s", err)
			w.WriteHeader(500)
			return
		}

		length := len(params.Body)
		if length > 140 {
			http.Error(w, "Chirp is too long", http.StatusBadRequest)
		} else {
			restricted := restrictFreeSpeech(params.Body)
			w.Header().Set("Content-Type", "application/json")

			chirpParams := database.CreateChirpParams{
				Body:   restricted,
				UserID: userID,
			}

			chirp, err := cfg.DB.CreateChirp(r.Context(), chirpParams)
			if err != nil {
				http.Error(w, "Failed to create chirp", http.StatusInternalServerError)
				return
			}

			newChirp := Chirp{
				ID:        chirp.ID,
				CreatedAt: chirp.CreatedAt,
				UpdatedAt: chirp.UpdatedAt,
				Body:      chirp.Body,
				UserID:    userID,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(newChirp)

		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

}

// the anti-american constitution goings on here is absurd and should be abolished immediately!

func restrictFreeSpeech(body string) string {
	restrictedBody := body

	badWords := []string{"kerfuffle", "sharbert", "fornax"}

	lowercaseBody := strings.ToLower(body)

	for _, word := range badWords {
		index := strings.Index(lowercaseBody, word)
		if index == -1 {
			continue
		}

		restrictedBody = restrictedBody[:index] + "****" + restrictedBody[index+len(word):]
		lowercaseBody = lowercaseBody[:index] + "****" + lowercaseBody[index+len(word):]
	}

	return restrictedBody
}

func (cfg *apiConfig) userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:

	case http.MethodPost:

		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			http.Error(w, "Error processing password", http.StatusInternalServerError)
			return
		}

		userParams := database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashedPassword,
		}

		user, err := cfg.DB.CreateUser(r.Context(), userParams)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		responseUser := User{
			ID:        user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email:     user.Email,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(responseUser)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case http.MethodPost:

		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		getUser, err := cfg.DB.GetUserByEmail(r.Context(), params.Email)
		if err != nil {
			http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
			return
		}

		err = auth.CheckPasswordHash(getUser.HashedPassword, params.Password)
		if err != nil {
			http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
			return
		}

		expiresIn := time.Hour // default 1 hour

		accessToken, err := auth.MakeJWT(getUser.ID, cfg.jwtSecret, expiresIn)
		if err != nil {
			http.Error(w, "Error creating token", http.StatusInternalServerError)
			return
		}

		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			http.Error(w, "Error creating refresh token", http.StatusInternalServerError)
			return
		}

		expiresAt := time.Now().AddDate(0, 0, 60) // 60 days from now

		rtParams := database.StoreRefreshTokenParams{
			Token:     refreshToken,
			UserID:    uuid.NullUUID{UUID: getUser.ID, Valid: true},
			ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
		}

		storedRefreshToken, err := cfg.DB.StoreRefreshToken(r.Context(), rtParams)
		if err != nil {
			http.Error(w, "Error storing refresh token", http.StatusInternalServerError)
			return
		}

		response := User{
			ID:           getUser.ID,
			CreatedAt:    getUser.CreatedAt,
			UpdatedAt:    getUser.UpdatedAt,
			Email:        getUser.Email,
			Token:        accessToken,
			RefreshToken: storedRefreshToken.Token,
		}

		data, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func main() {

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	// sql db stuff
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	dbQueries := database.New(db)

	// api config
	apiCfg := &apiConfig{
		DB:        dbQueries,
		jwtSecret: os.Getenv("JWT_SECRET"),
	}

	// chirpy server code
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler{})
	mux.HandleFunc("/api/healthz", healthHandler)
	mux.HandleFunc("/api/users", apiCfg.userHandler)
	mux.HandleFunc("/api/login", apiCfg.loginHandler)
	mux.HandleFunc("/admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("/admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("/api/chirps", apiCfg.chirpHandler)
	mux.HandleFunc("/api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("/api/revoke", apiCfg.revokedHandler)
	mux.HandleFunc("/api/chirps/{chirpID}", apiCfg.queryHandler)
	fileServer := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fileServer))

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

}

func (cfg *apiConfig) revokedHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:

		// Extract refresh token from request header
		refreshToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Unauthorized refresh access: %s", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Revoke token here

		_, err = cfg.DB.RevokeToken(r.Context(), refreshToken)
		if err != nil {
			http.Error(w, "Unabled to revoke token", http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:

		// Extract refresh token from request header
		refreshToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Could not find token: %s", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Check that the token exists in your data store
		user, err := cfg.DB.GetUserFromRefreshToken(r.Context(), refreshToken)
		if err != nil {
			http.Error(w, "Invalid or missing refresh token", http.StatusUnauthorized)
			return
		}

		// Issue a new access token
		newAccessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret, time.Hour)
		if err != nil {
			http.Error(w, "Error creating new token", http.StatusInternalServerError)
			return
		}

		// Respond with the new access token
		response := struct {
			Token string `json:"token"`
		}{
			Token: newAccessToken,
		}

		data, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

}

/*

|===== Constants used throughout Main.go =====|

*/
// HTML for metricsHandler function
const metricsTemplate = `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`

// Delete all Users from DB
// Why was this even added! Why would we want to delete all users!
const deleteAllUsers = `DELETE FROM users`
