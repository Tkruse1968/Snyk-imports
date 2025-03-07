package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Database configuration
const (
	host   = "localhost"
	port   = 5432
	dbname = "github_scan"
	dbUser = "POSTGRES_USER"
	dbPass = "POSTGRES_PASSWORD"
)

// Snyk API configuration
const (
	snykAPIEndpoint = "https://snyk.io/api/v1"
	snykImportLimit = 5 // Maximum concurrent imports
)

type Repository struct {
	ID     int
	Owner  string
	Name   string
	Branch string
}

type SnykImportPayload struct {
	Target struct {
		Owner  string `json:"owner"`
		Name   string `json:"name"`
		Branch string `json:"branch"`
	} `json:"target"`
	Files []struct {
		Path string `json:"path"`
	} `json:"files"`
}

type ImportResult struct {
	RepoID     int
	Owner      string
	Name       string
	FilePath   string
	Success    bool
	Error      string
	ImportedAt time.Time
}

func initDB() (*sql.DB, error) {
	user := os.Getenv(dbUser)
	password := os.Getenv(dbPass)

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	// Create imports results table if it doesn't exist
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS snyk_imports (
            id SERIAL PRIMARY KEY,
            repo_id INTEGER NOT NULL,
            repo_owner VARCHAR(255) NOT NULL,
            repo_name VARCHAR(255) NOT NULL,
            file_path TEXT NOT NULL,
            success BOOLEAN NOT NULL,
            error_message TEXT,
            imported_at TIMESTAMP NOT NULL,
            UNIQUE(repo_owner, repo_name, file_path)
        )
    `)
	return db, err
}

func getRepositoriesFromDB(db *sql.DB) ([]Repository, error) {
	rows, err := db.Query(`
        SELECT id, owner, name, default_branch 
        FROM repositories 
        WHERE active = true
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []Repository
	for rows.Next() {
		var repo Repository
		err := rows.Scan(&repo.ID, &repo.Owner, &repo.Name, &repo.Branch)
		if err != nil {
			return nil, err
		}
		repos = append(repos, repo)
	}
	return repos, nil
}

func importToSnyk(repo Repository, filePath string, snykToken string) error {
	payload := SnykImportPayload{}
	payload.Target.Owner = repo.Owner
	payload.Target.Name = repo.Name
	payload.Target.Branch = repo.Branch
	payload.Files = []struct {
		Path string `json:"path"`
	}{{Path: filePath}}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", snykAPIEndpoint+"/import/git", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "token "+snykToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Snyk API returned status: %d", resp.StatusCode)
	}

	return nil
}

func writeImportResult(db *sql.DB, result ImportResult) error {
	_, err := db.Exec(`
        INSERT INTO snyk_imports 
        (repo_id, repo_owner, repo_name, file_path, success, error_message, imported_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (repo_owner, repo_name, file_path) 
        DO UPDATE SET 
            success = EXCLUDED.success,
            error_message = EXCLUDED.error_message,
            imported_at = EXCLUDED.imported_at
    `, result.RepoID, result.Owner, result.Name, result.FilePath,
		result.Success, result.Error, result.ImportedAt)
	return err
}

func main() {
	// Initialize database
	db, err := initDB()
	if err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		return
	}
	defer db.Close()

	// Get environment variables
	githubToken := os.Getenv("GITHUB_TOKEN")
	snykToken := os.Getenv("SNYK_TOKEN")
	if githubToken == "" || snykToken == "" {
		fmt.Println("Please set GITHUB_TOKEN and SNYK_TOKEN environment variables")
		return
	}

	// Get repositories from database
	repos, err := getRepositoriesFromDB(db)
	if err != nil {
		fmt.Printf("Failed to get repositories: %v\n", err)
		return
	}

	// Create channels for processing
	resultsChan := make(chan ImportResult, 100)

	// Create rate limiter for Snyk API
	limiter := rate.NewLimiter(rate.Every(time.Second), snykImportLimit)

	// Start worker pool for processing imports
	var wg sync.WaitGroup
	for _, repo := range repos {
		wg.Add(1)
		go func(repo Repository) {
			defer wg.Done()

			// Get dependency files from scan_results table
			rows, err := db.Query(`
                SELECT file_path, file_type 
                FROM scan_results 
                WHERE repo_owner = $1 AND repo_name = $2
            `, repo.Owner, repo.Name)
			if err != nil {
				fmt.Printf("Error querying scan results: %v\n", err)
				return
			}
			defer rows.Close()

			for rows.Next() {
				var filePath, fileType string
				if err := rows.Scan(&filePath, &fileType); err != nil {
					fmt.Printf("Error scanning row: %v\n", err)
					continue
				}

				// Wait for rate limiter
				err = limiter.Wait(context.Background())
				if err != nil {
					fmt.Printf("Rate limiter error: %v\n", err)
					continue
				}

				// Import to Snyk
				err = importToSnyk(repo, filePath, snykToken)

				result := ImportResult{
					RepoID:     repo.ID,
					Owner:      repo.Owner,
					Name:       repo.Name,
					FilePath:   filePath,
					Success:    err == nil,
					ImportedAt: time.Now().UTC(),
				}

				if err != nil {
					result.Error = err.Error()
				}

				resultsChan <- result
			}
		}(repo)
	}

	// Start result writer
	var wgWriter sync.WaitGroup
	wgWriter.Add(1)
	go func() {
		defer wgWriter.Done()
		for result := range resultsChan {
			if err := writeImportResult(db, result); err != nil {
				fmt.Printf("Failed to write import result: %v\n", err)
			}
		}
	}()

	// Wait for all imports to complete
	wg.Wait()
	close(resultsChan)

	// Wait for all results to be written
	wgWriter.Wait()
}
