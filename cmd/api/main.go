//Luigi Acuna
//CMPS4191 Final Project
//Novemeber 23 2024

// Luigi Acuna
// CMPS4191 Test 3 Advanced Web Dev
// December 9 2024
package main

import (
	"context"
	"database/sql"
	"flag"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/luigiacunaUB/cmps4191-final-project/internal/data"
	"github.com/luigiacunaUB/cmps4191-final-project/internal/mailer"
)

const appVersion = "1.0.0"

type serverConfig struct {
	port       int    //port number to access signin page
	enviroment string //enviroment the signin page will be on
	db         struct {
		dsn string
	}
	limiter struct {
		rps     float64
		burst   int
		enabled bool
	}
	smtp struct {
		host     string
		port     int
		username string
		password string
		sender   string
	}
	cors struct {
		trustedOrigins []string
	}
}

type applicationDependencies struct {
	config           serverConfig
	logger           *slog.Logger
	BookModel        data.BookModel
	UserModel        data.UserModel
	TokenModel       data.TokenModel
	PermissionModel  data.PermissionModel
	ReviewModel      data.ReviewModel
	ReadingListModel data.ReadingListModel
	mailer           mailer.Mailer
	wg               sync.WaitGroup
}

func main() {
	var settings serverConfig

	//Settings ports and enviroment info
	flag.IntVar(&settings.port, "port", 4000, "Server Port")
	flag.StringVar(&settings.enviroment, "env", "development", "Enviroment(development|staging|)")
	flag.StringVar(&settings.db.dsn, "db-dsn", "postgres://bookadmin:admin123@localhost/bookstore?sslmode=disable", "PostgreSQL DSN")

	flag.Float64Var(&settings.limiter.rps, "limiter-rps", 2, "Rate Limiter maximum requests per second")
	flag.IntVar(&settings.limiter.burst, "limiter-burst", 5, "Rate Limiter maximum burst")
	flag.BoolVar(&settings.limiter.enabled, "limiter-enabled", true, "Enable rate limiter")
	//using an application called fake-SMTP, Mailtrap did not work
	flag.StringVar(&settings.smtp.host, "smtp-host", "192.168.7.123", "SMTP host")
	flag.IntVar(&settings.smtp.port, "smtp-port", 25, "SMTP port")
	flag.StringVar(&settings.smtp.username, "smtp-username", "", "SMTP username")
	flag.StringVar(&settings.smtp.username, "smtp-password", "", "SMTP password")
	flag.StringVar(&settings.smtp.sender, "smtp-sender", "Book Club <no-reply@bookclub.net>", "SMTP sender")

	flag.Func("cors-trusted-origins", "Trusted CORS origins (space seperated)",
		func(val string) error {
			settings.cors.trustedOrigins = strings.Fields(val)
			return nil
		})

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	db, err := openDB(settings)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	defer db.Close()
	logger.Info("database connection pool established")

	appInstance := &applicationDependencies{
		config:           settings,
		logger:           logger,
		BookModel:        data.BookModel{DB: db},
		UserModel:        data.UserModel{DB: db},
		TokenModel:       data.TokenModel{DB: db},
		PermissionModel:  data.PermissionModel{DB: db},
		ReviewModel:      data.ReviewModel{DB: db},
		ReadingListModel: data.ReadingListModel{DB: db},
		mailer:           mailer.New(settings.smtp.host, settings.smtp.port, settings.smtp.username, settings.smtp.password, settings.smtp.sender),
	}

	err = appInstance.serve()
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func openDB(settings serverConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", settings.db.dsn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}
