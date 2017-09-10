package backend_utils

import (
	"encoding/json"
	"os"
	"log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"github.com/grpc-ecosystem/go-grpc-middleware/validator"
	"io/ioutil"
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/net/context"
	"fmt"
	"google.golang.org/grpc/metadata"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
)

type GrpcServerConfig struct {

	// Use TLS for encryption
	UseTls 		bool	`json:"use_tls"`
	CertFile 	string	`json:"cert_file"`
	KeyFile 	string 	`json:"key_file"`

	// Use JWT based authentication
	UseJwt		bool	`json:"use_jwt"`
	PubKeyFile	string	`json:"pub_key"`
	PrivKeyFile	string	`json:"pub_key"`

	UseValidator	bool	`json:"use_validator"`
	Port		int32	`json:"port"`
	LogLevel	int32	`json:"log_level"`

	// Non-json fields
	PubKey		*rsa.PublicKey
	PrivKey		*rsa.PrivateKey
	auth_func_set	bool
	auth_func 	func (context.Context) (context.Context, error)
}

type GrpcClientConfig struct {

	// Use TLS for encryption
	UseTls 			bool	`json:"use_tls"`
	CertFile 		string	`json:"cert_file"`

	ServerHostOverride 	string	`json:"server_host_override"`
	ServerAddr 		string	`json:"server_addr"`
}

type PostgresDBConfig struct {
	Username	string	`json:"username"`
	Password	string	`json:"password"`
	DBName		string	`json:"db_name"`
}

type EmailerConfig struct {
	SmtpAddr	string	`json:"smtp_addr"`
	SmtpPort	int	`json:"smtp_port"`
	Username	string	`json:"username"`
	Password	string	`json:"password"`
}

type Configurations struct {
	ServerConfig	GrpcServerConfig 	`json:"server_config"`
	ClientConfig 	[]GrpcServerConfig	`json:"client_config"`
	PostgresDB	PostgresDBConfig	`json:"postgres_db"`
	Emailer		EmailerConfig		`json:"emailer"`
}

func ReadConfFile(file_path string) (*Configurations, error) {

	file, err := os.Open(file_path)
	if err != nil {
		return nil, err
	}

	conf := new(Configurations)

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&conf)
	if err != nil {
		return nil, err
	}

	log.Printf("Read Configurations:%v\n", conf)

	return conf, nil
}

func ParseJWTpubKeyFile(file_path string) (*rsa.PublicKey, error) {
	key, err := ioutil.ReadFile(file_path)
	if err != nil {
		log.Printf("Failed reading JWT public key file.ERR:%s\n", err)
		return nil, err
	}
	pub_key, err := jwt.ParseRSAPublicKeyFromPEM(key)
	if err != nil {
		log.Printf("Failed parsing public key.ERR:%s\n", err)
		return nil, err
	}
	return pub_key, nil
}

func ParseJWTprivKeyFile(file_path string) (*rsa.PrivateKey, error) {
	key, err := ioutil.ReadFile(file_path)
	if err != nil {
		log.Printf("Failed reading JWT public key file.ERR:%s\n", err)
		return nil, err
	}
	priv_key, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		log.Printf("Failed parsing public key.ERR:%s\n", err)
		return nil, err
	}
	return priv_key, nil
}

func validateToken(token string, publicKey *rsa.PublicKey) (*jwt.Token, error) {
	jwtToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			log.Printf("Unexpected signing method: %v", t.Header["alg"])
			return nil, fmt.Errorf("invalid token")
		}
		return publicKey, nil
	})
	if err == nil && jwtToken.Valid {
		return jwtToken, nil
	}
	return nil, err
}

func (c *Configurations) DefaultAuthFunction(ctx context.Context) (context.Context, error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrUnauthenticated("Metadata corrupted")
	}

	jwtToken, ok := md["authorization"]
	if !ok {
		return nil, ErrUnauthenticated("Authorization header not present")
	}

	token, err := validateToken(jwtToken[0], c.ServerConfig.PubKey)
	if err != nil {
		return nil, ErrUnauthenticated("Invalid token")
	}

	newCtx := context.WithValue(ctx, "jwt_token", token)
	return newCtx, nil
}

func (c *Configurations) WithAuthFunc(auth func (context.Context) (context.Context, error)) {

	if !c.ServerConfig.UseJwt {
		log.Fatal("Public key file not specified in config.")
	}

	var err error
	c.ServerConfig.PubKey, err = ParseJWTpubKeyFile(c.ServerConfig.PubKeyFile)
	if err != nil {
		log.Fatalf("Failed parsing public key.ERR:%s\n", err)
	}

	c.ServerConfig.auth_func = auth
	c.ServerConfig.auth_func_set = true
}

func (c *Configurations) withDefaultAuthFunc() {

	if !c.ServerConfig.UseJwt {
		log.Fatal("Public key file not specified in config.")
	}

	var err error
	c.ServerConfig.PubKey, err = ParseJWTpubKeyFile(c.ServerConfig.PubKeyFile)
	if err != nil {
		log.Fatalf("Failed parsing public key.ERR:%s\n", err)
	}

	c.ServerConfig.auth_func = c.DefaultAuthFunction
	c.ServerConfig.auth_func_set = true
}

func (c *Configurations) GetServerOpts() ([]grpc.ServerOption, error) {

	var opts []grpc.ServerOption

	if c.ServerConfig.UseTls {
		creds, err := credentials.NewServerTLSFromFile(c.ServerConfig.CertFile, c.ServerConfig.KeyFile)
		if err != nil {
			log.Printf("Failed creating TLS credentials.ERR:%s\n", err)
			return opts, err
		}

		opts = append(opts, grpc.Creds(creds))
	}

	if c.ServerConfig.UseJwt {
		if !c.ServerConfig.auth_func_set {
			c.withDefaultAuthFunc()
		}
		opts = append(opts, grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(c.ServerConfig.auth_func)))
		opts = append(opts, grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(c.ServerConfig.auth_func)))

	}

	if c.ServerConfig.UseValidator {
		opts = append(opts, grpc.StreamInterceptor(grpc_validator.StreamServerInterceptor()))
		opts = append(opts, grpc.UnaryInterceptor(grpc_validator.UnaryServerInterceptor()))
	}

	return opts, nil
}
