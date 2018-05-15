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
	"database/sql"
	"errors"
	"github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"runtime/debug"
)

type GrpcServerConfig struct {

	// Use TLS for encryption
	UseTls 		bool	`json:"use_tls"`
	CertFile 	string	`json:"cert_file"`
	KeyFile 	string 	`json:"key_file"`

	// Use JWT based authentication
	UseJwt		bool	`json:"use_jwt"`
	PubKeyFile	string	`json:"pub_key"`
	PrivKeyFile	string	`json:"priv_key"`

	UseValidator	bool	`json:"use_validator"`
	UseRecovery	bool	`json:"use_recovery"`
	Port		int32	`json:"port"`
	LogLevel	int32	`json:"log_level"`

	// Non-json fields
	PubKey		*rsa.PublicKey
	PrivKey		*rsa.PrivateKey
	auth_func_set	bool
	auth_func 	func (context.Context) (context.Context, error)
	recv_func_set	bool
	recv_func 	grpc_recovery.RecoveryHandlerFunc
}

type GrpcClientConfig struct {
	// Name of the service for which client config is.
	SvcName			string  `json:"svc_name"`
	// Use TLS for encryption
	UseTls 			bool	`json:"use_tls"`
	CertFile 		string	`json:"cert_file"`

	UseJwt			bool	`json:"use_jwt"`

	ServerHostOverride 	string	`json:"server_host_override"`
	ServerAddr 		string	`json:"server_addr"`

	// Non-json fields
	JwtToken		string
	pool			*RpcClientPool
}

type PostgresDBConfig struct {
	Hostname	string	`json:"hostname"`
	Port		int	`json:"port"`
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

type DumbDBConfig struct {
	DBName		string	`json:"db_name"`
	DBPath		string	`json:"db_path"`
}

type LockerConfig struct {
	Handler 	string	 `json:"handler"`
	Address 	[]string `json:"address"`
}

type FsConfig struct {
	RootPath 	string `json:"root_path"`
}

type ProxyConfig struct {
	Endpoint	string	`json:"endpoint"`
	Port		string	`json:"port"`
}

type PaymentProvider struct {
	Provider   string `json:"provider"`
	Secret     string `json:"secret"`
	MerchId    string `json:"merch_id"`
	PublicKey  string `json:"pub_key"`
	PrivateKey string `json:"priv_key"`
}

type RedisConfig struct {
	Hostname	string	`json:"hostname"`
	Port		int	`json:"port"`
	DBName		string	`json:"db_name"`
}

type CDNHostInfo struct {
	Hostname	string  `json:"hostname`
	Port		string  `json:"port"`
	BaseURL		string  `json:"base_url"`
	Protocol	string	`json:"protocol"`
}

type Configurations struct {
	ServerConfig	GrpcServerConfig 	`json:"server_config"`
	ClientConfig 	[]GrpcClientConfig	`json:"client_config"`
	PostgresDB	PostgresDBConfig	`json:"postgres_db"`
	DumbDB 		DumbDBConfig		`json:"dumb_db"`
	Emailer		EmailerConfig		`json:"emailer"`
	Locker		LockerConfig		`json:"locker_config"`
	FileStoreConfig FsConfig		`json:"fs_config"`
	Proxy 		ProxyConfig		`json:"proxy_config"`
	CDNInfo		CDNHostInfo		`json:"cdn_config"`
	Payments 	[]PaymentProvider	`json:"payment_providers"`
	RedisDB 	RedisConfig		`json:"redis_config"`
	//Non-json fields.
	client_map	map[string] *RpcClientPool
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
			return nil, fmt.Errorf("Invalid token %s", token)
		}
		return publicKey, nil
	})
	if err == nil && jwtToken.Valid {
		return jwtToken, nil
	}
	return nil, err
}

func (c *Configurations) GetClientConfig(svc_name string) *GrpcClientConfig {
	for i := range c.ClientConfig {
		if c.ClientConfig[i].SvcName == svc_name {
			return &c.ClientConfig[i]
		}
	}
	return nil
}

func (c *Configurations) CreateClientPool(heartbeat_map map[string] func(*grpc.ClientConn) error, conn_per_ep int) error {

	ep_map := make(map[string] []interface{}, 1)

	for i := range c.ClientConfig {
		if val, ok := ep_map[c.ClientConfig[i].SvcName]; ok {
			val = append(val, c.ClientConfig[i])
		} else {
			ep_map[c.ClientConfig[i].SvcName] = []interface{}{c.ClientConfig[i]}
		}
	}

	c.client_map = make(map[string] *RpcClientPool, len(ep_map))

	for k,v := range ep_map {
		val, ok := heartbeat_map[k]
		if !ok {
			return errors.New("Heartbeat function missing for Service " + k)
		}
		c.client_map[k] = NewRpcClientPool(val, v, conn_per_ep, os.Stdout)
		if c.client_map[k] == nil {
			return errors.New("Failed to create conn pool for Service " + k)
		}
	}
	return nil
}

func (c *Configurations) GetPooledConn(svc_name string) *grpc.ClientConn {
	val, ok := c.client_map[svc_name]
	if !ok {
		return nil
	}
	if !val.pool_created {
		return nil
	}
	return val.Get()
}

func (c *Configurations) PooledConnDone(svc_name string, conn *grpc.ClientConn) {
	val, ok := c.client_map[svc_name]
	if !ok {
		panic("unexpected connection returned to pool.")
	}
	val.Put(conn)
}

func (c *GrpcServerConfig) DefaultAuthFunction(ctx context.Context) (context.Context, error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrUnauthenticated("Metadata corrupted")
	}

	jwtToken, ok := md["authorization"]
	if !ok {
		return nil, ErrUnauthenticated("Authorization header not present")
	}

	token, err := validateToken(jwtToken[0], c.PubKey)
	if err != nil {
		return nil, ErrUnauthenticated("Invalid token")
	}

	newCtx := context.WithValue(ctx, "jwt_token", token)
	return newCtx, nil
}

func DefaultRecovery(arg interface{}) (ret_err error) {
	debug.PrintStack()

	switch arg.(type) {
	case string:
		ret_err = ErrInternal(arg.(string))
	default:
		ret_err = ErrUnknown("Server encountered unknown error.")
	}
	log.Println("Service Recovery handler. Returning error:" + ret_err.Error())
	return
}

func (c *GrpcServerConfig) WithAuthFunc(auth func (context.Context) (context.Context, error)) {

	if !c.UseJwt {
		log.Fatal("Public key file not specified in config.")
	}

	var err error
	c.PubKey, err = ParseJWTpubKeyFile(c.PubKeyFile)
	if err != nil {
		log.Fatalf("Failed parsing public key.ERR:%s\n", err)
	}

	c.auth_func = auth
	c.auth_func_set = true
}

func (c *GrpcServerConfig) withDefaultAuthFunc() {

	var err error
	c.PubKey, err = ParseJWTpubKeyFile(c.PubKeyFile)
	if err != nil {
		log.Fatalf("Failed parsing public key.ERR:%s\n", err)
	}

	c.auth_func = c.DefaultAuthFunction
	c.auth_func_set = true
}

func (c *GrpcServerConfig) WithRecvFunc(recv grpc_recovery.RecoveryHandlerFunc) {

	if !c.UseRecovery {
		log.Fatal("Use of recovery not specified in config.")
	}

	c.recv_func = recv
	c.recv_func_set = true
}

func (c *GrpcServerConfig) withDefaultRecvFunc() {
	c.recv_func = DefaultRecovery
	c.recv_func_set = true
}

func (c *GrpcServerConfig) GetServerOpts() ([]grpc.ServerOption, error) {

	var opts []grpc.ServerOption

	if c.UseTls {
		creds, err := credentials.NewServerTLSFromFile(c.CertFile, c.KeyFile)
		if err != nil {
			log.Printf("Failed creating TLS credentials.ERR:%s\n", err)
			return opts, err
		}

		opts = append(opts, grpc.Creds(creds))
	}

	var u_interceptors []grpc.UnaryServerInterceptor
	var s_interceptors []grpc.StreamServerInterceptor

	if c.UseJwt {
		if !c.auth_func_set {
			c.withDefaultAuthFunc()
		}
		u_interceptors = append(u_interceptors, grpc_auth.UnaryServerInterceptor(c.auth_func))
		s_interceptors = append(s_interceptors, grpc_auth.StreamServerInterceptor(c.auth_func))

	}

	if c.UseValidator {
		u_interceptors = append(u_interceptors, grpc_validator.UnaryServerInterceptor())
		s_interceptors = append(s_interceptors, grpc_validator.StreamServerInterceptor())
	}

	if c.UseRecovery {
		if !c.recv_func_set {
			c.withDefaultRecvFunc()
		}
		u_interceptors = append(u_interceptors, grpc_recovery.UnaryServerInterceptor(
									grpc_recovery.WithRecoveryHandler(c.recv_func)))
		s_interceptors = append(s_interceptors, grpc_recovery.StreamServerInterceptor(
									grpc_recovery.WithRecoveryHandler(c.recv_func)))
	}

	opts = append(opts, grpc_middleware.WithUnaryServerChain(u_interceptors...))
	opts = append(opts, grpc_middleware.WithStreamServerChain(s_interceptors...))

	return opts, nil
}

func (c *GrpcServerConfig) Valid() bool {
	if c.Port == 0 {
		return false;
	}
	if ! (c.LogLevel > 0) {
		return false;
	}
	if c.UseJwt {
		if len(c.PubKeyFile) == 0 {
			return false;
		}
	}
	return true;
}

type JwtCredentials struct {
	credentials.PerRPCCredentials
	token string
}

func NewJwtCredentials(tok string) *JwtCredentials {
	creds := new(JwtCredentials)
	creds.token = tok
	return creds
}

// GetRequestMetadata gets the current request metadata
func (j *JwtCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {

	return map[string]string{
		"authorization": j.token,
	}, nil
}

// Jwt does not RequireTransportSecurity
func (j *JwtCredentials) RequireTransportSecurity() bool { return false }

func (c *GrpcClientConfig) WithJWTToken(token string) *GrpcClientConfig {
	c.JwtToken = token
	return c
}

func (c *GrpcClientConfig) NewRPCConn() (*grpc.ClientConn, error) {

	opts, err := c.GetClientOpts()
	if err != nil {
		log.Printf("Failed to get client options. ERR:%s\n", err.Error())
		return nil, err
	}

	if !c.UseTls {
		opts = append(opts, grpc.WithInsecure())
	}

	conn, err := grpc.Dial(c.ServerAddr, opts...)
	if err != nil {
		log.Printf("Failed to dial. ERR:%s\n", err.Error())
		return nil, err
	}

	return conn, nil
}

func (c *GrpcClientConfig) GetClientOpts() ([]grpc.DialOption, error) {

	var opts []grpc.DialOption
	if c.UseTls {
		var sn string
		if c.ServerHostOverride != "" {
			sn = c.ServerHostOverride
		}

		var creds credentials.TransportCredentials
		if c.CertFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(c.CertFile, sn)
			if err != nil {
				log.Printf("Failed to create TLS credentials. ERR:%s\n", err.Error())
				return nil, err
			}
		} else {
			creds = credentials.NewClientTLSFromCert(nil, sn)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}

	if c.UseJwt {
		if len(c.JwtToken) == 0 {
			log.Println("Token not specified for JWT.")
			return nil, errors.New("Token not specified for use of JWT.")
		}
		opts = append(opts, grpc.WithPerRPCCredentials(NewJwtCredentials(c.JwtToken)))
	}

	return opts, nil
}

// Single client conn pool needs to be synchronized externally.
func (c *GrpcClientConfig) CreatePool(no_of_conn int, do_heartbeat func(*grpc.ClientConn) error) error {

	c.pool = NewRpcClientPool(do_heartbeat, []interface{}{c,}, no_of_conn, os.Stdout)
	if c.pool == nil {
		return errors.New("Failed to create pool")
	}
	return nil
}

func (c *GrpcClientConfig) GetPooledConn() *grpc.ClientConn {
	if ! c.pool.pool_created {
		panic("Pool has not been initialized yet.")
	}
	return c.pool.Get()
}

func (c *GrpcClientConfig) GiveupPooledConn(conn *grpc.ClientConn) {
	c.pool.Put(conn)
}

func (dbConf *PostgresDBConfig) OpenDB() (*sql.DB, error) {

	open_str := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		dbConf.Hostname, dbConf.Port, dbConf.Username, dbConf.Password, dbConf.DBName)

	dbP, err := sql.Open("postgres", open_str)
	if err == nil {
		// Open doesn't really do anything. Ping is where we will know.
		err = dbP.Ping()
	}

	if err != nil {
		log.Printf("Failed opening DB Err:%s", err.Error())
		return nil, err
	}

	log.Printf("Successfully connected to DB %s", dbConf.DBName)

	return dbP, nil
}

func (dbConf *PostgresDBConfig) CreatePQDB() (*sql.DB, error) {

	// If DB is already created, Use the same.
	dbP, err := dbConf.OpenDB()
	if err == nil {
		log.Println("DB has already been created.")
		return dbP, nil
	}

	// Connect to pq and create database.
	open_str := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable",
		dbConf.Hostname, dbConf.Port, dbConf.Username, dbConf.Password)

	dbP, err = sql.Open("postgres", open_str)
	if err != nil {
		log.Printf("Failed to open postgres. Open String:%s", open_str)
		return nil, err
	}

	err = dbP.Ping()
	if err != nil {
		log.Printf("Failed to ping postgres. Open String:%s", open_str)
		return nil, err
	}

	_, err = dbP.Exec("CREATE DATABASE " + dbConf.DBName)
	if err != nil {
		log.Printf("Failed to create postgres database %s", dbConf.DBName)
		return nil, err
	}

	// We need to make a new connection using the newly created database name.
	err = dbP.Close()
	if err != nil {
		log.Println("Failed to close postgres db after creation.")
		return nil, err
	}

	return dbConf.OpenDB()
}

func (dbConf *PostgresDBConfig) RemovePQDB() error {
	open_str := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=disable",
		dbConf.Hostname, dbConf.Port, dbConf.Username, dbConf.Password)

	dbP, err := sql.Open("postgres", open_str)
	if err != nil {
		log.Printf("Failed to open postgres. Open String:%s", open_str)
		return err
	}

	err = dbP.Ping()
	if err != nil {
		log.Printf("Failed to ping postgres. Open String:%s", open_str)
		return err
	}

	_, err = dbP.Exec("REVOKE CONNECT ON DATABASE " + dbConf.DBName + " FROM public")
	if err != nil {
		log.Printf("Failed to revoke database connections %s", dbConf.DBName)
		return err
	}

	_, err = dbP.Exec("SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity " +
		"WHERE pg_stat_activity.datname = '" + dbConf.DBName + "'")
	if err != nil {
		log.Printf("Failed to terminate database connections %s", dbConf.DBName)
		return err
	}

	_, err = dbP.Exec("DROP DATABASE " + dbConf.DBName)
	if err != nil {
		log.Printf("Failed to drop postgres database %s", dbConf.DBName)
		return err
	}

	err = dbP.Close()
	if err != nil {
		log.Println("Failed to close postgres db after creation.")
		return err
	}
	return nil
}

func (c *ProxyConfig) Valid() bool {
	if len(c.Endpoint) == 0 {
		return false
	}
	if len(c.Port) == 0 {
		return false;
	}
	return true;
}
