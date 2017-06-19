package backend_utils

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"errors"
)

type ConnEndpointInfo struct {
	Tls bool
	CertFile string
	ServerHostOverride string
	ServerAddr string
}

type RpcClientPool struct {
	doHeartBeat func(*grpc.ClientConn) error
	conn_pool chan *grpc.ClientConn
	conn_endpoints map[*grpc.ClientConn] int
	endpoints_map map[int] ConnEndpointInfo
	logr *LogUtil
	pool_created bool
}

func (r *RpcClientPool) createPool(endpoints []ConnEndpointInfo, conn_per_ep int) error {

	if len(endpoints) == 0 || conn_per_ep == 0 {
		return r.logr.Error(errors.New(INVALID_REQ), "Failed creating conn pool.")
	}

	r.conn_endpoints = make(map[*grpc.ClientConn] int, conn_per_ep * len(endpoints))
	r.conn_pool = make(chan *grpc.ClientConn, conn_per_ep * len(endpoints))
	r.endpoints_map = make(map[int] ConnEndpointInfo, len(endpoints))

	for i := range endpoints {
		r.endpoints_map[i] = endpoints[i]
		for j := 0; j < conn_per_ep; j++ {
			new_conn, err := r.newRPCConn(endpoints[i])
			if err != nil {
				r.logr.Error(err, "Failed creating connection Ep: %+v.", endpoints[i])
				continue
			}
			r.conn_endpoints[new_conn] = i
			r.Put(new_conn)
			r.logr.Info("Successfully created new connection to Ep:%+v", endpoints[i])
		}
	}
	if len(r.conn_endpoints) == 0 {
		return r.logr.Error(errors.New(FATAL_ERROR), "Failed creating any connection.")
	}
	r.pool_created = true
	return nil
}

func (r *RpcClientPool) newRPCConn(ep ConnEndpointInfo) (*grpc.ClientConn, error) {

	var opts []grpc.DialOption
	if ep.Tls {
		var sn string
		if ep.ServerHostOverride != "" {
			sn = ep.ServerHostOverride
		}
		var creds credentials.TransportAuthenticator
		if ep.CertFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(ep.CertFile, sn)
			if err != nil {
				return nil, r.logr.Error(err, "Failed to create TLS credentials.")
			}
		} else {
			creds = credentials.NewClientTLSFromCert(nil, sn)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(ep.ServerAddr, opts...)
	if err != nil {
		return nil, r.logr.Error(err, "Failed to dial.")
	}
	r.logr.Info("Established new RPC connection to %s.", ep.ServerAddr)
	return conn, nil
}

func NewRpcClientPool(do_heartbeat func(*grpc.ClientConn) error, endpoints []ConnEndpointInfo,
		      conn_per_ep int, logr *LogUtil) *RpcClientPool {
	client_pool := new(RpcClientPool)
	client_pool.doHeartBeat = do_heartbeat
	client_pool.logr = logr
	if err := client_pool.createPool(endpoints, conn_per_ep); err != nil {
		_ = client_pool.logr.Error(err, "Failed to create RPC pool.")
		return nil
	}
	return client_pool
}

func (r *RpcClientPool) Get() *grpc.ClientConn {
	if len(r.conn_endpoints) == 0 {
		r.logr.Error(errors.New(FATAL_ERROR), "No more connections in map.")
		return nil
	}
	var conn *grpc.ClientConn
	select {
	case conn = <- r.conn_pool:
		if err := r.doHeartBeat(conn); err != nil {
			ep := r.conn_endpoints[conn]
			delete(r.conn_endpoints, conn)
			conn, err = r.newRPCConn(r.endpoints_map[ep])
			if err != nil {
				_ = r.logr.Error(err, "Failed to re-establish connection. Ep:%+v", ep)
				// Try to get another connection.
				return r.Get()
			}
			r.conn_endpoints[conn] = ep
		}
	default:
	}
	return conn
}


func (r *RpcClientPool) Put(conn *grpc.ClientConn) {
	select {
	case r.conn_pool <- conn:
	default:
	}
}