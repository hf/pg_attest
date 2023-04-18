package server

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/hf/pg_attest/message"
)

type Server struct {
	Attest func(context.Context, message.RequestAttestation) (message.ResponseAttestation, error)
}

func (s *Server) Run(ctx context.Context, path string) error {
	ln, err := net.Listen("unixpacket", path)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()

		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		go func() {
			s.handle(ctx, conn.(*net.UnixConn))
		}()
	}
}

func (s *Server) handleRequestAttestation(ctx context.Context, conn *net.UnixConn, req message.RequestAttestation) error {
	res, err := s.Attest(ctx, req)
	if err != nil {
		if _, err := conn.Write(message.Marshal(err)); err != nil {
			return err
		}
	}

	if _, err := conn.Write(message.Marshal(res)); err != nil {
		return err
	}

	return nil
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn) error {
	defer conn.Close()

	buf := make([]byte, 2*os.Getpagesize())

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}

		msg, err := message.Parse(buf[:n])
		if err != nil {
			return err
		}

		switch msg.(type) {
		case message.RequestAttestation:
			if err := s.handleRequestAttestation(ctx, conn, msg.(message.RequestAttestation)); err != nil {
				return err
			}

		default:
			return fmt.Errorf("pg_attest: unhandled message type %#v", msg)
		}
	}
}
