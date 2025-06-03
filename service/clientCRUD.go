package service

import (
	"context"
	"fmt"
	grpclog "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	grpcretry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	crudv1 "github.com/shipho-pluto/PROTO/gen/go/crud"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"log/slog"
	"time"
)

type ClientCRUD struct {
	apiCRUD crudv1.MessageClient
	conn    *grpc.ClientConn
	log     *slog.Logger
}

type Message struct {
	ID       int64
	Content  string
	UserID   int64
	Type     string
	DateTime string
}

func NewCRUD(ctx context.Context, log *slog.Logger,
	addr string, timeout time.Duration, retriesCount int) (*ClientCRUD, error) {
	const op = "grpc.NewClient"

	retryOpts := []grpcretry.CallOption{
		grpcretry.WithCodes(codes.Aborted, codes.DeadlineExceeded, codes.NotFound),
		grpcretry.WithPerRetryTimeout(timeout),
		grpcretry.WithMax(uint(retriesCount)),
	}

	logOpts := []grpclog.Option{
		grpclog.WithLogOnEvents(grpclog.PayloadSent, grpclog.PayloadReceived),
	}

	ClientConn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			grpcretry.UnaryClientInterceptor(retryOpts...),
			grpclog.UnaryClientInterceptor(InterceptorLogger(log), logOpts...),
		))

	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &ClientCRUD{
		apiCRUD: crudv1.NewMessageClient(ClientConn),
		log:     log,
		conn:    ClientConn,
	}, nil
}

func (c *ClientCRUD) Close() error {
	return c.conn.Close()
}

func InterceptorLogger(l *slog.Logger) grpclog.Logger {
	return grpclog.LoggerFunc(func(ctx context.Context, lvl grpclog.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func (c *ClientCRUD) GetMessage(ctx context.Context, token string, mid int64) (Message, error) {
	const op = "crud.GetMessage"

	resp, err := c.apiCRUD.GetMessage(ctx, &crudv1.GetMessageRequest{
		Token: token,
		Mid:   mid,
	})
	if err != nil {
		return Message{}, fmt.Errorf("%s: %w", op, err)
	}
	return Message{Content: resp.Content}, nil
}

func (c *ClientCRUD) SentMessage(ctx context.Context, datetime, typeMessage, content, token string) (int64, error) {
	const op = "crud.SentMessage"

	typeOf := int32(0)
	switch typeMessage {
	case "text":
		typeOf = 1
	case "image":
		typeOf = 2
	case "file":
		typeOf = 3
	}

	resp, err := c.apiCRUD.SentMessage(ctx, &crudv1.SentMessageRequest{
		Type:     typeOf,
		Token:    token,
		Content:  content,
		Datetime: datetime,
	})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return resp.Mid, nil
}

func (c *ClientCRUD) UpdateMessage(ctx context.Context, newContent, token string, mid int64) (bool, error) {
	const op = "crud.UpdateMessage"

	resp, err := c.apiCRUD.UpdateMessage(ctx, &crudv1.UpdateMessageRequest{
		Token:      token,
		NewContent: newContent,
		Mid:        mid,
	})
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return resp.Status, nil
}

func (c *ClientCRUD) DeleteMessage(ctx context.Context, token string, mid int64) (bool, error) {
	const op = "crud.DeleteMessage"

	resp, err := c.apiCRUD.DeleteMessage(ctx, &crudv1.DeleteMessageRequest{
		Token: token,
		Mid:   mid,
	})
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return resp.Status, nil
}

func (c *ClientCRUD) ShowAllMessages(ctx context.Context, token string) ([]*crudv1.GetMessageResponse, error) {
	const op = "client.ShowAllMessages"

	req := &crudv1.ShowMessagesRequest{
		Token: token,
	}

	resp, err := c.apiCRUD.ShowMessages(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if len(resp.Message) == 0 {
		return []*crudv1.GetMessageResponse{}, nil
	}

	return resp.Message, nil
}
