package service

import (
	"context"
	"fmt"
	grpclog "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	grpcretry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	ssov1 "github.com/shipho-pluto/PROTO/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"log/slog"
	"time"
)

type ClientSSO struct {
	apiAuth    ssov1.AuthServiceClient
	apiProfile ssov1.ProfileClient
	conn       *grpc.ClientConn
	log        *slog.Logger
}

func NewSSO(ctx context.Context, log *slog.Logger, addr string, timeout time.Duration, retriesCount int) (*ClientSSO, error) {
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

	return &ClientSSO{
		apiAuth:    ssov1.NewAuthServiceClient(ClientConn),
		apiProfile: ssov1.NewProfileClient(ClientConn),
		log:        log,
		conn:       ClientConn,
	}, nil
}

func (c *ClientSSO) Close() error {
	return c.conn.Close()
}

func (c *ClientSSO) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsAdmin"

	resp, err := c.apiAuth.IsAdmin(ctx, &ssov1.IsAdminRequest{
		UserId: userID,
	})
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return resp.IsAdmin, nil
}

func (c *ClientSSO) IsModerator(ctx context.Context, userID int64) (bool, error) {
	const op = "auth.IsModerator"

	resp, err := c.apiAuth.IsModerator(ctx, &ssov1.IsModeratorRequest{
		UserId: userID,
	})
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return resp.IsMod, nil
}

func (c *ClientSSO) Login(ctx context.Context, email, password string, appID int64) (string, error) {
	const op = "auth.Login"

	resp, err := c.apiAuth.Login(ctx, &ssov1.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appID,
	})
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return resp.Token, nil
}

func (c *ClientSSO) Logout(ctx context.Context, token string, userID int64) (bool, error) {
	const op = "auth.Logout"
	c.log.Debug("logout request", slog.Int64("user_id", userID))

	resp, err := c.apiAuth.Logout(ctx, &ssov1.LogoutRequest{
		Token:  token,
		UserId: userID,
	})
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return resp.Answer, nil
}

func (c *ClientSSO) Register(ctx context.Context, username, email, password string) (int64, error) {
	const op = "auth.Register"

	resp, err := c.apiAuth.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Username: username,
		Password: password,
	})
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return resp.UserId, nil
}

func (c *ClientSSO) ChangePassword(ctx context.Context, oldPassword, newPassword string, userID int64) (bool, error) {
	const op = "profile.ChangePassword"

	resp, err := c.apiProfile.ChangePassword(ctx, &ssov1.ChangePasswordRequest{
		UserId:      userID,
		OldPassword: oldPassword,
		NewPassword: newPassword,
	})
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return resp.Success, nil
}

func (c *ClientSSO) ChangeName(ctx context.Context, userID int64, newName string) (bool, error) {
	const op = "profile.ChangeName"

	resp, err := c.apiProfile.ChangeName(ctx, &ssov1.ChangeNameRequest{
		UserId:  userID,
		NewName: newName,
	})
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return resp.Success, nil
}

func (c *ClientSSO) ChangeRole(ctx context.Context, adminID int64, targetUserID int64, newRole int32, adminPassword string) (bool, error) {
	const op = "profile.ChangeRole"

	resp, err := c.apiProfile.ChangeRole(ctx, &ssov1.ChangeRoleRequest{
		AdminId:  adminID,
		UserId:   targetUserID,
		NewRole:  newRole,
		Password: adminPassword,
	})
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return resp.Success, nil
}
