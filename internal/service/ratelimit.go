package service

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	redis *redis.Client
}

func NewRateLimiter(redis *redis.Client) *RateLimiter {
	return &RateLimiter{
		redis: redis,
	}
}

func (r *RateLimiter) CheckLogin(ctx context.Context, email string) error {
	key := fmt.Sprintf("login_attempts:%s", email)

	count, err := r.redis.Incr(ctx, key).Result()
	if err != nil {
		return err
	}

	if count == 1 {
		r.redis.Expire(ctx, key, 15*time.Minute)
	}

	if count > 5 {
		return ErrTooManyAttempts
	}

	return nil
}

func (r *RateLimiter) CheckRegister(ctx context.Context, email string) error {
	key := fmt.Sprintf("register_attempts:%s", email)

	count, err := r.redis.Incr(ctx, key).Result()
	if err != nil {
		return err
	}

	if count == 1 {
		r.redis.Expire(ctx, key, 1*time.Hour)
	}

	if count > 3 {
		return ErrTooManyAttempts
	}

	return nil
}

func (r *RateLimiter) CheckPasswordReset(ctx context.Context, email string) error {
	key := fmt.Sprintf("password_reset_attempts:%s", email)

	count, err := r.redis.Incr(ctx, key).Result()
	if err != nil {
		return err
	}

	if count == 1 {
		r.redis.Expire(ctx, key, 1*time.Hour)
	}

	if count > 3 {
		return ErrTooManyAttempts
	}

	return nil
}

func (r *RateLimiter) ResetAttempts(ctx context.Context, email, operation string) error {
	key := fmt.Sprintf("%s_attempts:%s", operation, email)
	return r.redis.Del(ctx, key).Err()
}
