/*
Copyright AppsCode Inc. and Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package retry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"k8s.io/klog/v2"
)

const (
	multiplier        = 2.0
	defaultMaxRetries = 5
	defaultDelay      = 10 * time.Second
	maxInterval       = 120 * time.Second
	maxElapsedTime    = 5 * time.Minute
)

var retryablePatterns = []string{
	"Connection closed by foreign host",
}

type RetryConfigOpts func(*RetryConfig)

type RetryConfig struct {
	// MaxRetries is the number of retry attempts after the initial attempt.
	MaxRetries uint64

	// Initial interval between attempts.
	Delay time.Duration

	// ExponentialBackOff parameters:
	Multiplier     float64
	MaxInterval    time.Duration
	MaxElapsedTime time.Duration // 0 means use cenkalti/backoff default (15m)

	// ShouldRetry returns true if the operation error+output should be retried.
	RetryablePatterns []string
	ShouldRetry       func(error, string) bool
}

// NewRetryConfig returns a RetryConfig with sane defaults.
func NewRetryConfig(opts ...RetryConfigOpts) *RetryConfig {
	config := &RetryConfig{
		MaxRetries:     uint64(defaultMaxRetries),
		Delay:          defaultDelay,
		Multiplier:     multiplier,
		MaxInterval:    maxInterval,
		MaxElapsedTime: maxElapsedTime,
		ShouldRetry:    defaultShouldRetry,
	}

	for _, fn := range opts {
		fn(config)
	}
	return config
}

// RunWithRetry runs execFunc with exponential backoff according to the RetryConfig.
func (rc *RetryConfig) RunWithRetry(ctx context.Context, execFunc func() (any, error)) (any, error) {
	if execFunc == nil {
		return nil, fmt.Errorf("execFunc cannot be nil")
	}
	var output any
	var attempts uint64

	boWithCtx := backoff.WithContext(backoff.NewExponentialBackOff(func(off *backoff.ExponentialBackOff) {
		off.InitialInterval = rc.Delay
		off.Multiplier = rc.Multiplier
		off.MaxInterval = rc.MaxInterval
		off.MaxElapsedTime = rc.MaxElapsedTime
	}), ctx)
	bo := backoff.WithMaxRetries(boWithCtx, rc.MaxRetries)

	operation := func() error {
		attempts++
		out, err := execFunc()
		output = out
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return backoff.Permanent(err)
		}
		if rc.ShouldRetry(err, fmt.Sprint(out)) {
			return err
		}
		if err == nil {
			return nil
		}
		return backoff.Permanent(err)
	}

	notify := func(err error, next time.Duration) {
		klog.Infoln("RetryNotify:", "attempt", attempts, "error", err, "next_backoff", next, "max_retries", rc.MaxRetries)
	}

	err := backoff.RetryNotify(operation, bo, notify)
	if err != nil {
		return output, fmt.Errorf("retry failed after %d attempts: %w", attempts, err)
	}
	return output, nil
}

func defaultShouldRetry(err error, output string) bool {
	if err == nil {
		return false
	}
	combined := strings.ToLower(err.Error() + " " + output)
	klog.Infoln("Combined output:", combined)
	for _, pattern := range retryablePatterns {
		if strings.Contains(combined, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}
