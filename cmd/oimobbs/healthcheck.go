// 公開ページと保存状態の監視要求を、呼出元の共通期限内で確認する。
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"oimobbs/internal/bootstrap"
)

// checkHealthURL は200と本文の読取り完了を要求する。監視用URLは固定本文も照合する。
// 保存側へ到達していない汎用200や、途中で切れた応答を正常としない。
func checkHealthURL(ctx context.Context, client *http.Client, origin, path string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck %s: HTTP %d", path, response.StatusCode)
	}
	if path == bootstrap.HealthcheckPath {
		body, err := io.ReadAll(io.LimitReader(response.Body, 4))
		if err != nil {
			return err
		}
		if string(body) != "ok\n" {
			return errors.New("healthcheck: invalid storage readiness response")
		}
		return nil
	}
	_, err = io.Copy(io.Discard, response.Body)
	return err
}
