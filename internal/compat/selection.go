// read.cgiのレス範囲を番号保持のまま最大200件へページ分割する。
package compat

import (
	"errors"
	"strconv"
	"strings"
)

var ErrSelection = errors.New("invalid post selection")

// SelectPosts は1起算の番号列を返す。範囲外、逆順、overflowを拒否する。
func SelectPosts(selection string, count, page int) ([]int, error) {
	if count < 1 || page < 1 {
		return nil, ErrSelection
	}
	withFirst := !strings.HasSuffix(selection, "n")
	selection = strings.TrimSuffix(selection, "n")
	if selection == "" {
		selection = "l50"
	}
	number := func(s string) (int, error) {
		if s == "" {
			return 0, ErrSelection
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, ErrSelection
			}
		}
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 {
			return 0, ErrSelection
		}
		return n, nil
	}
	start, end := 1, count
	switch {
	case strings.HasPrefix(selection, "l"):
		n, e := number(selection[1:])
		if e != nil || n > 1000 {
			return nil, ErrSelection
		}
		start = max(1, count-n+1)
	case strings.Contains(selection, "-"):
		a, b, _ := strings.Cut(selection, "-")
		if a == "" && b == "" {
			return nil, ErrSelection
		}
		var e error
		if a != "" {
			start, e = number(a)
			if e != nil {
				return nil, e
			}
		}
		if b != "" {
			end, e = number(b)
			if e != nil {
				return nil, e
			}
		}
		if start > end {
			return nil, ErrSelection
		}
	default:
		n, e := number(selection)
		if e != nil {
			return nil, e
		}
		start = n
		end = n
	}
	end = min(end, count)
	if start > end {
		return nil, ErrSelection
	}
	total := end - start + 1
	if withFirst && start > 1 {
		total++
	}
	if page > (total+199)/200 {
		return nil, ErrSelection
	}
	begin := (page - 1) * 200
	limit := min(begin+200, total)
	result := make([]int, 0, limit-begin)
	for i := begin; i < limit; i++ {
		if withFirst && start > 1 {
			if i == 0 {
				result = append(result, 1)
			} else {
				result = append(result, start+i-1)
			}
		} else {
			result = append(result, start+i)
		}
	}
	return result, nil
}
