package main

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

const testTime = 1517439798

func TestTimeToIp(t *testing.T) {
	ip := TimeToIP(time.Unix(testTime, 0))
	fmt.Printf("%+v", ip)
}

func TestTimeFromIp(t *testing.T) {
	ip := TimeToIP(time.Unix(testTime, 0))
	ipTime := TimeFromIP(ip)
	fmt.Printf("%+v", ipTime)
	fmt.Printf("%+v", ipTime.Unix())
	if ipTime.Unix() != testTime {
		t.Error(errors.New("wrong time"))
	}
}
