package utils

import "time"

// ConvertToUnixTimestamp is a function to convert Microsoft's timestamp value to Unix one
func ConvertToUnixTimestamp(timestamp uint64) time.Time {
	// Microsoft handles time as number of 100-nanosecond intervals since January 1, 1601 UTC
	// So to get a timestamp with unix time, subtract difference in 100-nanosecond intervals
	// and divide by 10 to convert to microseconds
	return time.UnixMicro(int64((timestamp - 116444736000000000) / 10))
}
