package source

// GetSources returns a slice of proxy list URLs as strings.
func GetSources() []string {
	return []string{
		"https://www.proxyscan.io/download?type=http",
		"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
		"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
		"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
		"https://raw.githubusercontent.com/ShiftyTR/Proxy",
	}
}
