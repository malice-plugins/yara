package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/codegangsta/cli"
	"github.com/crackcomm/go-clitable"
	"github.com/levigross/grequests"
	"github.com/parnurzeal/gorequest"
)

// Version stores the plugin's version
var Version string

// BuildTime stores the plugin's build time
var BuildTime string

// virustotal json object
type virustotal struct {
	Results ResultsData `json:"virustotal"`
}

// ResultsData json object
type ResultsData struct {
	Scans        map[string]Scan `json:"scans"`
	Permalink    string          `json:"permalink"`
	Resource     string          `json:"resource"`
	ResponseCode int             `json:"response_code"`
	Total        int             `json:"total"`
	Positives    int             `json:"positives"`
	ScanID       string          `json:"scan_id"`
	ScanDate     string          `json:"scan_date"`
	VerboseMsg   string          `json:"verbose_msg"`
	MD5          string          `json:"md5"`
	Sha1         string          `json:"sha1"`
	Sha256       string          `json:"sha256"`
}

// Scan is a VirusTotal AV scan JSON object
type Scan struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version"`
	Result   string `json:"result"`
	Update   string `json:"update"`
}

// ScanResults json object
type ScanResults struct {
	Permalink    string `json:"permalink"`
	Resource     string `json:"resource"`
	ResponseCode int    `json:"response_code"`
	ScanID       string `json:"scan_id"`
	VerboseMsg   string `json:"verbose_msg"`
	MD5          string `json:"md5"`
	Sha1         string `json:"sha1"`
	Sha256       string `json:"sha256"`
}

type bitly struct {
	StatusCode int       `json:"status_code"`
	StatusTxt  string    `json:"status_txt"`
	Data       bitlyData `json:"data"`
}

type bitlyData struct {
	LongURL    string `json:"long_url"`
	URL        string `json:"url"`
	NewHash    int    `json:"new_hash"`
	Hash       string `json:"hash"`
	GlobalHash string `json:"global_hash"`
}

func getopt(name, dfault string) string {
	value := os.Getenv(name)
	if value == "" {
		value = dfault
	}
	return value
}

func assert(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(resp.Status)
}

func printMarkDownTable(virustotal virustotal) {
	fmt.Println("#### virustotal")
	table := clitable.New([]string{"Ratio", "Link", "API", "Scanned"})
	table.AddRow(map[string]interface{}{
		"Ratio": getRatio(virustotal.Results.Positives, virustotal.Results.Total),
		"Link":  fmt.Sprintf("[link](%s)", virustotal.Results.Permalink),
		"API":   "Public",
		// "API":     virustotal.ApiType,
		"Scanned": virustotal.Results.ScanDate,
	})
	table.Markdown = true
	table.Print()
}

// scanFile uploads file to virustotal
func scanFile(path string, apikey string) string {
	// fmt.Println("Uploading file to virustotal...")
	fd, err := grequests.FileUploadFromDisk(path)

	if err != nil {
		log.Println("Unable to open file: ", err)
	}

	// This will upload the file as a multipart mime request
	resp, err := grequests.Post("https://www.virustotal.com/vtapi/v2/file/scan",
		&grequests.RequestOptions{
			Files: fd,
			Params: map[string]string{
				"apikey": apikey,
				// "notify_url": notify_url,
				// "notify_changes_only": bool,
			},
		})

	if err != nil {
		log.Println("Unable to make request", resp.Error)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	fmt.Println(resp.String())

	var scanResults ScanResults
	resp.JSON(&scanResults)
	// fmt.Printf("%#v", scanResults)

	// TODO: wait for an hour!?!?!? or create a notify URL endpoint?!?!?!
	ro := &grequests.RequestOptions{
		Params: map[string]string{
			"resource": scanResults.Sha256,
			"scan_id":  scanResults.ScanID,
			"apikey":   apikey,
			"allinfo":  "1",
		},
	}
	resp, err = grequests.Get("https://www.virustotal.com/vtapi/v2/file/report", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}

	// fmt.Println(resp.String())
	return resp.String()
}

// lookupHash retreieves the virustotal file report for the given hash
func lookupHash(hash string, apikey string) ResultsData {
	// NOTE: https://godoc.org/github.com/levigross/grequests
	// fmt.Println("Getting virustotal report...")
	ro := &grequests.RequestOptions{
		Params: map[string]string{
			"resource": hash,
			"apikey":   apikey,
			"allinfo":  "1",
		},
	}
	resp, err := grequests.Get("https://www.virustotal.com/vtapi/v2/file/report", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	if resp.StatusCode == 204 {
		log.Fatalln("Used more than 4 queries per minute")
	}

	if resp.Ok != true {
		log.Println("Request did not return OK")
	}
	var vtResult ResultsData
	// fmt.Println(resp.String())
	resp.JSON(&vtResult)
	// fmt.Printf("%#v", vtResult)
	t, _ := time.Parse("2006-01-02 15:04:05", vtResult.ScanDate)
	vtResult.ScanDate = t.Format("Mon 2006Jan02 15:04:05")

	return vtResult
}

func getRatio(positives int, total int) string {
	ratio := 100.0 * float64(positives) / float64(total)
	return fmt.Sprintf("%.f%%", ratio)
}

func shortenPermalink(longURL string) string {
	// NOTE: http://dev.bitly.com/api.html
	// https://github.com/bitly/go-simplejson
	var btl bitly

	ro := &grequests.RequestOptions{
		Params: map[string]string{
			"access_token": "23382325dd472aed14518ec5b8c8f4c2293e114a",
			"longUrl":      longURL,
		},
	}
	resp, err := grequests.Get("https://api-ssl.bitly.com/v3/shorten", ro)

	if err != nil {
		log.Fatalln("Unable to make request: ", err)
	}

	fmt.Println(resp.String())
	resp.JSON(&btl)

	return btl.Data.URL
}

var appHelpTemplate = `Usage: {{.Name}} {{if .Flags}}[OPTIONS] {{end}}COMMAND [arg...]

{{.Usage}}

Version: {{.Version}}{{if or .Author .Email}}

Author:{{if .Author}}
  {{.Author}}{{if .Email}} - <{{.Email}}>{{end}}{{else}}
  {{.Email}}{{end}}{{end}}
{{if .Flags}}
Options:
  {{range .Flags}}{{.}}
  {{end}}{{end}}
Commands:
  {{range .Commands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
  {{end}}
Run '{{.Name}} COMMAND --help' for more information on a command.
`

func main() {
	cli.AppHelpTemplate = appHelpTemplate
	app := cli.NewApp()
	app.Name = "virustotal"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice VirusTotal Plugin"
	var apikey string
	var table bool
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:   "post, p",
			Usage:  "POST results to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.BoolFlag{
			Name:        "table, t",
			Usage:       "output as Markdown table",
			Destination: &table,
		},
		cli.StringFlag{
			Name:        "api",
			Value:       "",
			Usage:       "VirusTotal API key",
			EnvVar:      "MALICE_VT_API",
			Destination: &apikey,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:      "scan",
			Aliases:   []string{"s"},
			Usage:     "Upload binary to VirusTotal for scanning",
			ArgsUsage: "FILE to upload to VirusTotal",
			Action: func(c *cli.Context) {
				// Check for valid apikey
				if apikey == "" {
					log.Fatal(fmt.Errorf("Please supply a valid VT_API key with the flag '--api'."))
				}

				if c.Args().Present() {
					path := c.Args().First()
					// Check that file exists
					if _, err := os.Stat(path); os.IsNotExist(err) {
						assert(err)
					}
					scanFile(path, apikey)
				} else {
					log.Fatal(fmt.Errorf("Please supply a file to upload to VirusTotal."))
				}
			},
		},
		{
			Name:      "lookup",
			Aliases:   []string{"l"},
			Usage:     "Get file hash scan report",
			ArgsUsage: "MD5/SHA1/SHA256 hash of file",
			Action: func(c *cli.Context) {
				// Check for valid apikey
				if apikey == "" {
					log.Fatal(fmt.Errorf("Please supply a valid VT_API key with the flag '--api'."))
				}

				if c.Args().Present() {
					vtReport := lookupHash(c.Args().First(), apikey)
					vt := virustotal{Results: vtReport}
					if table {
						printMarkDownTable(vt)
					} else {
						vtJSON, err := json.Marshal(vt)
						assert(err)
						fmt.Println(string(vtJSON))
					}
				} else {
					log.Fatal(fmt.Errorf("Please supply a MD5/SHA1/SHA256 hash to query."))
				}
			},
		},
	}

	err := app.Run(os.Args)
	assert(err)
}
