package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/crackcomm/go-clitable"
	"github.com/fatih/structs"
	"github.com/gorilla/mux"
	yara "github.com/hillu/go-yara"
	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

const (
	name     = "yara"
	category = "av"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string
	// yara rules directory
	rules string
	// blacklisted rules that can't compile
	blacklisted []string
	path        string
	// yara rule compiler
	yaraCompiler *yara.Compiler
	// es is the elasticsearch database object
	es elasticsearch.Database
)

type pluginResults struct {
	ID   string      `json:"id" structs:"id,omitempty"`
	Data ResultsData `json:"yara" structs:"yara"`
}

// Yara json object
type Yara struct {
	Results ResultsData `json:"yara" structs:"yara"`
}

// ResultsData json object
type ResultsData struct {
	Matches  []yara.MatchRule `json:"matches" structs:"matches"`
	MarkDown string           `json:"markdown,omitempty" structs:"markdown,omitempty"`
}

func assert(err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
			"path":     path,
		}).Fatal(err)
	}
}

// compileRules compiles the yara rules
func compileRules(rulesDir string) error {

	fileList := []string{}

	// walk rules directory
	err := filepath.Walk(rulesDir, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "failed walking rules filepath")
	}

	// new yara compiler
	yaraCompiler, err = yara.NewCompiler()
	if err != nil {
		return errors.Wrap(err, "failed to create new yara compiler")
	}

	// compile all yara rules
	for _, file := range fileList {

		if utils.StringInSlice(file, blacklisted) {
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			return errors.Wrap(err, "failed to open rule")
		}

		log.Debug("Adding rule: ", file)
		err = yaraCompiler.AddFile(f, "malice")
		if err != nil {
			blacklisted = append(blacklisted, file)
			for _, er := range yaraCompiler.Errors {
				log.WithFields(log.Fields{
					"rule":    er.Filename,
					"line_no": er.Line,
				}).Error(er.Text)
			}
			// for _, wr := range yaraCompiler.Warnings {
			// 	log.Warn(wr)
			// }
			f.Close()

			// destroy unstable YR_COMPILER
			// (see https://github.com/hillu/go-yara/issues/32#issuecomment-416040753)
			log.Debug("destroying unstable yara compiler")
			yaraCompiler.Destroy()
			log.Debug("recreating yara compiler")
			assert(compileRules(rulesDir))
		}
		f.Close()
	}

	return nil
}

// scanFile scans file with all yara rules in the rules folder
func scanFile(path string, rulesDir string, timeout int) ResultsData {

	yaraResults := ResultsData{}

	// comile rules if they haven't been compiled yet
	if yaraCompiler == nil {
		assert(compileRules(rulesDir))
	}

	r, err := yaraCompiler.GetRules()
	matches, err := r.ScanFile(
		path,                               // filename string
		0,                                  // flags ScanFlags
		time.Duration(timeout)*time.Second, //timeout time.Duration
	)
	assert(errors.Wrapf(err, "failed to scan file: %s", path))

	yaraResults.Matches = matches

	return yaraResults
}

func generateMarkDownTable(y Yara) string {
	var tplOut bytes.Buffer

	t := template.Must(template.New("yara").Parse(tpl))

	err := t.Execute(&tplOut, y)
	if err != nil {
		log.Println("executing template:", err)
	}

	return tplOut.String()
}

func printStatus(resp gorequest.Response, body string, errs []error) {
	fmt.Println(body)
}

func webService() error {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/scan", webAvScan).Methods("POST")
	log.Info("web service listening on port :3993")
	return http.ListenAndServe(":3993", router)
}

func webAvScan(w http.ResponseWriter, r *http.Request) {

	r.ParseMultipartForm(32 << 20)
	file, header, err := r.FormFile("malware")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Please supply a valid file to scan.")
		log.Error(err)
	}
	defer file.Close()

	log.Debug("Uploaded fileName: ", header.Filename)

	tmpfile, err := ioutil.TempFile("/malware", "web_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	data, err := ioutil.ReadAll(file)

	if _, err = tmpfile.Write(data); err != nil {
		log.Fatal(err)
	}
	if err = tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	// Do AV scan
	yara := scanFile(tmpfile.Name(), rules, 60)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(yara); err != nil {
		log.Fatal(err)
	}
}

// TODO: handle more than just the first Offset, handle multiple MatchStrings
func printMarkDownTable(yara Yara) {
	fmt.Println("#### Yara")
	if yara.Results.Matches != nil {
		table := clitable.New([]string{"Rule", "Description", "Offset", "Data", "Tags"})
		for _, match := range yara.Results.Matches {
			var tags string
			if len(match.Tags) == 0 {
				tags = ""
			} else {
				tags = match.Tags[0]
			}
			table.AddRow(map[string]interface{}{
				"Rule":        match.Rule,
				"Description": match.Meta["description"],
				"Offset":      match.Strings[0].Offset,
				"Data":        string(match.Strings[0].Data),
				"Tags":        tags,
			})
		}
		table.Markdown = true
		table.Print()
	} else {
		fmt.Println(" - No Matches")
	}
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "yara"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice YARA Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.StringFlag{
			Name:        "elasticsearch",
			Value:       "",
			Usage:       "elasticsearch url for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH_URL",
			Destination: &es.URL,
		},
		cli.BoolFlag{
			Name:   "callback, c",
			Usage:  "POST results to Malice webhook",
			EnvVar: "MALICE_ENDPOINT",
		},
		cli.BoolFlag{
			Name:   "proxy, x",
			Usage:  "proxy settings for Malice webhook endpoint",
			EnvVar: "MALICE_PROXY",
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  60,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
		cli.StringFlag{
			Name:        "rules",
			Value:       "/rules",
			Usage:       "YARA rules directory",
			Destination: &rules,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "web",
			Usage: "Create a Yara web service",
			Action: func(c *cli.Context) error {
				return webService()
			},
		},
	}
	app.ArgsUsage = "FILE to scan with YARA"
	app.Action = func(c *cli.Context) error {
		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {

			path, err := filepath.Abs(c.Args().First())
			if err != nil {
				return errors.Wrap(err, "failed to get path from args")
			}
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return errors.Wrap(err, "input file does not exist")
			}

			yara := Yara{Results: scanFile(path, rules, c.Int("timeout"))}
			yara.Results.MarkDown = generateMarkDownTable(yara)

			// upsert into Database
			if len(c.String("elasticsearch")) > 0 {
				err := es.Init()
				if err != nil {
					return errors.Wrap(err, "failed to initalize elasticsearch")
				}
				err = es.StorePluginResults(database.PluginResults{
					ID:       utils.Getopt("MALICE_SCANID", utils.GetSHA256(path)),
					Name:     name,
					Category: category,
					Data:     structs.Map(yara.Results),
				})
				if err != nil {
					return errors.Wrapf(err, "failed to index malice/%s results", name)
				}
			}

			if c.Bool("table") {
				fmt.Printf(yara.Results.MarkDown)
			} else {
				yara.Results.MarkDown = ""
				yaraJSON, err := json.Marshal(yara)
				if err != nil {
					return errors.Wrap(err, "failed to marshal JSON")
				}
				if c.Bool("callback") {
					request := gorequest.New()
					if c.Bool("proxy") {
						request = gorequest.New().Proxy(os.Getenv("MALICE_PROXY"))
					}
					request.Post(os.Getenv("MALICE_ENDPOINT")).
						Set("X-Malice-ID", utils.Getopt("MALICE_SCANID", utils.GetSHA256(path))).
						Send(string(yaraJSON)).
						End(printStatus)

					return nil
				}
				fmt.Println(string(yaraJSON))
			}
		} else {
			log.Fatal(fmt.Errorf("Please supply a file to scan with YARA"))
		}
		return nil
	}

	err := app.Run(os.Args)
	assert(err)
}
